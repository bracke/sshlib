with Ada.Directories;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.File_Transfer;
with SSH_Lib.Platform.Environment;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.SFTP;
with SSH_Lib.Sessions;
with SSH_Lib.Sessions.Test_Support;
with SSH_Lib.Tests.Assertions;

package body SSH_Lib.Tests.Fixtures.Local_SSHD is
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;

   Current_Keyboard_Interactive_Secret : Unbounded_String;

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   function Env (Name : String) return String is
   begin
      return To_String (SSH_Lib.Platform.Environment.Getenv (Name));
   exception
      when others =>
         return "";
   end Env;


   function Bytes_From_String (Value : String) return Ada.Streams.Stream_Element_Array is
      Result : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Value'Length));
      Index  : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      for Character_Value of Value loop
         Result (Index) := Character'Pos (Character_Value);
         Index := Index + 1;
      end loop;
      return Result;
   end Bytes_From_String;

   Stream_Download_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   Stream_Upload_Source   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   Stream_Upload_Limit    : Natural := 0;
   Directory_Page_Calls   : Natural := 0;
   Directory_Page_Entries : Natural := 0;
   Directory_Page_Names   : Unbounded_String;

   function Capture_Directory_Page
     (Entries : SSH_Lib.SFTP.Directory_Entry_Vectors.Vector)
      return CryptoLib.Errors.Status
   is
   begin
      Directory_Page_Calls := Directory_Page_Calls + 1;
      Directory_Page_Entries := Directory_Page_Entries + Natural (Entries.Length);
      for Item of Entries loop
         if Length (Directory_Page_Names) > 0 then
            Append (Directory_Page_Names, Character'Val (10));
         end if;
         Append (Directory_Page_Names, To_String (Item.Name));
      end loop;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Capture_Directory_Page;

   function Capture_Stream_Chunk
     (Offset : Interfaces.Unsigned_64;
      Data   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      pragma Unreferenced (Offset);
   begin
      return SSH_Lib.Protocol.Buffers.Append (Stream_Download_Buffer, Data);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Capture_Stream_Chunk;

   function Provide_Stream_Chunk
     (Offset         : Interfaces.Unsigned_64;
      Maximum_Length : Natural;
      Data           : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Source      : constant Ada.Streams.Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Stream_Upload_Source);
      Start_Index : Ada.Streams.Stream_Element_Offset;
      Count       : Natural;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Data);
      if Offset > Interfaces.Unsigned_64 (Source'Length) then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Count := Source'Length - Natural (Offset);
      if Stream_Upload_Limit > 0 and then Count > Stream_Upload_Limit then
         Count := Stream_Upload_Limit;
      end if;
      if Count > Maximum_Length then
         Count := Maximum_Length;
      end if;
      if Count = 0 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Start_Index := Source'First + Ada.Streams.Stream_Element_Offset (Offset);
      return SSH_Lib.Protocol.Buffers.Set
        (Data, Source (Start_Index .. Start_Index + Ada.Streams.Stream_Element_Offset (Count) - 1));
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Data);
         return CryptoLib.Errors.Internal_Error;
   end Provide_Stream_Chunk;

   procedure Write_Test_File
     (Path : String;
      Data : Ada.Streams.Stream_Element_Array)
   is
      File : Ada.Streams.Stream_IO.File_Type;
   begin
      Ada.Streams.Stream_IO.Create
        (File, Ada.Streams.Stream_IO.Out_File, Path);
      Ada.Streams.Stream_IO.Write (File, Data);
      Ada.Streams.Stream_IO.Close (File);
   exception
      when others =>
         if Ada.Streams.Stream_IO.Is_Open (File) then
            Ada.Streams.Stream_IO.Close (File);
         end if;
         raise;
   end Write_Test_File;

   function Read_Test_File (Path : String) return Ada.Streams.Stream_Element_Array is
      File : Ada.Streams.Stream_IO.File_Type;
      Size : Ada.Streams.Stream_IO.Count;
   begin
      Ada.Streams.Stream_IO.Open (File, Ada.Streams.Stream_IO.In_File, Path);
      Size := Ada.Streams.Stream_IO.Size (File);
      declare
         Data : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Size));
         Last : Ada.Streams.Stream_Element_Offset;
      begin
         Ada.Streams.Stream_IO.Read (File, Data, Last);
         Ada.Streams.Stream_IO.Close (File);
         if Last < Data'Last then
            return Data (Data'First .. Last);
         end if;
         return Data;
      end;
   exception
      when others =>
         if Ada.Streams.Stream_IO.Is_Open (File) then
            Ada.Streams.Stream_IO.Close (File);
         end if;
         raise;
   end Read_Test_File;

   procedure Remove_Local_Tree_If_Exists (Path : String) is
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_Tree (Path);
      end if;
   exception
      when others =>
         null;
   end Remove_Local_Tree_If_Exists;

   function Enabled return Boolean is
   begin
      return Env ("SSH_LIB_TEST_SSHD_ENABLE") = "1";
   end Enabled;

   function Port_From_Environment return Natural is
      Text : constant String := Env ("SSH_LIB_TEST_SSHD_PORT");
   begin
      if Text'Length = 0 then
         return 0;
      end if;

      return Natural'Value (Text);
   exception
      when others =>
         return 0;
   end Port_From_Environment;

   function Password_Callback
     (Host : String;
      User : String)
      return SSH_Lib.Sessions.Credential_Callback_Result
   is
      pragma Unreferenced (Host, User);
      Secret : constant String := Env ("SSH_LIB_TEST_SSHD_PASSWORD");
   begin
      if Secret'Length = 0 then
         return (Provided => False, Secret => Null_Unbounded_String);
      end if;

      return (Provided => True, Secret => To_Unbounded_String (Secret));
   end Password_Callback;

   function Keyboard_Interactive_Callback
     (Host      : String;
      User      : String;
      Challenge : SSH_Lib.Sessions.Keyboard_Interactive_Challenge)
      return SSH_Lib.Sessions.Keyboard_Interactive_Callback_Result
   is
      pragma Unreferenced (Host, User);
      Result : SSH_Lib.Sessions.Keyboard_Interactive_Callback_Result;
   begin
      if To_String (Current_Keyboard_Interactive_Secret)'Length = 0 then
         return Result;
      end if;

      if Challenge.Prompt_Count = 0 then
         Result.Provided := True;
         Result.Response_Count := 0;
         return Result;
      end if;

      Result.Provided := True;
      Result.Response_Count := Challenge.Prompt_Count;
      for Prompt_Index in 1 .. Challenge.Prompt_Count loop
         Result.Responses (Prompt_Index) := Current_Keyboard_Interactive_Secret;
      end loop;
      return Result;
   end Keyboard_Interactive_Callback;

   function Base_Options return SSH_Lib.Sessions.Session_Options is
      Host_Text : constant String := Env ("SSH_LIB_TEST_SSHD_HOST");
      User_Text : constant String := Env ("SSH_LIB_TEST_SSHD_USER");
      Port      : constant Natural := Port_From_Environment;
   begin
      return Result : SSH_Lib.Sessions.Session_Options do
         Result.Host := To_Unbounded_String (Host_Text);
         Result.Port := Port;
         Result.User := To_Unbounded_String (User_Text);
         Result.Connect_Timeout_MS := 5_000;
         Result.Read_Timeout_MS := 5_000;
         Result.Write_Timeout_MS := 5_000;
         Result.Verify_Known_Host := False;
         Result.Strict_Host_Key := False;
         Result.Use_Agent := False;
         Result.Identity_Agent := To_Unbounded_String ("none");
      end return;
   end Base_Options;

   procedure Assert_Open_Interop
     (Options    : SSH_Lib.Sessions.Session_Options;
      Label_Text : String)
   is
      Session_Item : SSH_Lib.Sessions.Session;
      Status_Value : CryptoLib.Errors.Status;
      Strict       : constant Boolean := Env ("SSH_LIB_TEST_SSHD_STRICT") = "1";
   begin
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      if Strict or else Status_Value = CryptoLib.Errors.Ok then
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "local sshd integration", Label_Text);
         Check
           (SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item),
            Label_Text & " publishes an open session");
         Status_Value := SSH_Lib.Sessions.Close (Session_Item);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok, "local sshd integration",
            Label_Text & " closes cleanly");
      else
         Check
           (Status_Value = CryptoLib.Errors.Handshake_Failed
            or else Status_Value = CryptoLib.Errors.Unsupported_Feature,
            Label_Text & " reaches live sshd before known unsupported boundary");
      end if;
   end Assert_Open_Interop;

   procedure Assert_Publickey is
      Options       : SSH_Lib.Sessions.Session_Options := Base_Options;
      Identity_File : constant String := Env ("SSH_LIB_TEST_SSHD_IDENTITY_FILE");
   begin
      if Identity_File'Length = 0 then
         return;
      end if;

      Options.Identity_File := To_Unbounded_String (Identity_File);
      Options.Preferred_Authentications := To_Unbounded_String ("publickey");
      Assert_Open_Interop (Options, "publickey auth against local sshd");
   end Assert_Publickey;

   procedure Assert_Password is
      Options : SSH_Lib.Sessions.Session_Options := Base_Options;
   begin
      if Env ("SSH_LIB_TEST_SSHD_PASSWORD")'Length = 0 then
         return;
      end if;

      Options.Preferred_Authentications := To_Unbounded_String ("password");
      Options.Use_Password := True;
      Options.Password_Callback := Password_Callback'Access;
      Assert_Open_Interop (Options, "password auth against local sshd");
   end Assert_Password;

   procedure Assert_Keyboard_Interactive is
      Options : SSH_Lib.Sessions.Session_Options := Base_Options;
   begin
      Current_Keyboard_Interactive_Secret :=
        To_Unbounded_String (Env ("SSH_LIB_TEST_SSHD_KBDINT_PASSWORD"));
      if To_String (Current_Keyboard_Interactive_Secret)'Length = 0 then
         return;
      end if;

      Options.Preferred_Authentications :=
        To_Unbounded_String ("keyboard-interactive");
      Options.Keyboard_Interactive_Callback :=
        Keyboard_Interactive_Callback'Access;
      Assert_Open_Interop
        (Options, "keyboard-interactive auth against local sshd");
      Current_Keyboard_Interactive_Secret := Null_Unbounded_String;
   exception
      when others =>
         Current_Keyboard_Interactive_Secret := Null_Unbounded_String;
         raise;
   end Assert_Keyboard_Interactive;


   function Natural_Env
     (Name          : String;
      Default_Value : Natural)
      return Natural
   is
      Text : constant String := Env (Name);
   begin
      if Text'Length = 0 then
         return Default_Value;
      end if;
      return Natural'Value (Text);
   exception
      when others =>
         return Default_Value;
   end Natural_Env;

   procedure Assert_Optional_Live_SFTP_V4_V6 is
      Host_Text     : constant String := Env ("SSH_LIB_TEST_SFTP_V4_HOST");
      User_Text     : constant String := Env ("SSH_LIB_TEST_SFTP_V4_USER");
      Identity_File : constant String := Env ("SSH_LIB_TEST_SFTP_V4_IDENTITY_FILE");
      Remote_File   : constant String :=
        (if Env ("SSH_LIB_TEST_SFTP_V4_FILE")'Length > 0
         then Env ("SSH_LIB_TEST_SFTP_V4_FILE")
         else "/tmp/ssh_lib_sftp_v4_v6.txt");
      Port_Value    : constant Natural :=
        Natural_Env ("SSH_LIB_TEST_SFTP_V4_PORT", 22);
      Requested     : constant Natural :=
        Natural_Env ("SSH_LIB_TEST_SFTP_V4_REQUEST_VERSION",
                     SSH_Lib.SFTP.Maximum_Protocol_Version);
      Options       : SSH_Lib.Sessions.Session_Options;
      Session_Item  : SSH_Lib.Sessions.Session;
      Client_Item   : SSH_Lib.SFTP.Client;
      Status_Value  : CryptoLib.Errors.Status;
      Data_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Attributes    : SSH_Lib.SFTP.File_Attributes;
      Extensions    : SSH_Lib.SFTP.Extension_Info;
      Check_Info    : SSH_Lib.SFTP.Check_File_Result;
      Stats_Info    : SSH_Lib.SFTP.StatVFS_Result;
      Limits_Info   : SSH_Lib.SFTP.Limits_Result;
   begin
      if Env ("SSH_LIB_TEST_SFTP_V4_ENABLE") /= "1" then
         return;
      end if;

      Check (Host_Text'Length > 0, "SFTP v4-v6 fixture host configured");
      Check (User_Text'Length > 0, "SFTP v4-v6 fixture user configured");
      Check (Identity_File'Length > 0,
             "SFTP v4-v6 fixture identity configured");
      Check
        (Requested in SSH_Lib.SFTP.Minimum_Protocol_Version ..
          SSH_Lib.SFTP.Maximum_Protocol_Version,
         "SFTP v4-v6 fixture requested version supported locally");

      Options.Host := To_Unbounded_String (Host_Text);
      Options.Port := Port_Value;
      Options.User := To_Unbounded_String (User_Text);
      Options.Identity_File := To_Unbounded_String (Identity_File);
      Options.Preferred_Authentications := To_Unbounded_String ("publickey");
      Options.Connect_Timeout_MS := 5_000;
      Options.Read_Timeout_MS := 5_000;
      Options.Write_Timeout_MS := 5_000;
      Options.Verify_Known_Host := False;
      Options.Strict_Host_Key := False;
      Options.Use_Agent := False;
      Options.Identity_Agent := To_Unbounded_String ("none");

      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "SFTP v4-v6 live integration", "open session");
      Status_Value := SSH_Lib.SFTP.Open (Session_Item, Client_Item, Requested);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "SFTP v4-v6 live integration", "open requested SFTP version");
      Check
        (SSH_Lib.SFTP.Version (Client_Item) >= 4,
         "SFTP v4-v6 live integration negotiated v4 or newer");
      Extensions := SSH_Lib.SFTP.Extensions (Client_Item);
      Check
        (not Extensions.Versions
         or else SSH_Lib.SFTP.Supports_Protocol_Version
           (SSH_Lib.SFTP.Version (Client_Item)),
         "SFTP v4-v6 live integration exposes negotiated metadata");
      if Extensions.Versions
        and then SSH_Lib.SFTP.Version (Client_Item) /= Requested
      then
         Status_Value := SSH_Lib.SFTP.Version_Select
           (Client_Item, SSH_Lib.SFTP.Version (Client_Item));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "SFTP v4-v6 live integration", "version-select current version");
      end if;

      Status_Value := SSH_Lib.SFTP.Remove_File (Client_Item, Remote_File);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Upload_Data
           (Client_Item, Remote_File, Bytes_From_String ("v4-v6-live"), "0600"),
         CryptoLib.Errors.Ok, "SFTP v4-v6 live integration", "upload data");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Download_Data (Client_Item, Remote_File, Data_Buffer),
         CryptoLib.Errors.Ok, "SFTP v4-v6 live integration", "download data");
      Check
        (SSH_Lib.Protocol.Buffers.To_Array (Data_Buffer) =
         Bytes_From_String ("v4-v6-live"),
         "SFTP v4-v6 live integration round-trips bytes");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Stat (Client_Item, Remote_File, Attributes),
         CryptoLib.Errors.Ok, "SFTP v4-v6 live integration", "stat file");
      Check
        (Attributes.Size_Known and then Attributes.Size = 10,
         "SFTP v4-v6 live integration reports uploaded size");

      if Extensions.StatVFS then
         Stats_Info := SSH_Lib.SFTP.StatVFS_Info (Session_Item, Remote_File);
         SSH_Lib.Tests.Assertions.Check_Status
           (Stats_Info.Result.Status, CryptoLib.Errors.Ok,
            "SFTP v4-v6 live integration", "statvfs extension semantics");
         Check
           (SSH_Lib.SFTP.SFTP_Operation'Pos (Stats_Info.Result.Operation) =
              SSH_Lib.SFTP.SFTP_Operation'Pos
                (SSH_Lib.SFTP.StatVFS_Operation),
            "SFTP v4-v6 live integration tags statvfs result");
      end if;

      if Extensions.Limits then
         Limits_Info := SSH_Lib.SFTP.Limits_Info (Session_Item);
         SSH_Lib.Tests.Assertions.Check_Status
           (Limits_Info.Result.Status, CryptoLib.Errors.Ok,
            "SFTP v4-v6 live integration", "limits extension semantics");
         Check
           (SSH_Lib.SFTP.SFTP_Operation'Pos (Limits_Info.Result.Operation) =
              SSH_Lib.SFTP.SFTP_Operation'Pos
                (SSH_Lib.SFTP.Limits_Operation),
            "SFTP v4-v6 live integration tags limits result");
      end if;

      if Extensions.Check_File then
         Check_Info := SSH_Lib.SFTP.Check_File_Info
           (Client_Item, Remote_File, "sha1,sha256,md5");
         SSH_Lib.Tests.Assertions.Check_Status
           (Check_Info.Result.Status, CryptoLib.Errors.Ok,
            "SFTP v4-v6 live integration", "check-file extension semantics");
         Check
           (SSH_Lib.SFTP.SFTP_Operation'Pos (Check_Info.Result.Operation) =
              SSH_Lib.SFTP.SFTP_Operation'Pos
                (SSH_Lib.SFTP.Check_File_Operation)
            and then Length (Check_Info.Algorithm) > 0
            and then SSH_Lib.Protocol.Buffers.Length (Check_Info.Digest) > 0,
            "SFTP v4-v6 live integration returns check-file digest");
      end if;

      Status_Value := SSH_Lib.SFTP.Remove_File (Client_Item, Remote_File);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "SFTP v4-v6 live integration", "remove uploaded file");
      Status_Value := SSH_Lib.SFTP.Close (Client_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "SFTP v4-v6 live integration", "close SFTP client");
      Status_Value := SSH_Lib.Sessions.Close (Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "SFTP v4-v6 live integration", "close session");
   exception
      when others =>
         if SSH_Lib.SFTP.Is_Open (Client_Item) then
            Status_Value := SSH_Lib.SFTP.Remove_File (Client_Item, Remote_File);
            Status_Value := SSH_Lib.SFTP.Close (Client_Item);
         end if;
         if SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item) then
            Status_Value := SSH_Lib.Sessions.Close (Session_Item);
         end if;
         raise;
   end Assert_Optional_Live_SFTP_V4_V6;


   procedure Assert_Optional_Live_SFTP_Against_SSHD is
      Options       : SSH_Lib.Sessions.Session_Options := Base_Options;
      Identity_File : constant String := Env ("SSH_LIB_TEST_SSHD_IDENTITY_FILE");
      Port_Text     : constant String := Env ("SSH_LIB_TEST_SSHD_PORT");
      Strict        : constant Boolean := Env ("SSH_LIB_TEST_SSHD_STRICT") = "1";
      Session_Item  : SSH_Lib.Sessions.Session;
      Status_Value  : CryptoLib.Errors.Status;
      Remote_Root            : constant String := "/tmp/ssh_lib_live_sftp_" & Port_Text;
      Remote_File            : constant String := Remote_Root & "/file.txt";
      Remote_File_Upload     : constant String := Remote_Root & "/upload-file.txt";
      Remote_Resume_Download : constant String := Remote_Root & "/resume-download.txt";
      Remote_Resume_Upload   : constant String := Remote_Root & "/resume-upload.txt";
      Remote_Stream          : constant String := Remote_Root & "/stream.txt";
      Remote_Rename_Source   : constant String := Remote_Root & "/rename-source.txt";
      Remote_Renamed         : constant String := Remote_Root & "/renamed.txt";
      Remote_Hardlink        : constant String := Remote_Root & "/hardlink.txt";
      Remote_Copy_Data       : constant String := Remote_Root & "/copy-data.txt";
      Remote_Link            : constant String := Remote_Root & "/link.txt";
      Remote_Tree            : constant String := Remote_Root & "/tree";
      Remote_Workflow        : constant String := Remote_Root & "/workflow";
      Local_Root             : constant String := "/tmp/ssh_lib_live_sftp_local_" & Port_Text;
      Local_Source           : constant String := Local_Root & "/source";
      Local_Dest             : constant String := Local_Root & "/dest";
      Local_Workflow_Source  : constant String := Local_Root & "/workflow-source";
      Local_Workflow_Restore : constant String := Local_Root & "/workflow-restore";
      Local_File_Source      : constant String := Local_Root & "/upload-file-source.txt";
      Local_File_Dest        : constant String := Local_Root & "/upload-file-dest.txt";
      Local_Partial          : constant String := Local_Root & "/partial.txt";
      Data_Buffer            : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Names                  : Unbounded_String;
      Attributes             : SSH_Lib.SFTP.File_Attributes;
      Metadata               : SSH_Lib.SFTP.File_Attributes;
      Target                 : Unbounded_String;
      Stats                  : SSH_Lib.SFTP.File_System_Stats;
      Limits                 : SSH_Lib.SFTP.Server_Limits;
      Reply_Data             : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Mode_Value             : Interfaces.Unsigned_32 := 0;
      Workflow_Result        : SSH_Lib.File_Transfer.Workflow_Result;
      Workflow_Inventory     : SSH_Lib.File_Transfer.Inventory_Result;
      Workflow_Manifest      : Unbounded_String;
      Supports_Check_File    : Boolean := False;
   begin
      Assert_Optional_Live_SFTP_V4_V6;

      if not Enabled or else Identity_File'Length = 0 then
         return;
      end if;
      Options.Identity_File := To_Unbounded_String (Identity_File);
      Options.Preferred_Authentications := To_Unbounded_String ("publickey");
      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         if Strict then
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Ok,
               "local sshd SFTP integration", "open session for SFTP");
         else
            Check
              (Status_Value = CryptoLib.Errors.Handshake_Failed
               or else Status_Value = CryptoLib.Errors.Unsupported_Feature,
               "local SFTP fixture reaches known unsupported open boundary");
            return;
         end if;
      end if;

      Remove_Local_Tree_If_Exists (Local_Root);
      Ada.Directories.Create_Path (Local_Source & "/nested");
      Write_Test_File
        (Local_Source & "/nested/data.txt", Bytes_From_String ("tree-data"));
      Ada.Directories.Create_Path (Local_Workflow_Source & "/nested");
      Write_Test_File
        (Local_Workflow_Source & "/upload.txt", Bytes_From_String ("workflow-root"));
      Write_Test_File
        (Local_Workflow_Source & "/nested/child.txt",
         Bytes_From_String ("workflow-child"));

      --  The remote root may be absent or half-created from an interrupted
      --  prior run. Some SFTP failure paths close the SSH session, so perform
      --  setup cleanup on a throwaway session and reopen for the strict path.
      Status_Value := SSH_Lib.SFTP.Remove_Tree (Session_Item, Remote_Root);
      if SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item) then
         Status_Value := SSH_Lib.Sessions.Close (Session_Item);
      end if;

      Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         if Strict then
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Ok,
               "local sshd SFTP integration", "reopen session after cleanup");
         else
            Check
              (Status_Value = CryptoLib.Errors.Handshake_Failed
               or else Status_Value = CryptoLib.Errors.Unsupported_Feature,
               "local SFTP fixture reopens after setup cleanup");
            Remove_Local_Tree_If_Exists (Local_Root);
            return;
         end if;
      end if;

      Status_Value := SSH_Lib.SFTP.Make_Directory
        (Session_Item, Remote_Root, "0700");
      if Status_Value /= CryptoLib.Errors.Ok then
         if Strict then
            SSH_Lib.Tests.Assertions.Check_Status
              (Status_Value, CryptoLib.Errors.Ok,
               "local sshd SFTP integration", "mkdir remote root");
         else
            Check
              (Status_Value = CryptoLib.Errors.Channel_Open_Failed
               or else Status_Value = CryptoLib.Errors.Unsupported_Feature,
               "local SFTP fixture reaches known subsystem open boundary");
            Remove_Local_Tree_If_Exists (Local_Root);
            Status_Value := SSH_Lib.Sessions.Close (Session_Item);
            return;
         end if;
      end if;
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Upload_Data
           (Session_Item, Remote_File, Bytes_From_String ("hello-live"), "0600"),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "upload data");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Download_Data (Session_Item, Remote_File, Data_Buffer),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "download data");
      Check
        (SSH_Lib.Protocol.Buffers.To_Array (Data_Buffer)
         = Bytes_From_String ("hello-live"),
         "local SFTP download returns uploaded bytes");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.List_Directory (Session_Item, Remote_Root, Names),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "list directory");
      Check
        (Ada.Strings.Unbounded.Index (Names, "file.txt") > 0,
         "local SFTP list includes uploaded file");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Stat (Session_Item, Remote_File, Attributes),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "stat file");
      Check
        (Attributes.Size_Known and then Attributes.Size = 10,
         "local SFTP stat reports uploaded size");

      Check
        (SSH_Lib.SFTP.Is_Regular_File (Attributes),
         "local SFTP stat reports regular file type");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Set_Permissions (Session_Item, Remote_File, "0644"),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "set permissions");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Stat (Session_Item, Remote_File, Attributes),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "stat changed permissions");
      Check
        (SSH_Lib.SFTP.Mode_To_Permissions ("0644", Mode_Value)
         and then SSH_Lib.SFTP.Permission_Bits (Attributes) = Mode_Value
         and then SSH_Lib.SFTP.Permissions_To_Mode (Attributes.Permissions) = "0644"
         and then SSH_Lib.SFTP.Owner_Can_Read (Attributes)
         and then SSH_Lib.SFTP.Owner_Can_Write (Attributes)
         and then SSH_Lib.SFTP.Group_Can_Read (Attributes)
         and then SSH_Lib.SFTP.Other_Can_Read (Attributes),
         "local SFTP metadata helpers round-trip permissions");
      Metadata := SSH_Lib.SFTP.Copy_Metadata (Attributes);
      Check
        (SSH_Lib.SFTP.Mode_To_Permissions ("0600", Mode_Value)
         and then SSH_Lib.SFTP.Set_Permissions_Mode (Metadata, "0600"),
         "local SFTP converts metadata update mode");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Set_Attributes (Session_Item, Remote_File, Metadata),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "set copied metadata");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Stat (Session_Item, Remote_File, Attributes),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "stat copied metadata");
      Check
        (SSH_Lib.SFTP.Permission_Bits (Attributes) = Mode_Value,
         "local SFTP copied metadata updates permissions");

      Write_Test_File
        (Local_File_Source, Bytes_From_String ("file-live"));
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Upload_File
           (Session_Item, Remote_File_Upload, Local_File_Source, "0600"),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "upload local file");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Download_File
           (Session_Item, Remote_File_Upload, Local_File_Dest),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "download remote file");
      Check
        (Read_Test_File (Local_File_Dest) = Bytes_From_String ("file-live"),
         "local SFTP file download returns uploaded local file bytes");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Upload_Data
           (Session_Item, Remote_Resume_Download,
            Bytes_From_String ("resume-download"), "0600"),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "seed resume download");
      Write_Test_File (Local_Partial, Bytes_From_String ("resume-"));
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Resume_Download_File
           (Session_Item, Remote_Resume_Download, Local_Partial),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "resume download");
      Check
        (Read_Test_File (Local_Partial) = Bytes_From_String ("resume-download"),
         "local SFTP resume download appends missing suffix");

      Write_Test_File (Local_File_Source, Bytes_From_String ("resume-upload"));
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Upload_Data
           (Session_Item, Remote_Resume_Upload, Bytes_From_String ("resume-"),
            "0600"),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "seed resume upload");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Resume_Upload_File
           (Session_Item, Remote_Resume_Upload, Local_File_Source, "0600"),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "resume upload");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Download_Data
           (Session_Item, Remote_Resume_Upload, Data_Buffer),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "read resumed upload");
      Check
        (SSH_Lib.Protocol.Buffers.To_Array (Data_Buffer)
         = Bytes_From_String ("resume-upload"),
         "local SFTP resume upload writes missing suffix");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Buffers.Set
           (Stream_Upload_Source, Bytes_From_String ("stream-live")),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "seed stream upload");
      Stream_Upload_Limit := 4;
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Upload_Stream
           (Session_Item, Remote_Stream, 11, Provide_Stream_Chunk'Access, "0600"),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "upload stream");
      Stream_Upload_Limit := 0;
      SSH_Lib.Protocol.Buffers.Clear (Stream_Download_Buffer);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Download_Stream
           (Session_Item, Remote_Stream, Capture_Stream_Chunk'Access),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "download stream");
      Check
        (SSH_Lib.Protocol.Buffers.To_Array (Stream_Download_Buffer)
         = Bytes_From_String ("stream-live"),
         "local SFTP stream download returns uploaded stream bytes");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Read_At
           (Session_Item, Remote_Stream, 7, 4, Data_Buffer),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "read at offset");
      Check
        (SSH_Lib.Protocol.Buffers.To_Array (Data_Buffer)
         = Bytes_From_String ("live"),
         "local SFTP read-at returns requested range");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Write_At
           (Session_Item, Remote_Stream, 7, Bytes_From_String ("data"), "0600"),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "write at offset");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Download_Data (Session_Item, Remote_Stream, Data_Buffer),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "read write-at result");
      Check
        (SSH_Lib.Protocol.Buffers.To_Array (Data_Buffer)
         = Bytes_From_String ("stream-data"),
         "local SFTP write-at updates requested range");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.FStat (Session_Item, Remote_Stream, Attributes),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "fstat by path");
      Check
        (Attributes.Size_Known and then Attributes.Size = 11,
         "local SFTP fstat reports stream size");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Set_Handle_Permissions
           (Session_Item, Remote_Stream, "0644"),
         CryptoLib.Errors.Ok, "local sshd SFTP integration",
         "set handle permissions by path");
      Metadata := SSH_Lib.SFTP.Copy_Metadata (Attributes);
      Metadata.Permissions_Known := True;
      Metadata.Permissions :=
        (Attributes.Permissions and Interfaces.Unsigned_32'(16#FFFF_F000#))
        or 8#600#;
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Set_Handle_Attributes
           (Session_Item, Remote_Stream, Metadata),
         CryptoLib.Errors.Ok, "local sshd SFTP integration",
         "set handle attributes by path");
      Status_Value := SSH_Lib.SFTP.Fsync (Session_Item, Remote_Stream);
      Check
        (Status_Value = CryptoLib.Errors.Ok
         or else Status_Value = CryptoLib.Errors.Unsupported_Feature,
         "local SFTP fsync returns success or unsupported");

      declare
         Client_Item : SSH_Lib.SFTP.Client;
      begin
         SSH_Lib.Tests.Assertions.Check_Status
           (SSH_Lib.SFTP.Open (Session_Item, Client_Item),
            CryptoLib.Errors.Ok, "local sshd SFTP integration",
            "open persistent client");
         Check
           (SSH_Lib.SFTP.Is_Open (Client_Item)
            and then SSH_Lib.SFTP.Version (Client_Item) = SSH_Lib.SFTP.Protocol_Version,
            "local SFTP persistent client exposes version");
         SSH_Lib.Tests.Assertions.Check_Status
           (SSH_Lib.SFTP.Stat (Client_Item, Remote_Stream, Attributes),
            CryptoLib.Errors.Ok, "local sshd SFTP integration",
            "persistent client stat");
         SSH_Lib.Tests.Assertions.Check_Status
           (SSH_Lib.SFTP.Download_Data
              (Client_Item, Remote_Stream, Data_Buffer),
            CryptoLib.Errors.Ok, "local sshd SFTP integration",
            "persistent client download");
         Check
           (SSH_Lib.Protocol.Buffers.To_Array (Data_Buffer)
            = Bytes_From_String ("stream-data"),
            "local SFTP persistent client download returns bytes");
         SSH_Lib.Tests.Assertions.Check_Status
           (SSH_Lib.SFTP.Close (Client_Item),
            CryptoLib.Errors.Ok, "local sshd SFTP integration",
            "close persistent client");
      end;

      Status_Value := SSH_Lib.SFTP.Copy_File_Range
        (Session_Item, Remote_Stream, Remote_Copy_Data, 0, 6, 0, "0600");
      Check
        (Status_Value = CryptoLib.Errors.Ok
         or else Status_Value = CryptoLib.Errors.Unsupported_Feature,
         "local SFTP copy-data returns success or unsupported");
      if Status_Value = CryptoLib.Errors.Ok then
         SSH_Lib.Tests.Assertions.Check_Status
           (SSH_Lib.SFTP.Download_Data
              (Session_Item, Remote_Copy_Data, Data_Buffer),
            CryptoLib.Errors.Ok, "local sshd SFTP integration",
            "read copy-data result");
         Check
           (SSH_Lib.Protocol.Buffers.To_Array (Data_Buffer)
            = Bytes_From_String ("stream"),
            "local SFTP copy-data copies requested range");
      end if;

      Directory_Page_Calls := 0;
      Directory_Page_Entries := 0;
      Directory_Page_Names := Null_Unbounded_String;
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.List_Directory_Paged
           (Session_Item, Remote_Root, Capture_Directory_Page'Access),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "paged list directory");
      Check
        (Directory_Page_Calls > 0
         and then Directory_Page_Entries > 0
         and then Ada.Strings.Unbounded.Index
           (Directory_Page_Names, "stream.txt") > 0,
         "local SFTP paged list includes streamed file");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Upload_Data
           (Session_Item, Remote_Rename_Source, Bytes_From_String ("rename-live"),
            "0600"),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "seed rename source");
      Status_Value := SSH_Lib.SFTP.Posix_Rename
        (Session_Item, Remote_Rename_Source, Remote_Renamed);
      Check
        (Status_Value = CryptoLib.Errors.Ok
         or else Status_Value = CryptoLib.Errors.Unsupported_Feature,
         "local SFTP posix rename returns success or unsupported");
      if Status_Value = CryptoLib.Errors.Ok then
         SSH_Lib.Tests.Assertions.Check_Status
           (SSH_Lib.SFTP.Download_Data
              (Session_Item, Remote_Renamed, Data_Buffer),
            CryptoLib.Errors.Ok, "local sshd SFTP integration",
            "read posix-renamed file");
         Check
           (SSH_Lib.Protocol.Buffers.To_Array (Data_Buffer)
            = Bytes_From_String ("rename-live"),
            "local SFTP posix rename preserves contents");
         Status_Value := SSH_Lib.SFTP.Hardlink
           (Session_Item, Remote_Renamed, Remote_Hardlink);
         Check
           (Status_Value = CryptoLib.Errors.Ok
            or else Status_Value = CryptoLib.Errors.Unsupported_Feature
            or else Status_Value = CryptoLib.Errors.Remote_Failure,
            "local SFTP hardlink returns success or supported server failure");
      end if;

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Create_Symlink (Session_Item, "file.txt", Remote_Link),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "create symlink");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Read_Link (Session_Item, Remote_Link, Target),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "read symlink");
      Check
        (To_String (Target) = "file.txt",
         "local SFTP readlink returns symlink target");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Upload_Directory
           (Session_Item, Remote_Tree, Local_Source, "0700", "0600"),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "recursive upload");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Download_Directory (Session_Item, Remote_Tree, Local_Dest),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "recursive download");
      Check
        (Read_Test_File (Local_Dest & "/nested/data.txt")
         = Bytes_From_String ("tree-data"),
         "local SFTP recursive download returns tree data");

      declare
         Client_Item : SSH_Lib.SFTP.Client;
      begin
         SSH_Lib.Tests.Assertions.Check_Status
           (SSH_Lib.SFTP.Open (Session_Item, Client_Item),
            CryptoLib.Errors.Ok, "local sshd workflow integration",
            "open client for workflow extension discovery");
         Supports_Check_File :=
           SSH_Lib.SFTP.Extensions (Client_Item).Check_File;
         SSH_Lib.Tests.Assertions.Check_Status
           (SSH_Lib.SFTP.Close (Client_Item), CryptoLib.Errors.Ok,
            "local sshd workflow integration", "close extension client");
      end;

      Workflow_Result := SSH_Lib.File_Transfer.Upload
        (Session_Item, Local_Workflow_Source, Remote_Workflow,
         Recursive => True);
      SSH_Lib.Tests.Assertions.Check_Status
        (Workflow_Result.Status, CryptoLib.Errors.Ok,
         "local sshd workflow integration", "workflow upload");
      Check
        (Workflow_Result.Items_Processed >= 3
         and then Workflow_Result.Bytes_Processed >= 27,
         "local workflow upload reports recursive counts");

      if Supports_Check_File then
         Workflow_Inventory := SSH_Lib.File_Transfer.Inventory_With_Checks
           (Session_Item, Remote_Workflow, Recursive => True,
            Algorithms => "sha256");
      else
         Workflow_Inventory := SSH_Lib.File_Transfer.Inventory
           (Session_Item, Remote_Workflow, Recursive => True);
      end if;
      SSH_Lib.Tests.Assertions.Check_Status
        (Workflow_Inventory.Result.Status, CryptoLib.Errors.Ok,
         "local sshd workflow integration", "workflow inventory");
      Check
        (Natural (Workflow_Inventory.Entries.Length) >= 3,
         "local workflow inventory includes recursive files");

      Workflow_Manifest :=
        SSH_Lib.File_Transfer.Inventory_Manifest (Workflow_Inventory);
      Workflow_Result := SSH_Lib.File_Transfer.Verify_Inventory
        (Session_Item, To_String (Workflow_Manifest), Remote_Workflow,
         Recursive => True);
      SSH_Lib.Tests.Assertions.Check_Status
        (Workflow_Result.Status, CryptoLib.Errors.Ok,
         "local sshd workflow integration", "workflow verify manifest");
      Check (Workflow_Result.Verified,
             "local workflow manifest verification succeeds");

      Remove_Local_Tree_If_Exists (Local_Workflow_Restore);
      Workflow_Result := SSH_Lib.File_Transfer.Restore_From_Manifest
        (Session_Item, To_String (Workflow_Manifest), Remote_Workflow,
         Local_Workflow_Restore);
      SSH_Lib.Tests.Assertions.Check_Status
        (Workflow_Result.Status, CryptoLib.Errors.Ok,
         "local sshd workflow integration", "workflow restore manifest");
      Check
        (Read_Test_File (Local_Workflow_Restore & "/upload.txt")
         = Bytes_From_String ("workflow-root")
         and then Read_Test_File
           (Local_Workflow_Restore & "/nested/child.txt")
           = Bytes_From_String ("workflow-child"),
         "local workflow restore returns uploaded bytes");

      Workflow_Result := SSH_Lib.File_Transfer.Delete
        (Session_Item, Remote_Workflow,
         Target => SSH_Lib.File_Transfer.Delete_Tree);
      SSH_Lib.Tests.Assertions.Check_Status
        (Workflow_Result.Status, CryptoLib.Errors.Ok,
         "local sshd workflow integration", "workflow delete tree");
      Check
        (Workflow_Result.Items_Processed >= 3,
         "local workflow delete reports recursive counts");

      Status_Value := SSH_Lib.SFTP.StatVFS (Session_Item, Remote_Root, Stats);
      Check
        (Status_Value = CryptoLib.Errors.Ok
         or else Status_Value = CryptoLib.Errors.Unsupported_Feature,
         "local SFTP statvfs returns data or unsupported");
      if Status_Value = CryptoLib.Errors.Ok then
         Check (Stats.Block_Size > 0, "local SFTP statvfs reports block size");
      end if;

      Status_Value := SSH_Lib.SFTP.Limits (Session_Item, Limits);
      Check
        (Status_Value = CryptoLib.Errors.Ok
         or else Status_Value = CryptoLib.Errors.Unsupported_Feature,
         "local SFTP limits returns data or unsupported");
      if Status_Value = CryptoLib.Errors.Ok then
         Check
           (Limits.Max_Packet_Length > 0,
            "local SFTP limits reports packet length");
      end if;

      Status_Value := SSH_Lib.SFTP.Expand_Path (Session_Item, Remote_Root, Target);
      Check
        (Status_Value = CryptoLib.Errors.Ok
         or else Status_Value = CryptoLib.Errors.Unsupported_Feature,
         "local SFTP expand-path returns data or unsupported");
      if Status_Value = CryptoLib.Errors.Ok then
         Check (Ada.Strings.Unbounded.Length (Target) > 0,
                "local SFTP expand-path reports a path");
      end if;

      Status_Value := SSH_Lib.SFTP.Extended_Request
        (Session_Item,
         "unknown-extension@ada-ssh.test",
         Ada.Streams.Stream_Element_Array'(1 .. 0 => 0),
         Reply_Data);
      Check
        (Status_Value = CryptoLib.Errors.Unsupported_Feature
         or else Status_Value = CryptoLib.Errors.Remote_Failure
         or else Status_Value = CryptoLib.Errors.Ok,
         "local SFTP generic extension gets a server response");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.SFTP.Remove_Tree (Session_Item, Remote_Root),
         CryptoLib.Errors.Ok, "local sshd SFTP integration", "remove remote tree");
      Remove_Local_Tree_If_Exists (Local_Root);
      Status_Value := SSH_Lib.Sessions.Close (Session_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "local sshd SFTP integration", "close session");
   exception
      when others =>
         Remove_Local_Tree_If_Exists (Local_Root);
         if SSH_Lib.Sessions.Test_Support.Is_Open_For_Test (Session_Item) then
            Status_Value := SSH_Lib.SFTP.Remove_Tree (Session_Item, Remote_Root);
            Status_Value := SSH_Lib.Sessions.Close (Session_Item);
         end if;
         raise;
   end Assert_Optional_Live_SFTP_Against_SSHD;

   procedure Assert_Optional_Live_Userauth_Against_SSHD is
      Host_Text : constant String := Env ("SSH_LIB_TEST_SSHD_HOST");
      User_Text : constant String := Env ("SSH_LIB_TEST_SSHD_USER");
      Port      : constant Natural := Port_From_Environment;
   begin
      if not Enabled then
         return;
      end if;

      Check (Host_Text'Length > 0, "local sshd fixture host configured");
      Check (User_Text'Length > 0, "local sshd fixture user configured");
      Check (Port > 0, "local sshd fixture port configured");
      Check
        (Env ("SSH_LIB_TEST_SSHD_IDENTITY_FILE")'Length > 0
         or else Env ("SSH_LIB_TEST_SSHD_PASSWORD")'Length > 0
         or else Env ("SSH_LIB_TEST_SSHD_KBDINT_PASSWORD")'Length > 0,
         "local sshd fixture has at least one auth method configured");

      Assert_Publickey;
      Assert_Password;
      Assert_Keyboard_Interactive;
   end Assert_Optional_Live_Userauth_Against_SSHD;
end SSH_Lib.Tests.Fixtures.Local_SSHD;
