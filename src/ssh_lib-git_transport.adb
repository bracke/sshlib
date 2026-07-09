with Ada.Characters.Handling;
with Ada.Strings.Fixed;
with GNAT.Expect;
with GNAT.OS_Lib;
with Interfaces;
with Interfaces.C;
with SSH_Lib.Remote_Names;

package body SSH_Lib.Git_Transport is
   use CryptoLib.Errors;
   use Ada.Strings.Unbounded;
   use type Ada.Streams.Stream_Element_Offset;
   use type GNAT.OS_Lib.File_Descriptor;
   use type GNAT.OS_Lib.String_Access;
   use type Interfaces.C.int;

   Read_Buffer_Size : constant Natural := 4096;

   type Poll_FD is record
      FD      : Interfaces.C.int;
      Events  : Interfaces.C.short;
      Revents : Interfaces.C.short;
   end record
     with Convention => C;

   function C_Poll
     (FDs     : access Poll_FD;
      NFDs    : Interfaces.C.unsigned_long;
      Timeout : Interfaces.C.int) return Interfaces.C.int
     with Import, Convention => C, External_Name => "poll";

   Poll_Input_Event  : constant Interfaces.C.short := 16#0001#;
   Poll_Output_Event : constant Interfaces.C.short := 16#0004#;

   function Starts_With_Ssh_Scheme (Value : String) return Boolean is
      Prefix : constant String := "ssh://";
      Lower_Value : constant String := Ada.Characters.Handling.To_Lower (Value);
   begin
      return Value'Length >= Prefix'Length
        and then Lower_Value (Lower_Value'First .. Lower_Value'First + Prefix'Length - 1) = Prefix;
   end Starts_With_Ssh_Scheme;

   function Has_Control_Break (Value : String) return Boolean is
   begin
      for Text_Character of Value loop
         if Text_Character = Character'Val (0)
           or else Text_Character = Character'Val (10)
           or else Text_Character = Character'Val (13)
         then
            return True;
         end if;
      end loop;

      return False;
   end Has_Control_Break;

   function Control_Break_Is_In_Repository (Value : String) return Boolean is
   begin
      if not Has_Control_Break (Value) then
         return False;
      end if;

      if Starts_With_Ssh_Scheme (Value) then
         declare
            Prefix : constant String := "ssh://";
            Remainder_First : constant Natural := Value'First + Prefix'Length;
            Slash_Position : constant Natural :=
              Ada.Strings.Fixed.Index
                (Value (Remainder_First .. Value'Last), "/");
         begin
            if Slash_Position = 0 then
               return False;
            end if;

            for Index_Value in Slash_Position + 1 .. Value'Last loop
               if Value (Index_Value) = Character'Val (0)
                 or else Value (Index_Value) = Character'Val (10)
                 or else Value (Index_Value) = Character'Val (13)
               then
                  return True;
               end if;
            end loop;

            return False;
         end;
      else
         declare
            Colon_Position : constant Natural := Ada.Strings.Fixed.Index (Value, ":");
         begin
            if Colon_Position = 0 or else Colon_Position = Value'Last then
               return False;
            end if;

            for Index_Value in Colon_Position + 1 .. Value'Last loop
               if Value (Index_Value) = Character'Val (0)
                 or else Value (Index_Value) = Character'Val (10)
                 or else Value (Index_Value) = Character'Val (13)
               then
                  return True;
               end if;
            end loop;

            return False;
         end;
      end if;
   exception
      when others =>
         return False;
   end Control_Break_Is_In_Repository;

   function Prepare
     (Remote_Text  : String;
      Config       : SSH_Lib.Config.Host_Config;
      Default_User : String;
      Requested    : Service;
      Options      : out SSH_Lib.Sessions.Session_Options;
      Command      : out Unbounded_String)
      return CryptoLib.Errors.Status
   is
      Remote_Item  : SSH_Lib.Remote_Names.Parsed_Remote;
      Status_Value : CryptoLib.Errors.Status;
      Repository   : Unbounded_String := Null_Unbounded_String;
   begin
      if Control_Break_Is_In_Repository (Remote_Text) then
         Options := (Host                 => Null_Unbounded_String,
                     Port                 => 22,
                     User                 => Null_Unbounded_String,
                     Connect_Timeout_MS   => 30_000,
                     Read_Timeout_MS      => 30_000,
                     Write_Timeout_MS     => 30_000,
                     Verify_Known_Host    => True,
                     Known_Hosts_File     => Null_Unbounded_String,
                     Identity_File        => Null_Unbounded_String,
                     Certificate_File     => Null_Unbounded_String,
                     Use_Agent            => True,
                     Strict_Host_Key      => True,
                     Proxy_Jump           => Null_Unbounded_String,
                     Proxy_Command        => Null_Unbounded_String,
                     Use_Password         => False,
                     Password             => Null_Unbounded_String,
                     Use_Identity_Passphrase => False,
                     Identity_Passphrase  => Null_Unbounded_String,
                     Password_Callback     => null,
                     Identity_Passphrase_Callback => null,
                     Password_Change_Callback => null,
                     others => <>);
         Command := Null_Unbounded_String;
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Options := (Host                 => Null_Unbounded_String,
                  Port                 => 22,
                  User                 => Null_Unbounded_String,
                  Connect_Timeout_MS   => 30_000,
                  Read_Timeout_MS      => 30_000,
                  Write_Timeout_MS     => 30_000,
                  Verify_Known_Host    => True,
                  Known_Hosts_File     => Null_Unbounded_String,
                  Identity_File        => Null_Unbounded_String,
                  Certificate_File     => Null_Unbounded_String,
                  Use_Agent            => True,
                  Strict_Host_Key      => True,
                     Proxy_Jump           => Null_Unbounded_String,
                     Proxy_Command        => Null_Unbounded_String,
                     Use_Password         => False,
                     Password             => Null_Unbounded_String,
                     Use_Identity_Passphrase => False,
                     Identity_Passphrase  => Null_Unbounded_String,
                     Password_Callback     => null,
                     Identity_Passphrase_Callback => null,
                     Password_Change_Callback => null,
                     others => <>);
      Command := Null_Unbounded_String;

      Status_Value := SSH_Lib.Remote_Names.Parse (Remote_Text, Remote_Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Repository := To_Unbounded_String
        (SSH_Lib.Remote_Names.Repository_Path (Remote_Item));
      if Length (Repository) = 0 then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      if SSH_Lib.Config.Has_Unsupported_Feature
        (Config, SSH_Lib.Remote_Names.Host (Remote_Item))
      then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;

      --  Resolve config before applying remote overrides.  Do not pass
      --  Default_User when the remote already contains an explicit user:
      --  for version, remote user is authoritative and should not be made
      --  dependent on a default-user fallback that will never be used.
      Status_Value := SSH_Lib.Config.Resolve
        (Config,
         SSH_Lib.Remote_Names.Host (Remote_Item),
         (if SSH_Lib.Remote_Names.Has_User (Remote_Item) then "" else Default_User),
         Options);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      if SSH_Lib.Remote_Names.Has_User (Remote_Item) then
         Options.User := To_Unbounded_String
           (SSH_Lib.Remote_Names.User (Remote_Item));
      end if;

      if SSH_Lib.Remote_Names.Has_Explicit_Port (Remote_Text) then
         Options.Port := SSH_Lib.Remote_Names.Port (Remote_Item);
      end if;

      Options.Verify_Known_Host := True;
      Options.Strict_Host_Key := True;

      if Length (Options.User) = 0 then
         return CryptoLib.Errors.Invalid_User;
      end if;

      case Requested is
         when Upload_Pack =>
            Status_Value := SSH_Lib.Git.Build_Upload_Pack_Command
              (To_String (Repository), Command);
         when Receive_Pack =>
            Status_Value := SSH_Lib.Git.Build_Receive_Pack_Command
              (To_String (Repository), Command);
      end case;

      if Status_Value /= CryptoLib.Errors.Ok then
         Command := Null_Unbounded_String;
         return Status_Value;
      end if;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Options := (Host                 => Null_Unbounded_String,
                     Port                 => 22,
                     User                 => Null_Unbounded_String,
                     Connect_Timeout_MS   => 30_000,
                     Read_Timeout_MS      => 30_000,
                     Write_Timeout_MS     => 30_000,
                     Verify_Known_Host    => True,
                     Known_Hosts_File     => Null_Unbounded_String,
                     Identity_File        => Null_Unbounded_String,
                     Certificate_File     => Null_Unbounded_String,
                     Use_Agent            => True,
                     Strict_Host_Key      => True,
                     Proxy_Jump           => Null_Unbounded_String,
                     Proxy_Command        => Null_Unbounded_String,
                     Use_Password         => False,
                     Password             => Null_Unbounded_String,
                     Use_Identity_Passphrase => False,
                     Identity_Passphrase  => Null_Unbounded_String,
                     Password_Callback     => null,
                     Identity_Passphrase_Callback => null,
                     Password_Change_Callback => null,
                     others => <>);
         Command := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end Prepare;

   function Open_Service
     (Session   : in out SSH_Lib.Sessions.Session;
      Requested : Service;
      Command   : String;
      Channel   : in out SSH_Lib.Channels.Channel)
      return CryptoLib.Errors.Status
   is
      pragma Unreferenced (Requested);
   begin
      return SSH_Lib.Channels.Open_Exec (Session, Command, Channel);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Open_Service;

   function Copy_Response_Chunk
     (Source   : Ada.Streams.Stream_Element_Array;
      Target   : in out Ada.Streams.Stream_Element_Array;
      Last     : in out Ada.Streams.Stream_Element_Offset;
      Summary  : in out Git_Workflow_Summary)
      return CryptoLib.Errors.Status
   is
      Target_Index : Ada.Streams.Stream_Element_Offset;
   begin
      if Source'Length = 0 then
         return CryptoLib.Errors.Ok;
      end if;

      if Target'Length = 0 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      if Last < Target'First then
         Target_Index := Target'First;
      else
         Target_Index := Last + 1;
      end if;

      if Target_Index > Target'Last
        or else Source'Length >
          Natural (Target'Last - Target_Index + 1)
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      for Source_Index in Source'Range loop
         Target (Target_Index) := Source (Source_Index);
         Target_Index := Target_Index + 1;
      end loop;

      Last := Target_Index - 1;
      Summary.Response_Bytes := Summary.Response_Bytes + Source'Length;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Copy_Response_Chunk;

   function Validate_Response
     (Requested : Service;
      Response  : Ada.Streams.Stream_Element_Array;
      Summary   : in out Git_Workflow_Summary)
      return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status;
   begin
      case Requested is
         when Upload_Pack =>
            Status_Value := SSH_Lib.Git.Validate_Upload_Pack_Response
              (Response, Summary.Upload_Response);
         when Receive_Pack =>
            Status_Value := SSH_Lib.Git.Validate_Receive_Pack_Report
              (Response, Summary.Receive_Report);
      end case;

      Summary.Response_Validated := Status_Value = CryptoLib.Errors.Ok;
      return Status_Value;
   exception
      when others =>
         Summary.Response_Validated := False;
         return CryptoLib.Errors.Internal_Error;
   end Validate_Response;

   function Complete_Service
     (Channel  : in out SSH_Lib.Channels.Channel;
      Requested : Service;
      Request  : Ada.Streams.Stream_Element_Array;
      Response : out Ada.Streams.Stream_Element_Array;
      Last     : out Ada.Streams.Stream_Element_Offset;
      Summary  : out Git_Workflow_Summary)
      return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Read_Buffer  : Ada.Streams.Stream_Element_Array
        (Ada.Streams.Stream_Element_Offset'(1)
         .. Ada.Streams.Stream_Element_Offset (Read_Buffer_Size));
      Read_Last    : Ada.Streams.Stream_Element_Offset;
      Exit_Code    : Integer := 0;
   begin
      Summary := (Requested => Requested, others => <>);
      Summary.Request_Bytes := Request'Length;
      if Response'Length = 0 then
         Last := Response'First - 1;
      else
         Last := Response'First - 1;
      end if;

      Status_Value := SSH_Lib.Channels.Write (Channel, Request);
      if Status_Value /= CryptoLib.Errors.Ok then
         Close_Status := SSH_Lib.Channels.Close (Channel);
         if Close_Status /= CryptoLib.Errors.Ok then
            return Close_Status;
         end if;
         return Status_Value;
      end if;

      Status_Value := SSH_Lib.Channels.Send_EOF (Channel);
      if Status_Value /= CryptoLib.Errors.Ok then
         Close_Status := SSH_Lib.Channels.Close (Channel);
         if Close_Status /= CryptoLib.Errors.Ok then
            return Close_Status;
         end if;
         return Status_Value;
      end if;

      loop
         Status_Value := SSH_Lib.Channels.Read_Some
           (Channel, Read_Buffer, Read_Last);
         exit when Status_Value = CryptoLib.Errors.End_Of_Stream;

         if Status_Value /= CryptoLib.Errors.Ok then
            Close_Status := SSH_Lib.Channels.Close (Channel);
            if Close_Status /= CryptoLib.Errors.Ok then
               return Close_Status;
            end if;
            return Status_Value;
         end if;

         if Read_Last >= Read_Buffer'First then
            Status_Value := Copy_Response_Chunk
              (Read_Buffer (Read_Buffer'First .. Read_Last),
               Response,
               Last,
               Summary);
            if Status_Value /= CryptoLib.Errors.Ok then
               Close_Status := SSH_Lib.Channels.Close (Channel);
               if Close_Status /= CryptoLib.Errors.Ok then
                  return Close_Status;
               end if;
               return Status_Value;
            end if;
         end if;
      end loop;

      if Summary.Response_Bytes = 0 then
         Status_Value := CryptoLib.Errors.Read_Failed;
      else
         Status_Value := Validate_Response
           (Requested, Response (Response'First .. Last), Summary);
      end if;

      if Status_Value /= CryptoLib.Errors.Ok then
         Close_Status := SSH_Lib.Channels.Close (Channel);
         if Close_Status /= CryptoLib.Errors.Ok then
            return Close_Status;
         end if;
         return Status_Value;
      end if;

      Status_Value := SSH_Lib.Channels.Exit_Status (Channel, Exit_Code);
      Summary.Exit_Code := Exit_Code;
      Summary.Remote_Exit_Observed := Status_Value = CryptoLib.Errors.Ok
        or else Status_Value = CryptoLib.Errors.Remote_Exit_Nonzero;

      Close_Status := SSH_Lib.Channels.Close (Channel);
      if Status_Value = CryptoLib.Errors.Channel_Request_Failed then
         if Close_Status /= CryptoLib.Errors.Ok then
            return Close_Status;
         else
            return CryptoLib.Errors.Ok;
         end if;
      elsif Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif Close_Status /= CryptoLib.Errors.Ok then
         return Close_Status;
      else
         return CryptoLib.Errors.Ok;
      end if;
   exception
      when others =>
         Summary := (Requested => Requested, others => <>);
         Last := Response'First - 1;
         return CryptoLib.Errors.Internal_Error;
   end Complete_Service;

   function Run_Service
     (Session   : in out SSH_Lib.Sessions.Session;
      Requested : Service;
      Command   : String;
      Request   : Ada.Streams.Stream_Element_Array;
      Response  : out Ada.Streams.Stream_Element_Array;
      Last      : out Ada.Streams.Stream_Element_Offset;
      Summary   : out Git_Workflow_Summary)
      return CryptoLib.Errors.Status
   is
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Summary := (Requested => Requested, others => <>);
      Last := Response'First - 1;

      Status_Value := Open_Service
        (Session, Requested, Command, Channel_Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      return Complete_Service
        (Channel_Item, Requested, Request, Response, Last, Summary);
   exception
      when others =>
         Summary := (Requested => Requested, others => <>);
         Last := Response'First - 1;
         return CryptoLib.Errors.Internal_Error;
   end Run_Service;

   function Wait_For_Process_FD
     (FD         : GNAT.OS_Lib.File_Descriptor;
      For_Write  : Boolean;
      Timeout_MS : Natural) return CryptoLib.Errors.Status
   is
      Event : constant Interfaces.C.short :=
        (if For_Write then Poll_Output_Event else Poll_Input_Event);
      Poll_Item : aliased Poll_FD :=
        (FD      => Interfaces.C.int (FD),
         Events  => Event,
         Revents => 0);
      Poll_Timeout : Interfaces.C.int;
      Result       : Interfaces.C.int;
   begin
      if FD = GNAT.OS_Lib.Invalid_FD then
         if For_Write then
            return CryptoLib.Errors.Write_Failed;
         end if;
         return CryptoLib.Errors.Read_Failed;
      end if;

      if Timeout_MS = 0 then
         Poll_Timeout := -1;
      else
         Poll_Timeout := Interfaces.C.int (Timeout_MS);
      end if;

      Result := C_Poll (Poll_Item'Access, 1, Poll_Timeout);
      if Result > 0 then
         return CryptoLib.Errors.Ok;
      elsif Result = 0 then
         return CryptoLib.Errors.Timeout;
      elsif For_Write then
         return CryptoLib.Errors.Write_Failed;
      else
         return CryptoLib.Errors.Read_Failed;
      end if;
   exception
      when others =>
         if For_Write then
            return CryptoLib.Errors.Write_Failed;
         end if;
         return CryptoLib.Errors.Read_Failed;
   end Wait_For_Process_FD;

   function Run_Subprocess_Service
     (Program_Name : String;
      Arguments    : GNAT.OS_Lib.Argument_List;
      Requested    : Service;
      Request      : Ada.Streams.Stream_Element_Array;
      Response     : out Ada.Streams.Stream_Element_Array;
      Last         : out Ada.Streams.Stream_Element_Offset;
      Summary      : out Git_Workflow_Summary;
      Timeout_MS   : Natural)
      return CryptoLib.Errors.Status
   is
      Program_Path : GNAT.OS_Lib.String_Access :=
        GNAT.OS_Lib.Locate_Exec_On_Path (Program_Name);
      Process      : GNAT.Expect.Process_Descriptor;
      Status_Value : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Child_Status : Integer := 0;

      procedure Close_Process is
      begin
         GNAT.Expect.Close (Process, Child_Status);
      exception
         when others =>
            null;
      end Close_Process;
   begin
      Summary := (Requested => Requested, others => <>);
      Summary.Request_Bytes := Request'Length;
      if Response'Length = 0 then
         Last := Response'First - 1;
      else
         Last := Response'First - 1;
      end if;

      if Program_Name'Length = 0 or else Program_Path = null then
         if Program_Path /= null then
            GNAT.OS_Lib.Free (Program_Path);
         end if;
         return CryptoLib.Errors.Unsupported_Feature;
      end if;

      GNAT.Expect.Non_Blocking_Spawn
        (Process,
         Program_Path.all,
         Arguments,
         Buffer_Size => 0,
         Err_To_Out  => False);
      GNAT.OS_Lib.Free (Program_Path);

      declare
         Input_FD : constant GNAT.OS_Lib.File_Descriptor :=
           GNAT.Expect.Get_Input_Fd (Process);
         First_Index : Ada.Streams.Stream_Element_Offset := Request'First;
      begin
         while First_Index <= Request'Last loop
            declare
               Ready_Status : constant CryptoLib.Errors.Status :=
                 Wait_For_Process_FD (Input_FD, True, Timeout_MS);
               Remaining : constant Ada.Streams.Stream_Element_Offset :=
                 Request'Last - First_Index + 1;
               Written : Integer;
            begin
               if Ready_Status /= CryptoLib.Errors.Ok then
                  Close_Process;
                  return Ready_Status;
               end if;
               Written :=
                 GNAT.OS_Lib.Write
                   (Input_FD,
                    Request (First_Index)'Address,
                    Integer (Remaining));
               if Written <= 0 then
                  Close_Process;
                  return CryptoLib.Errors.Write_Failed;
               end if;
               First_Index := First_Index
                 + Ada.Streams.Stream_Element_Offset (Written);
            end;
         end loop;
         GNAT.OS_Lib.Close (Input_FD);
      end;

      declare
         Output_FD : constant GNAT.OS_Lib.File_Descriptor :=
           GNAT.Expect.Get_Output_Fd (Process);
         Buffer    : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Read_Buffer_Size));
         Count     : Integer;
      begin
         loop
            Status_Value := Wait_For_Process_FD (Output_FD, False, Timeout_MS);
            if Status_Value /= CryptoLib.Errors.Ok then
               Close_Process;
               return Status_Value;
            end if;

            Count :=
              GNAT.OS_Lib.Read
                (Output_FD, Buffer (Buffer'First)'Address, Buffer'Length);
            exit when Count = 0;
            if Count < 0 then
               Close_Process;
               return CryptoLib.Errors.Read_Failed;
            end if;

            Status_Value :=
              Copy_Response_Chunk
                (Buffer
                   (Buffer'First
                    .. Buffer'First
                      + Ada.Streams.Stream_Element_Offset (Count) - 1),
                 Response,
                 Last,
                 Summary);
            if Status_Value /= CryptoLib.Errors.Ok then
               Close_Process;
               return Status_Value;
            end if;
         end loop;
      end;

      Close_Process;
      Summary.Exit_Code := Child_Status;
      Summary.Remote_Exit_Observed := True;
      if Child_Status /= 0 then
         return CryptoLib.Errors.Remote_Exit_Nonzero;
      elsif Summary.Response_Bytes = 0 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      return Validate_Response
        (Requested, Response (Response'First .. Last), Summary);
   exception
      when GNAT.Expect.Invalid_Process =>
         if Program_Path /= null then
            GNAT.OS_Lib.Free (Program_Path);
         end if;
         Summary := (Requested => Requested, others => <>);
         Last := Response'First - 1;
         return CryptoLib.Errors.Connection_Failed;
      when others =>
         if Program_Path /= null then
            GNAT.OS_Lib.Free (Program_Path);
         end if;
         Summary := (Requested => Requested, others => <>);
         Last := Response'First - 1;
         return CryptoLib.Errors.Internal_Error;
   end Run_Subprocess_Service;

   function Run_Service_With_Local_Git
     (Repository_Path : String;
      Requested       : Service;
      Request         : Ada.Streams.Stream_Element_Array;
      Response        : out Ada.Streams.Stream_Element_Array;
      Last            : out Ada.Streams.Stream_Element_Offset;
      Summary         : out Git_Workflow_Summary;
      Timeout_MS      : Natural := 30_000)
      return CryptoLib.Errors.Status
   is
      Service_Arg : aliased String :=
        (case Requested is
            when Upload_Pack  => "upload-pack",
            when Receive_Pack => "receive-pack");
      Repo_Arg    : aliased String := Repository_Path;
      Args        : constant GNAT.OS_Lib.Argument_List (1 .. 2) :=
        [Service_Arg'Unchecked_Access, Repo_Arg'Unchecked_Access];
   begin
      if Repository_Path'Length = 0 or else Has_Control_Break (Repository_Path) then
         Summary := (Requested => Requested, others => <>);
         Last := Response'First - 1;
         return CryptoLib.Errors.Invalid_Command;
      end if;
      return Run_Subprocess_Service
        ("git", Args, Requested, Request, Response, Last, Summary, Timeout_MS);
   exception
      when others =>
         Summary := (Requested => Requested, others => <>);
         Last := Response'First - 1;
         return CryptoLib.Errors.Internal_Error;
   end Run_Service_With_Local_Git;

   function Run_Service_With_Local_SSH
     (Options    : SSH_Lib.Sessions.Session_Options;
      Command    : String;
      Requested  : Service;
      Request    : Ada.Streams.Stream_Element_Array;
      Response   : out Ada.Streams.Stream_Element_Array;
      Last       : out Ada.Streams.Stream_Element_Offset;
      Summary    : out Git_Workflow_Summary;
      Timeout_MS : Natural := 30_000)
      return CryptoLib.Errors.Status
   is
      Host_Text : constant String := To_String (Options.Host);
      User_Text : constant String := To_String (Options.User);
      Host_Arg  : aliased String :=
        (if User_Text'Length = 0 then Host_Text else User_Text & "@" & Host_Text);
      Command_Arg : aliased String := Command;
   begin
      if Host_Text'Length = 0
        or else Command'Length = 0
        or else Has_Control_Break (Host_Text)
        or else Has_Control_Break (User_Text)
        or else Has_Control_Break (Command)
      then
         Summary := (Requested => Requested, others => <>);
         Last := Response'First - 1;
         return CryptoLib.Errors.Invalid_Command;
      end if;
      declare
         Port_Flag : aliased String := "-p";
         Port_Arg  : aliased String :=
           Ada.Strings.Fixed.Trim (Natural'Image (Options.Port), Ada.Strings.Both);
         Args      : constant GNAT.OS_Lib.Argument_List (1 .. 4) :=
           [Port_Flag'Unchecked_Access,
            Port_Arg'Unchecked_Access,
            Host_Arg'Unchecked_Access,
            Command_Arg'Unchecked_Access];
      begin
         return Run_Subprocess_Service
           ("ssh", Args, Requested, Request, Response, Last, Summary, Timeout_MS);
      end;
   exception
      when others =>
         Summary := (Requested => Requested, others => <>);
         Last := Response'First - 1;
         return CryptoLib.Errors.Internal_Error;
   end Run_Service_With_Local_SSH;
end SSH_Lib.Git_Transport;
