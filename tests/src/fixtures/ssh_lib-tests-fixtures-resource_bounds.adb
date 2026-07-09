with Ada.Directories;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Interfaces;
with SSH_Lib.Agent;
with SSH_Lib.Agent.Protocol;
with SSH_Lib.Channels;
with SSH_Lib.Channels.Test_Support;
with SSH_Lib.Config;
with CryptoLib.Errors;
with SSH_Lib.Git;
with SSH_Lib.Identity_Files;
with SSH_Lib.Known_Hosts;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Channels;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Packets;
with SSH_Lib.Sessions;
with SSH_Lib.Sessions.Channel_Table;
with SSH_Lib.Sessions.Test_Support;
with SSH_Lib.Tests.Assertions;
with SSH_Lib.Tests.Fixtures.Known_Hosts;
with SSH_Lib.Tests.Fixtures.Temp_Paths;

package body SSH_Lib.Tests.Fixtures.Resource_Bounds is
   use type SSH_Lib.Identity_Files.Key_Kind;
   use type SSH_Lib.Known_Hosts.Verification_Result;
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   procedure Remove_If_Exists (Path : String) is
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;
   exception
      when others =>
         null;
   end Remove_If_Exists;

   procedure Write_Text_File (Path : String; Text : String) is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Remove_If_Exists (Path);
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put (Output_File, Text);
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Text_File;

   procedure Write_Binary_File (Path : String; Size_Value : Natural) is
      Output_File : Ada.Streams.Stream_IO.File_Type;
      Chunk_Data  : constant Stream_Element_Array (1 .. 4096) := [others => 16#41#];
      Remaining   : Natural := Size_Value;
   begin
      Remove_If_Exists (Path);
      Ada.Streams.Stream_IO.Create (Output_File, Ada.Streams.Stream_IO.Out_File, Path);
      while Remaining > 0 loop
         declare
            Count_Value : constant Natural := Natural'Min (Remaining, Chunk_Data'Length);
         begin
            Ada.Streams.Stream_IO.Write
              (Output_File,
               Chunk_Data (1 .. Stream_Element_Offset (Count_Value)));
            Remaining := Remaining - Count_Value;
         end;
      end loop;
      Ada.Streams.Stream_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Streams.Stream_IO.Is_Open (Output_File) then
            Ada.Streams.Stream_IO.Close (Output_File);
         end if;
         raise;
   end Write_Binary_File;

   function Repeated (Value : Character; Count_Value : Natural) return String is
      Result : String (1 .. Count_Value);
   begin
      Result := [others => Value];
      return Result;
   end Repeated;

   procedure Check_Packet_Length_Bounds is
      State_Item : SSH_Lib.Protocol.Packets.Protocol_State;
      Payload_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Oversized_Header : constant Stream_Element_Array (1 .. 4) :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32
             (SSH_Lib.Protocol.Packets.Maximum_Packet_Length + 1));
      Result_Status : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Packets.Reset (State_Item);
      Result_Status := SSH_Lib.Protocol.Packets.Decode_Cleartext_Packet
        (State_Item, Oversized_Header, Payload_Buffer);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Handshake_Failed,
         "resource bound", "oversized SSH packet header rejected before allocation");
   end Check_Packet_Length_Bounds;

   procedure Check_Packet_Buffer_Bounds is
      Buffer_Item : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Max_Data : constant Stream_Element_Array
        (1 .. Stream_Element_Offset (SSH_Lib.Protocol.Buffers.Max_Packet_Length)) :=
        [others => 16#55#];
      Extra_Data : constant Stream_Element_Array (1 .. 1) := [1 => 16#AA#];
      Result_Status : CryptoLib.Errors.Status;
   begin
      Result_Status := SSH_Lib.Protocol.Buffers.Set (Buffer_Item, Max_Data);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Ok,
         "resource bound", "packet buffer accepts exact configured maximum");
      Result_Status := SSH_Lib.Protocol.Buffers.Append (Buffer_Item, Extra_Data);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Internal_Error,
         "resource bound", "packet buffer rejects growth beyond maximum");
   end Check_Packet_Buffer_Bounds;

   procedure Check_Agent_Bounds is
      Header_Data : constant Stream_Element_Array (1 .. 4) :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (SSH_Lib.Agent.Max_Agent_Message_Size + 1));
      Payload_Length : Natural := 0;
      Identities : SSH_Lib.Agent.Identity_List;
      Too_Many_Identities : constant Stream_Element_Array (1 .. 5) :=
        [1 => SSH_Lib.Agent.Protocol.SSH_AGENT_IDENTITIES_ANSWER,
         2 .. 5 => 0];
      Count_Data : constant Stream_Element_Array (1 .. 4) :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (SSH_Lib.Agent.Max_Identities + 1));
      Identity_Payload : Stream_Element_Array (1 .. 5) := Too_Many_Identities;
      Result_Status : CryptoLib.Errors.Status;
   begin
      Result_Status := SSH_Lib.Agent.Protocol.Decode_Message_Length
        (Header_Data, Payload_Length);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Authentication_Failed,
         "resource bound", "oversized agent message length rejected");
      Check (Payload_Length = 0, "oversized agent message does not expose length");

      Identity_Payload (2 .. 5) := Count_Data;
      Result_Status := SSH_Lib.Agent.Protocol.Parse_Identities_Answer
        (Identity_Payload, Identities);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Authentication_Failed,
         "resource bound", "too many agent identities rejected");
      Check
        (SSH_Lib.Agent.Count (Identities) = 0,
         "rejected agent identity list leaves no decoded identities");
   end Check_Agent_Bounds;

   procedure Check_Identity_File_Bound is
      Path : constant String := SSH_Lib.Tests.Fixtures.Temp_Paths.Path
        ("phase19_oversized_identity_key");
      Identity_Item : SSH_Lib.Identity_Files.Identity_Key;
      Result_Status : CryptoLib.Errors.Status;
   begin
      Write_Binary_File (Path, SSH_Lib.Identity_Files.Max_Identity_File_Size + 1);
      Result_Status := SSH_Lib.Identity_Files.Load (Path, Identity_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Authentication_Failed,
         "resource bound", "oversized identity file rejected before parsing");
      Check
        (SSH_Lib.Identity_Files.Kind (Identity_Item) = SSH_Lib.Identity_Files.No_Key,
         "rejected oversized identity file leaves key empty");
      Remove_If_Exists (Path);
   end Check_Identity_File_Bound;

   procedure Check_Config_Line_Bound is
      Path : constant String := SSH_Lib.Tests.Fixtures.Temp_Paths.Path
        ("phase19_oversized_config_line");
      Config_Item : SSH_Lib.Config.Host_Config;
      Options : SSH_Lib.Sessions.Session_Options;
      Result_Status : CryptoLib.Errors.Status;
   begin
      Write_Text_File
        (Path,
         "Host example" & Character'Val (10)
         & "  HostName " & Repeated ('a', 20_000) & Character'Val (10)
         & "Host other" & Character'Val (10)
         & "  HostName safe.example" & Character'Val (10));

      Result_Status := SSH_Lib.Config.Load (Path, Config_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Ok,
         "resource bound", "oversized config line ignored safely");
      Result_Status := SSH_Lib.Config.Resolve (Config_Item, "example", "git", Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Ok,
         "resource bound", "config with oversized line remains resolvable");
      Check
        (To_String (Options.Host) = "example",
         "oversized HostName line cannot install unbounded resolved host");
      Remove_If_Exists (Path);
   end Check_Config_Line_Bound;

   procedure Check_Known_Hosts_Line_Bound is
      Path : constant String := SSH_Lib.Tests.Fixtures.Temp_Paths.Path
        ("phase19_oversized_known_hosts_line");
      Result_Value : SSH_Lib.Known_Hosts.Verification_Result;
      Presented_Key : constant SSH_Lib.Known_Hosts.Host_Key :=
        SSH_Lib.Tests.Fixtures.Known_Hosts.Fixture_Host_Key;
   begin
      Write_Text_File
        (Path,
         "example.com "
         & SSH_Lib.Known_Hosts.Algorithm (Presented_Key)
         & " "
         & SSH_Lib.Known_Hosts.Encoded (Presented_Key)
         & " " & Repeated ('x', 20_000) & Character'Val (10));
      Result_Value := SSH_Lib.Known_Hosts.Verify
        (Path, "example.com", 22, Presented_Key);
      Check
        (Result_Value = SSH_Lib.Known_Hosts.Unsupported_Entry,
         "oversized known_hosts line is ignored, not trusted before any later trust can mask it");
      Remove_If_Exists (Path);
   end Check_Known_Hosts_Line_Bound;

   procedure Check_Channel_Buffer_Bounds is
      Channel_Item : SSH_Lib.Channels.Channel;
      Max_Data : constant Stream_Element_Array
        (1 .. Stream_Element_Offset (SSH_Lib.Protocol.Buffers.Max_Packet_Length)) :=
        [others => 16#42#];
      Extra_Data : constant Stream_Element_Array (1 .. 1) := [1 => 16#43#];
      Result_Status : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test (Channel_Item);
      Result_Status := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
        (Channel_Item, Max_Data);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Ok,
         "resource bound", "pending stdout accepts exact maximum");
      Result_Status := SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
        (Channel_Item, Extra_Data);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Internal_Error,
         "resource bound", "pending stdout rejects unbounded growth");

      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test (Channel_Item);
      Result_Status := SSH_Lib.Channels.Test_Support.Queue_Stderr_For_Test
        (Channel_Item, Max_Data);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Ok,
         "resource bound", "pending stderr accepts exact maximum");
      Result_Status := SSH_Lib.Channels.Test_Support.Queue_Stderr_For_Test
        (Channel_Item, Extra_Data);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Internal_Error,
         "resource bound", "pending stderr rejects unbounded growth");
   end Check_Channel_Buffer_Bounds;

   procedure Check_Channel_Count_Bound is
      Session_Item : SSH_Lib.Sessions.Session;
      First_Channel : Interfaces.Unsigned_32;
      Second_Channel : Interfaces.Unsigned_32;
      Result_Status : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
      SSH_Lib.Sessions.Test_Support.Set_Channel_Limit_For_Test (Session_Item, 1);
      Result_Status := SSH_Lib.Sessions.Channel_Table.Allocate
        (Session_Item, First_Channel);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Ok,
         "resource bound", "first channel allocation within limit succeeds");
      Result_Status := SSH_Lib.Sessions.Channel_Table.Allocate
        (Session_Item, Second_Channel);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Channel_Open_Failed,
         "resource bound", "too many open channels rejected");
      Check
        (SSH_Lib.Sessions.Test_Support.Active_Channel_Count_For_Test (Session_Item) = 1,
         "failed extra channel allocation does not grow active count");
   end Check_Channel_Count_Bound;

   procedure Check_Command_And_Repo_Bounds is
      Oversized_Command : constant String :=
        Repeated ('c', SSH_Lib.Protocol.Channels.Maximum_Command_Length + 1);
      Oversized_Repo : constant String :=
        Repeated ('r', SSH_Lib.Git.Maximum_Repository_Path_Length + 1);
      Command_Text : Unbounded_String;
      Result_Status : CryptoLib.Errors.Status;
   begin
      Check
        (not SSH_Lib.Protocol.Channels.Valid_Command (Oversized_Command),
         "oversized exec command rejected by production command validator");
      Result_Status := SSH_Lib.Git.Build_Upload_Pack_Command
        (Oversized_Repo, Command_Text);
      SSH_Lib.Tests.Assertions.Check_Status
        (Result_Status, CryptoLib.Errors.Invalid_Command,
         "resource bound", "oversized Git repository path rejected");
      Check (Length (Command_Text) = 0, "oversized repo path does not build command");
   end Check_Command_And_Repo_Bounds;

   procedure Assert_All_Production_Bounds_Reject_Oversized_Input is
   begin
      Check_Packet_Length_Bounds;
      Check_Packet_Buffer_Bounds;
      Check_Agent_Bounds;
      Check_Identity_File_Bound;
      Check_Config_Line_Bound;
      Check_Known_Hosts_Line_Bound;
      Check_Channel_Buffer_Bounds;
      Check_Channel_Count_Bound;
      Check_Command_And_Repo_Bounds;
   end Assert_All_Production_Bounds_Reject_Oversized_Input;
end SSH_Lib.Tests.Fixtures.Resource_Bounds;
