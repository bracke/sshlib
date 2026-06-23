with Ada.Directories;
with Ada.Streams;
with Ada.Text_IO;
with Ada.Strings.Unbounded;
with Interfaces;
with SSH_Lib.Agent;
with SSH_Lib.Agent.Protocol;
with SSH_Lib.Config;
with CryptoLib.Errors;
with SSH_Lib.Identity_Files;
with SSH_Lib.Known_Hosts;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Packets;
with SSH_Lib.Sessions;
with SSH_Lib.SFTP;
with SSH_Lib.Tests.Assertions;
with SSH_Lib.Tests.Fixtures.Known_Hosts;
with SSH_Lib.Tests.Fixtures.Temp_Paths;

package body SSH_Lib.Tests.Fixtures.Fuzz_Lite is

   use type SSH_Lib.Identity_Files.Key_Kind;
   use type SSH_Lib.Known_Hosts.Verification_Result;
   use Ada.Streams;
   use type CryptoLib.Errors.Status;
   use type Interfaces.Unsigned_32;

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

   function With_Length
     (Length_Value : Interfaces.Unsigned_32;
      Payload      : Stream_Element_Array)
      return Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32 (Length_Value) & Payload;
   end With_Length;

   procedure Expect_Not_Ok
     (Actual_Status : CryptoLib.Errors.Status;
      Label_Text    : String)
   is
   begin
      if Actual_Status = CryptoLib.Errors.Ok then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text & " unexpectedly returned Ok");
         raise Program_Error;
      end if;
   end Expect_Not_Ok;

   procedure Check_Packet_Framing_Fuzz is
      State_Item : SSH_Lib.Protocol.Packets.Protocol_State;
      Payload_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
      Truncated_Header : constant Stream_Element_Array (1 .. 3) :=
        [1 => 0, 2 => 0, 3 => 0];
      Too_Small_Packet : constant Stream_Element_Array (1 .. 8) :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
        & Stream_Element_Array'[1 => 0, 2 => 0, 3 => 0, 4 => 0];
      Non_Block_Multiple : constant Stream_Element_Array (1 .. 9) :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32 (5)
        & Stream_Element_Array'[1 => 4, 2 => 0, 3 => 0, 4 => 0, 5 => 0];
      Extra_Trailing : constant Stream_Element_Array (1 .. 16) :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32 (11)
        & Stream_Element_Array'
            [1 => 4, 2 => 16#00#, 3 => 16#0A#, 4 => 16#0D#,
             5 => 16#7F#, 6 => 16#80#, 7 => 16#FF#,
             8 => 16#AA#, 9 => 16#AA#, 10 => 16#AA#, 11 => 16#AA#]
        & Stream_Element_Array'[1 => 16#EE#];
   begin
      SSH_Lib.Protocol.Packets.Reset (State_Item);
      Status_Value := SSH_Lib.Protocol.Packets.Decode_Cleartext_Packet
        (State_Item, Truncated_Header, Payload_Buffer);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.End_Of_Stream,
         "fuzz-lite packet framing", "truncated packet header is deterministic");

      SSH_Lib.Protocol.Packets.Reset (State_Item);
      Status_Value := SSH_Lib.Protocol.Packets.Decode_Cleartext_Packet
        (State_Item, Too_Small_Packet, Payload_Buffer);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "fuzz-lite packet framing", "too-small packet length is rejected");

      SSH_Lib.Protocol.Packets.Reset (State_Item);
      Status_Value := SSH_Lib.Protocol.Packets.Decode_Cleartext_Packet
        (State_Item, Non_Block_Multiple, Payload_Buffer);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "fuzz-lite packet framing", "non-block-multiple packet length is rejected");

      SSH_Lib.Protocol.Packets.Reset (State_Item);
      Status_Value := SSH_Lib.Protocol.Packets.Decode_Cleartext_Packet
        (State_Item, Extra_Trailing, Payload_Buffer);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "fuzz-lite packet framing", "packet with trailing bytes is rejected");
   end Check_Packet_Framing_Fuzz;

   procedure Check_SSH_String_Fuzz is
      Payload_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Next_Index : Stream_Element_Offset;
      Value_Text : Ada.Strings.Unbounded.Unbounded_String;
      Status_Value : CryptoLib.Errors.Status;
      Truncated_Length : constant Stream_Element_Array (1 .. 2) := [1 => 0, 2 => 1];
      Length_Too_Long : constant Stream_Element_Array (1 .. 7) :=
        With_Length (5, Stream_Element_Array'[1 => 16#61#, 2 => 16#62#, 3 => 16#63#]);
      High_Bit_Name : constant Stream_Element_Array (1 .. 5) :=
        With_Length (1, Stream_Element_Array'[1 => 16#80#]);
      Empty_String : constant Stream_Element_Array (1 .. 4) :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32 (0);
   begin
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Truncated_Length, Truncated_Length'First, Payload_Buffer, Next_Index);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "fuzz-lite SSH string", "truncated SSH string length is rejected");

      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Length_Too_Long, Length_Too_Long'First, Payload_Buffer, Next_Index);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "fuzz-lite SSH string", "SSH string length past buffer is rejected");

      Status_Value := SSH_Lib.Protocol.Numbers.Decode_Name_List
        (High_Bit_Name, High_Bit_Name'First, Value_Text, Next_Index);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "fuzz-lite SSH string", "name-list high-bit byte is rejected");

      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Empty_String, Empty_String'First, Payload_Buffer, Next_Index);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "fuzz-lite SSH string", "empty SSH string remains valid edge case");
      Check (SSH_Lib.Protocol.Buffers.Length (Payload_Buffer) = 0,
             "empty SSH string yields empty payload");
   end Check_SSH_String_Fuzz;

   function Text_Bytes (Text : String) return Stream_Element_Array is
      Result : Stream_Element_Array
        (1 .. Stream_Element_Offset (Text'Length));
      Cursor : Stream_Element_Offset := Result'First;
   begin
      for Ch of Text loop
         Result (Cursor) := Stream_Element (Character'Pos (Ch));
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end Text_Bytes;

   function SFTP_String (Text : String) return Stream_Element_Array is
   begin
      return With_Length
        (Interfaces.Unsigned_32 (Text'Length), Text_Bytes (Text));
   end SFTP_String;

   function SFTP_Bytes (Data : Stream_Element_Array) return Stream_Element_Array is
   begin
      return With_Length (Interfaces.Unsigned_32 (Data'Length), Data);
   end SFTP_Bytes;

   procedure Set_Buffer
     (Buffer : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Data   : Stream_Element_Array;
      Label  : String)
   is
      Status_Value : constant CryptoLib.Errors.Status :=
        SSH_Lib.Protocol.Buffers.Set (Buffer, Data);
   begin
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok, "fuzz-lite SFTP", Label);
   end Set_Buffer;

   function SFTP_Version_Packet
     (Version : Interfaces.Unsigned_32;
      Extra   : Stream_Element_Array)
      return Stream_Element_Array
   is
      Payload : constant Stream_Element_Array :=
        Stream_Element_Array'[1 => SSH_Lib.SFTP.SSH_FXP_VERSION]
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Version)
        & Extra;
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
        (Interfaces.Unsigned_32 (Payload'Length)) & Payload;
   end SFTP_Version_Packet;

   function SFTP_Field
     (Length_Value : Interfaces.Unsigned_32;
      Data         : Stream_Element_Array)
      return Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32 (Length_Value) & Data;
   end SFTP_Field;

   function SFTP_Version_Packet
     (Version : Interfaces.Unsigned_32) return Stream_Element_Array
   is
      Payload : constant Stream_Element_Array :=
        Stream_Element_Array'[1 => SSH_Lib.SFTP.SSH_FXP_VERSION]
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (Version);
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32
        (Interfaces.Unsigned_32 (Payload'Length)) & Payload;
   end SFTP_Version_Packet;

   procedure Check_SFTP_Parser_Fuzz is
      Buffer       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Extensions   : SSH_Lib.SFTP.Extension_Info;
      Version      : Natural := 99;
      Status_Value : CryptoLib.Errors.Status;
      Supported2   : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_0005#)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_0004#)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_0003#)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (16#0000_0002#)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (4096)
        & Stream_Element_Array'[1 => 0, 2 => 1, 3 => 0, 4 => 2]
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (0)
        & SSH_Lib.Protocol.Numbers.Encode_Uint32 (1)
        & SFTP_String (SSH_Lib.SFTP.Text_Seek_Extension);
      Version_Extensions : constant Stream_Element_Array :=
        SFTP_String (SSH_Lib.SFTP.Versions_Extension)
        & SFTP_String ("3,4,5,6")
        & SFTP_String (SSH_Lib.SFTP.Supported2_Extension)
        & SFTP_Bytes (Supported2)
        & SFTP_String (SSH_Lib.SFTP.Check_File_Extension)
        & SFTP_String ("");
      Unknown_Extension : constant Stream_Element_Array :=
        SFTP_String ("vendor@example.test")
        & SFTP_String ("opaque")
        & SFTP_String (SSH_Lib.SFTP.Fsync_Extension)
        & SFTP_String ("");
      Empty_Name_Extension : constant Stream_Element_Array :=
        SFTP_Field (0, Stream_Element_Array'(1 .. 0 => 0)) & SFTP_String ("value");
      Truncated_Value_Extension : constant Stream_Element_Array :=
        SFTP_String (SSH_Lib.SFTP.Versions_Extension)
        & SFTP_Field
            (Interfaces.Unsigned_32'(4),
             Stream_Element_Array'[1 => Character'Pos ('3'),
                                   2 => Character'Pos (',')]);
      Truncated_Supported2 : constant Stream_Element_Array :=
        SFTP_String (SSH_Lib.SFTP.Supported2_Extension)
        & SFTP_Bytes
            (SSH_Lib.Protocol.Numbers.Encode_Uint32
               (Interfaces.Unsigned_32'(16#0000_0005#)));
   begin
      Set_Buffer
        (Buffer, Stream_Element_Array'[1 => 0, 2 => 0, 3 => 0],
         "queue truncated version packet");
      Status_Value := SSH_Lib.SFTP.Parse_Version_Packet
        (Buffer, Version, Extensions);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Read_Failed,
         "fuzz-lite SFTP", "truncated version packet is rejected");
      Check (Version = 0, "truncated SFTP version clears version");

      Set_Buffer
        (Buffer, SFTP_Version_Packet (Interfaces.Unsigned_32'(7)),
         "queue unsupported version packet");
      Status_Value := SSH_Lib.SFTP.Parse_Version_Packet
        (Buffer, Version, Extensions);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "fuzz-lite SFTP", "unsupported SFTP version is rejected");
      Check (Version = 7, "unsupported SFTP version is still reported");

      Set_Buffer
        (Buffer,
         SSH_Lib.Protocol.Numbers.Encode_Uint32 (6)
         & Stream_Element_Array'[1 => SSH_Lib.SFTP.SSH_FXP_VERSION]
         & SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32'(3)),
         "queue mismatched version length packet");
      Status_Value := SSH_Lib.SFTP.Parse_Version_Packet
        (Buffer, Version, Extensions);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Read_Failed,
         "fuzz-lite SFTP", "mismatched packet length is rejected");

      Set_Buffer
        (Buffer, SFTP_Version_Packet (Interfaces.Unsigned_32'(6), Version_Extensions),
         "queue typed version extensions packet");
      Status_Value := SSH_Lib.SFTP.Parse_Version_Packet
        (Buffer, Version, Extensions);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "fuzz-lite SFTP", "typed version extensions parse");
      Check
        (Version = 6
         and then Extensions.Versions
         and then Extensions.Version_4
         and then Extensions.Version_5
         and then Extensions.Version_6
         and then Extensions.Supported2
         and then Extensions.Check_File
         and then Extensions.Text_Seek
         and then Extensions.Capabilities.Present
         and then Extensions.Capabilities.Max_Read_Size = Interfaces.Unsigned_32'(4096),
         "typed SFTP version and supported2 extension data is retained");

      Set_Buffer
        (Buffer, SFTP_Version_Packet (Interfaces.Unsigned_32'(3), Unknown_Extension),
         "queue unknown extension plus known extension packet");
      Status_Value := SSH_Lib.SFTP.Parse_Version_Packet
        (Buffer, Version, Extensions);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "fuzz-lite SFTP", "unknown extension is skipped");
      Check
        (Version = 3
         and then Extensions.Fsync
         and then not Extensions.StatVFS,
         "unknown SFTP extension does not poison known extension parsing");

      Set_Buffer
        (Buffer, SFTP_Version_Packet
           (Interfaces.Unsigned_32'(3), Empty_Name_Extension),
         "queue empty extension name packet");
      Status_Value := SSH_Lib.SFTP.Parse_Version_Packet
        (Buffer, Version, Extensions);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Read_Failed,
         "fuzz-lite SFTP", "empty extension name is rejected");

      Set_Buffer
        (Buffer, SFTP_Version_Packet
           (Interfaces.Unsigned_32'(3), Truncated_Value_Extension),
         "queue truncated extension value packet");
      Status_Value := SSH_Lib.SFTP.Parse_Version_Packet
        (Buffer, Version, Extensions);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Read_Failed,
         "fuzz-lite SFTP", "truncated extension value is rejected");

      Set_Buffer
        (Buffer, SFTP_Version_Packet
           (Interfaces.Unsigned_32'(6), Truncated_Supported2),
         "queue truncated supported2 extension packet");
      Status_Value := SSH_Lib.SFTP.Parse_Version_Packet
        (Buffer, Version, Extensions);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "fuzz-lite SFTP", "truncated supported2 value is tolerated");
      Check
        (Extensions.Supported2
         and then not Extensions.Capabilities.Present,
         "truncated supported2 leaves capabilities absent");
   end Check_SFTP_Parser_Fuzz;

   procedure Check_Agent_Framing_Fuzz is
      Identities : SSH_Lib.Agent.Identity_List;
      Signature_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Payload_Length : Natural := 99;
      Status_Value : CryptoLib.Errors.Status;
      Short_Header : constant Stream_Element_Array (1 .. 3) := [1 => 0, 2 => 0, 3 => 1];
      Huge_Header : constant Stream_Element_Array (1 .. 4) :=
        SSH_Lib.Protocol.Numbers.Encode_Uint32
          (Interfaces.Unsigned_32 (SSH_Lib.Agent.Max_Agent_Message_Size + 1));
      Unknown_Message : constant Stream_Element_Array (1 .. 1) := [1 => 99];
      Truncated_Count : constant Stream_Element_Array (1 .. 3) :=
        [1 => SSH_Lib.Agent.Protocol.SSH_AGENT_IDENTITIES_ANSWER,
         2 => 0,
         3 => 0];
      Trailing_Identity_Bytes : constant Stream_Element_Array (1 .. 6) :=
        [1 => SSH_Lib.Agent.Protocol.SSH_AGENT_IDENTITIES_ANSWER,
         2 => 0, 3 => 0, 4 => 0, 5 => 0,
         6 => 16#FF#];
      Sign_Response_No_String : constant Stream_Element_Array (1 .. 1) :=
        [1 => SSH_Lib.Agent.Protocol.SSH_AGENT_SIGN_RESPONSE];
   begin
      Status_Value := SSH_Lib.Agent.Protocol.Decode_Message_Length
        (Short_Header, Payload_Length);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "fuzz-lite agent framing", "short agent message header is rejected");
      Check (Payload_Length = 0,
             "short agent message header clears decoded length");

      Status_Value := SSH_Lib.Agent.Protocol.Decode_Message_Length
        (Huge_Header, Payload_Length);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "fuzz-lite agent framing", "huge agent message header is rejected");
      Check (Payload_Length = 0,
             "huge agent message header clears decoded length");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Identities_Answer
        (Unknown_Message, Identities);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "fuzz-lite agent framing", "unknown agent identities message type is rejected");
      Check (SSH_Lib.Agent.Count (Identities) = 0,
             "unknown identities message leaves no identities");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Identities_Answer
        (Truncated_Count, Identities);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "fuzz-lite agent framing", "truncated agent identity count is rejected");
      Check (SSH_Lib.Agent.Count (Identities) = 0,
             "truncated identity count leaves no identities");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Identities_Answer
        (Trailing_Identity_Bytes, Identities);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "fuzz-lite agent framing", "trailing bytes after agent identities are rejected");
      Check (SSH_Lib.Agent.Count (Identities) = 0,
             "trailing identity bytes leave no identities");

      Status_Value := SSH_Lib.Agent.Protocol.Parse_Sign_Response
        (Sign_Response_No_String, Signature_Buffer);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Authentication_Failed,
         "fuzz-lite agent framing", "truncated agent sign response is rejected");
      Check (SSH_Lib.Protocol.Buffers.Is_Empty (Signature_Buffer),
             "truncated agent sign response leaves empty signature");
   end Check_Agent_Framing_Fuzz;

   procedure Check_Known_Hosts_Fuzz is
      Path : constant String := SSH_Lib.Tests.Fixtures.Temp_Paths.Path
        ("phase19_fuzz_known_hosts");
      Presented_Key : constant SSH_Lib.Known_Hosts.Host_Key :=
        SSH_Lib.Tests.Fixtures.Known_Hosts.Fixture_Host_Key;
      Result_Value : SSH_Lib.Known_Hosts.Verification_Result;
   begin
      Write_Text_File
        (Path,
         "" & Character'Val (10)
         & "# comment" & Character'Val (10)
         & "example.com" & Character'Val (10)
         & "example.com ssh-ed25519 not-base64!!!" & Character'Val (10)
         & "|1|hashed|entry ssh-ed25519 AAAA" & Character'Val (10)
         & "*.example.com ssh-ed25519 AAAA" & Character'Val (10)
         & "!example.com ssh-ed25519 AAAA" & Character'Val (10)
         & "[example.com]:2222 ssh-ed25519 AAAA" & Character'Val (10));
      Result_Value := SSH_Lib.Known_Hosts.Verify
        (Path, "example.com", 22, Presented_Key);
      Check
        (Result_Value = SSH_Lib.Known_Hosts.Unknown
         or else Result_Value = SSH_Lib.Known_Hosts.Unsupported_Entry,
         "fuzz-lite known_hosts malformed records are not trusted");
      Remove_If_Exists (Path);
   end Check_Known_Hosts_Fuzz;

   procedure Check_Config_Fuzz is
      Path : constant String := SSH_Lib.Tests.Fixtures.Temp_Paths.Path
        ("phase19_fuzz_config");
      Config_Item : SSH_Lib.Config.Host_Config;
      Options : SSH_Lib.Sessions.Session_Options;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Write_Text_File
        (Path,
         Character'Val (0) & Character'Val (10)
         & "Host" & Character'Val (10)
         & "Host target" & Character'Val (10)
         & "  Port not-a-number" & Character'Val (10)
         & "  IdentityFile `not-executed`" & Character'Val (10)
         & "  ProxyCommand ignored" & Character'Val (10)
         & "Host target" & Character'Val (10)
         & "  HostName safe.example" & Character'Val (10)
         & "  User git" & Character'Val (10));
      Status_Value := SSH_Lib.Config.Load (Path, Config_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "fuzz-lite config", "malformed config lines are parsed deterministically");
      Status_Value := SSH_Lib.Config.Resolve (Config_Item, "target", "git", Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Invalid_Port,
         "fuzz-lite config", "malformed port still fails before ProxyCommand use");
      Check (Options.Verify_Known_Host and then Options.Strict_Host_Key,
             "fuzz-lite config cannot disable host-key security defaults");
      Remove_If_Exists (Path);
   end Check_Config_Fuzz;

   procedure Check_Identity_File_Fuzz is
      Identity_Item : SSH_Lib.Identity_Files.Identity_Key;
      Status_Value : CryptoLib.Errors.Status;

      procedure Check_Malformed_Identity (Case_Text : String) is
      begin
         Status_Value := SSH_Lib.Identity_Files.Parse (Case_Text, Identity_Item);
         Expect_Not_Ok
           (Status_Value,
            "fuzz-lite identity-file section framing rejects malformed key");
         Check
           (SSH_Lib.Identity_Files.Kind (Identity_Item) = SSH_Lib.Identity_Files.No_Key,
            "fuzz-lite identity-file malformed key leaves no loaded key");
      end Check_Malformed_Identity;
   begin
      Check_Malformed_Identity ("");
      Check_Malformed_Identity
        ("-----BEGIN OPENSSH PRIVATE KEY-----" & Character'Val (10));
      Check_Malformed_Identity
        ("-----BEGIN OPENSSH PRIVATE KEY-----" & Character'Val (10)
         & "!!!!" & Character'Val (10)
         & "-----END OPENSSH PRIVATE KEY-----" & Character'Val (10));
      Check_Malformed_Identity
        ("-----BEGIN RSA PRIVATE KEY-----" & Character'Val (10)
         & "AAAA" & Character'Val (10)
         & "-----END RSA PRIVATE KEY-----" & Character'Val (10));
   end Check_Identity_File_Fuzz;

   procedure Assert_Deterministic_Malformed_Input_Sweep is
   begin
      Check_Packet_Framing_Fuzz;
      Check_SSH_String_Fuzz;
      Check_Agent_Framing_Fuzz;
      Check_SFTP_Parser_Fuzz;
      Check_Known_Hosts_Fuzz;
      Check_Config_Fuzz;
      Check_Identity_File_Fuzz;
   end Assert_Deterministic_Malformed_Input_Sweep;
end SSH_Lib.Tests.Fixtures.Fuzz_Lite;
