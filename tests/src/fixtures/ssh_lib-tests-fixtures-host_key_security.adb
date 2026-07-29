with Ada.Directories;
with Ada.Text_IO;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Known_Hosts;
with SSH_Lib.Keys;
with SSH_Lib.Keys.Internal;
with SSH_Lib.Protocol.Authentication_Guards;
with SSH_Lib.Protocol.Host_Key_Guards;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Certificates;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Tests.Assertions;
with SSH_Lib.Tests.Fixtures.Keys;
with SSH_Lib.Tests.Fixtures.Known_Hosts;
with SSH_Lib.Tests.Fixtures.Temp_Paths;

package body SSH_Lib.Tests.Fixtures.Host_Key_Security is

   use type Ada.Streams.Stream_Element_Offset;
   use type SSH_Lib.Known_Hosts.Verification_Result;
   use type CryptoLib.Errors.Status;
   use type Interfaces.Unsigned_64;

   Test_CA_Host_Key_Algorithm : constant String :=
     "ssh-rsa";
   Test_CA_Host_Key_Blob : constant String :=
     "AAAAB3NzaC1yc2EAAAADAQABAAAAgQDcrp5Q+V08jF7wLru0LLEl19/qfSWV9Nr9h4YDyrH18OXFV2"
       & "GvARrg2eEkhgVuUvjgQqKu7CVE/JmLHRoakAOC8bQp84ZgCYM5Rd+c0GrTgvG38Cj6wD7VV/qgwvNd"
       & "A9WfcDKyZw53Vwsk+qJR8wQN2nQOXp9NXCqyoVq32+t/BQ==";
   Test_Certified_Host_Key_Blob : constant String :=
     "AAAAC3NzaC1lZDI1NTE5AAAAIJShID26hbIwzKeckFXVUGzAvIJENpRQhSq7TRWAJo4u";
   Test_Host_Certificate_Algorithm : constant String :=
     "ssh-ed25519-cert-v01@openssh.com";
   Test_Host_Certificate_Blob : constant String :=
     "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIM5t90pNp8gZkBV0EJOddJnYDm"
       & "ycW65HOXKlkyc0d9jMAAAAIJShID26hbIwzKeckFXVUGzAvIJENpRQhSq7TRWAJo4uAAAAAAAAAAAA"
       & "AAACAAAAGGFkYS1zc2gtaG9zdC1jZXJ0LXJzYS1jYQAAACwAAAARY2VydC5leGFtcGxlLnRlc3QAAA"
       & "ATKi5jZXJ0LmV4YW1wbGUudGVzdAAAAABndHdwAAAAAHpDHXAAAAAAAAAAAAAAAAAAAACXAAAAB3Nz"
       & "aC1yc2EAAAADAQABAAAAgQDcrp5Q+V08jF7wLru0LLEl19/qfSWV9Nr9h4YDyrH18OXFV2GvARrg2e"
       & "EkhgVuUvjgQqKu7CVE/JmLHRoakAOC8bQp84ZgCYM5Rd+c0GrTgvG38Cj6wD7VV/qgwvNdA9WfcDKy"
       & "Zw53Vwsk+qJR8wQN2nQOXp9NXCqyoVq32+t/BQAAAJQAAAAMcnNhLXNoYTItNTEyAAAAgLBdMAqqyf"
       & "HwSmY3PGKWqZFMIWioTwUuXopwaClaTC/pLNSynhNQ9Q0iunAxDietd7lWoSBMzxmi/CAnHjtZ4V5W"
       & "xnVvQDfJDedkekCr4/2uo86//jKg9yUXXZOKryWHCTLDXdC5ADXRedlOvvAOwBrXmMQWYrYmUwwZK4"
       & "GrvEef";

   Test_Ed25519_CA_Host_Key_Algorithm : constant String :=
     "ssh-ed25519";
   Test_Ed25519_CA_Host_Key_Blob : constant String :=
     "AAAAC3NzaC1lZDI1NTE5AAAAIOop/LfsdNibh+M36Gk6WEyDQpTaEDs+/s10/l24ELFV";
   Test_Ed25519_CA_Host_Certificate_Blob : constant String :=
     "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIDcNl9b+dnRVV3J97E9J/H+9cN"
       & "4XG7cV1v9JZyziyXizAAAAIFJQVGTsfjZWMAYGSAZIdDkvywO3nH61jmvB5fx37a48AAAAAAAAAAAA"
       & "AAACAAAAF2FkYS1zc2gtaG9zdC1jZXJ0LWVkLWNhAAAAGAAAABRlZC5jZXJ0LmV4YW1wbGUudGVzdA"
       & "AAAABndHdwAAAAAHpDHXAAAAAAAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIOop/LfsdNib"
       & "h+M36Gk6WEyDQpTaEDs+/s10/l24ELFVAAAAUwAAAAtzc2gtZWQyNTUxOQAAAECk2xqjUXK4mzl7H2"
       & "T4qcE1Z0MJ+HbS4nEKCJBWYjTDE7dJ7niLGHCFE9x68J4/XrBWg4lxDB8JXqxL2wc/xXUL";

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   function Bytes (Value : String) return Ada.Streams.Stream_Element_Array is
      Result : Ada.Streams.Stream_Element_Array
        (Ada.Streams.Stream_Element_Offset (1) ..
         Ada.Streams.Stream_Element_Offset (Value'Length));
      Index_Value : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      for Character_Value of Value loop
         Result (Index_Value) := Ada.Streams.Stream_Element
           (Character'Pos (Character_Value));
         Index_Value := Index_Value + 1;
      end loop;
      return Result;
   end Bytes;

   function Critical_Option
     (Name_Text : String;
      Data      : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array
   is
      Buffer_Item : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Buffer_Item,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Bytes (Name_Text))));
      Check (Status_Value = CryptoLib.Errors.Ok,
             "certificate critical option name encoded");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Buffer_Item,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Data)));
      Check (Status_Value = CryptoLib.Errors.Ok,
             "certificate critical option data encoded");
      return SSH_Lib.Protocol.Buffers.To_Array (Buffer_Item);
   end Critical_Option;

   function Critical_Option_With_Text
     (Name_Text : String;
      Value     : String)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return Critical_Option
        (Name_Text,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Bytes (Value))));
   end Critical_Option_With_Text;

   function Critical_Option_With_No_Data
     (Name_Text : String)
      return Ada.Streams.Stream_Element_Array
   is
      Empty_Data : Ada.Streams.Stream_Element_Array (1 .. 0);
   begin
      return Critical_Option (Name_Text, Empty_Data);
   end Critical_Option_With_No_Data;

   function Join_Bytes
     (Left_Value  : Ada.Streams.Stream_Element_Array;
      Right_Value : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array
   is
      Result : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset
                (Left_Value'Length + Right_Value'Length));
      Cursor : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      for Byte_Value of Left_Value loop
         Result (Cursor) := Byte_Value;
         Cursor := Cursor + 1;
      end loop;
      for Byte_Value of Right_Value loop
         Result (Cursor) := Byte_Value;
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end Join_Bytes;

   procedure Write_Unsupported_Key_Type_File
     (Path : String;
      Host : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         Host & " ssh-dss "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " unsupported-public-test-fixture");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Unsupported_Key_Type_File;

   procedure Write_Malformed_Key_File
     (Path : String;
      Host : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File, Host & " ssh-ed25519 not-base64*** malformed-public-test-fixture");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Malformed_Key_File;

   procedure Write_Unsupported_Marker_File
     (Path : String;
      Host : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         "@future-marker " & Host & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " unsupported-marker-test-fixture");
      Ada.Text_IO.Put_Line
        (Output_File,
         Host & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " later-trust-must-not-mask-unsupported-marker");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Unsupported_Marker_File;

   procedure Write_Hashed_Entry_File
     (Path : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         "|1|MDEyMzQ1Njc4OTAxMjM0NTY3ODk=|bplZWJh/q373tJUck9r4LRZmhuU= "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " hashed-public-test-fixture");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Hashed_Entry_File;

   procedure Write_Negated_Hashed_Veto_File
     (Path : String;
      Host : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         "!|1|MDEyMzQ1Njc4OTAxMjM0NTY3ODk=|bplZWJh/q373tJUck9r4LRZmhuU=,"
         & Host & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " negated-hashed-veto-test-fixture");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Negated_Hashed_Veto_File;

   procedure Write_Nonmatching_Hashed_Unsupported_Marker_File
     (Path : String;
      Host : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         "@future-marker |1|MDEyMzQ1Njc4OTAxMjM0NTY3ODk=|i1N6iwXhz1+LwJbA9CP3DbfSKKI= "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " nonmatching-hashed-unsupported-marker-test-fixture");
      Ada.Text_IO.Put_Line
        (Output_File,
         Host & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " later-trust-after-unrelated-hashed-marker");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Nonmatching_Hashed_Unsupported_Marker_File;

   procedure Write_Malformed_Bracketed_Selector_File
     (Path : String;
      Host : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         "[" & Host & "]x22 "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " malformed-bracketed-selector-test-fixture");
      Ada.Text_IO.Put_Line
        (Output_File,
         Host & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " later-trust-must-not-mask-malformed-bracketed-selector");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Malformed_Bracketed_Selector_File;

   procedure Write_Empty_Host_List_Member_File
     (Path : String;
      Host : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         Host & ",," & Host & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " empty-host-list-member-test-fixture");
      Ada.Text_IO.Put_Line
        (Output_File,
         Host & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " later-trust-must-not-mask-empty-host-list-member");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Empty_Host_List_Member_File;

   procedure Write_Unsupported_Hash_Version_File
     (Path : String;
      Host : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         "|2|MDEyMzQ1Njc4OTAxMjM0NTY3ODk=|bplZWJh/q373tJUck9r4LRZmhuU= "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " unsupported-hash-version-test-fixture");
      Ada.Text_IO.Put_Line
        (Output_File,
         Host & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " later-trust-must-not-mask-unknown-hash-version");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Unsupported_Hash_Version_File;

   procedure Write_Malformed_Hashed_Selector_File
     (Path : String;
      Host : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         "|1|not-base64|also-not-base64 "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " malformed-hashed-selector-test-fixture");
      Ada.Text_IO.Put_Line
        (Output_File,
         Host & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " later-trust-must-not-mask-malformed-hashed-selector");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Malformed_Hashed_Selector_File;

   procedure Write_Matching_Hashed_Unsupported_Key_File
     (Path : String;
      Host : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         "|1|MDEyMzQ1Njc4OTAxMjM0NTY3ODk=|bplZWJh/q373tJUck9r4LRZmhuU= "
         & "ssh-future-hostkey@example.test "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " matching-hashed-unsupported-key-test-fixture");
      Ada.Text_IO.Put_Line
        (Output_File,
         Host & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " later-trust-must-not-mask-matching-hashed-unsupported-key");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Matching_Hashed_Unsupported_Key_File;

   procedure Write_Matching_Hashed_Malformed_Key_File
     (Path : String;
      Host : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         "|1|MDEyMzQ1Njc4OTAxMjM0NTY3ODk=|bplZWJh/q373tJUck9r4LRZmhuU= "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm
         & " AAAA matching-hashed-malformed-key-test-fixture");
      Ada.Text_IO.Put_Line
        (Output_File,
         Host & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " later-trust-must-not-mask-matching-hashed-malformed-key");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Matching_Hashed_Malformed_Key_File;

   procedure Write_Cert_Authority_File
     (Path : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         "@cert-authority *.example.test " & Test_CA_Host_Key_Algorithm & " "
         & Test_CA_Host_Key_Blob
         & " cert-authority-public-test-fixture");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Cert_Authority_File;

   procedure Write_Ed25519_Cert_Authority_File
     (Path : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         "@cert-authority ed.cert.example.test "
         & Test_Ed25519_CA_Host_Key_Algorithm & " "
         & Test_Ed25519_CA_Host_Key_Blob
         & " ed25519-cert-authority-public-test-fixture");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Ed25519_Cert_Authority_File;

   procedure Write_Wrong_Cert_Authority_File
     (Path : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         "@cert-authority *.example.test ssh-ed25519 "
         & SSH_Lib.Tests.Fixtures.Keys.Alternate_Host_Key_Blob
         & " wrong-cert-authority-public-test-fixture");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Wrong_Cert_Authority_File;

   procedure Write_Revoked_Cert_Authority_File
     (Path : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         "@revoked *.example.test " & Test_CA_Host_Key_Algorithm & " "
         & Test_CA_Host_Key_Blob
         & " revoked-cert-authority-public-test-fixture");
      Ada.Text_IO.Put_Line
        (Output_File,
         "@cert-authority *.example.test " & Test_CA_Host_Key_Algorithm & " "
         & Test_CA_Host_Key_Blob
         & " later-ca-trust-must-not-mask-revocation");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Revoked_Cert_Authority_File;

   procedure Write_Wildcard_File
     (Path : String)
   is
      Output_File : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         "*.example.test "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " wildcard-public-test-fixture");
      Ada.Text_IO.Close (Output_File);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Write_Wildcard_File;

   procedure Remove_If_Present (Path : String) is
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_File (Path);
      end if;
   exception
      when others =>
         null;
   end Remove_If_Present;

   procedure Assert_OpenSSH_Certificate_Critical_Option_Policy is
      Status_Value : CryptoLib.Errors.Status;
      Empty_Options : Ada.Streams.Stream_Element_Array (1 .. 0);
      Malformed_Text_Data : constant Ada.Streams.Stream_Element_Array := Bytes ("192.0.2.0/24");
      Unknown_Options : constant Ada.Streams.Stream_Element_Array :=
        Critical_Option_With_No_Data ("unknown-critical@example.test");
      Source_Address_Options : constant Ada.Streams.Stream_Element_Array :=
        Critical_Option_With_Text ("source-address", "192.0.2.0/24,2001:db8::/32");
      Force_Command_Options : constant Ada.Streams.Stream_Element_Array :=
        Critical_Option_With_Text ("force-command", "git-upload-pack repo.git");
      Verify_Required_Options : constant Ada.Streams.Stream_Element_Array :=
        Critical_Option_With_No_Data ("verify-required");
      Malformed_Source_Address_Options : constant Ada.Streams.Stream_Element_Array :=
        Critical_Option ("source-address", Malformed_Text_Data);
      Bad_Source_Address_Octet_Options : constant Ada.Streams.Stream_Element_Array :=
        Critical_Option_With_Text ("source-address", "999.0.2.1/24");
      Bad_Source_Address_Mask_Options : constant Ada.Streams.Stream_Element_Array :=
        Critical_Option_With_Text ("source-address", "192.0.2.1/33");
      Bad_Source_Address_Name_Options : constant Ada.Streams.Stream_Element_Array :=
        Critical_Option_With_Text ("source-address", "git.example.test");
      Bad_Source_Address_IPv6_Mask_Options : constant Ada.Streams.Stream_Element_Array :=
        Critical_Option_With_Text ("source-address", "2001:db8::/129");
      Bad_Source_Address_IPv6_Trailing_Colon_Options : constant Ada.Streams.Stream_Element_Array :=
        Critical_Option_With_Text ("source-address", "2001:db8:1:2:3:4:5:");
      Valid_Source_Address_IPv6_Compressed_Trailing_Options : constant Ada.Streams.Stream_Element_Array :=
        Critical_Option_With_Text ("source-address", "2001:db8::/32");
      Bad_Verify_Required_Options : constant Ada.Streams.Stream_Element_Array :=
        Critical_Option_With_Text ("verify-required", "payload-is-not-canonical");
      No_Touch_Required_Options : constant Ada.Streams.Stream_Element_Array :=
        Critical_Option_With_No_Data ("no-touch-required");
      Duplicate_Options : constant Ada.Streams.Stream_Element_Array :=
        Join_Bytes
          (Critical_Option_With_No_Data ("verify-required"),
           Critical_Option_With_No_Data ("verify-required"));
      Unsorted_Options : constant Ada.Streams.Stream_Element_Array :=
        Join_Bytes
          (Critical_Option_With_Text ("source-address", "192.0.2.0/24"),
           Critical_Option_With_Text ("force-command", "git-upload-pack repo.git"));
   begin
      Status_Value := SSH_Lib.Protocol.Certificates.Validate_Host_Critical_Options_For_Test
        (Empty_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "host certificate critical options",
         "empty host-certificate critical option map is accepted");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_Host_Critical_Options_For_Test
        (Unknown_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "host certificate critical options",
         "unknown host-certificate critical options remain fail-closed");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_Host_Critical_Options_For_Test
        (Source_Address_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Host_Key_Mismatch,
         "host certificate critical options",
         "valid source-address option is parsed then rejected for host certificates");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_Host_Critical_Options_For_Test
        (Force_Command_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Host_Key_Mismatch,
         "host certificate critical options",
         "valid force-command option is parsed then rejected for host certificates");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_Host_Critical_Options_For_Test
        (Verify_Required_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Host_Key_Mismatch,
         "host certificate critical options",
         "empty verify-required option is rejected as user-certificate-only policy");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_Host_Critical_Options_For_Test
        (Malformed_Source_Address_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "host certificate critical options",
         "source-address data must be nested SSH-string encoded");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_Host_Critical_Options_For_Test
        (Bad_Source_Address_Octet_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "host certificate critical options",
         "source-address rejects invalid IPv4 octets before host-certificate policy");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_Host_Critical_Options_For_Test
        (Bad_Source_Address_Mask_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "host certificate critical options",
         "source-address rejects invalid IPv4 masks before host-certificate policy");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_Host_Critical_Options_For_Test
        (Bad_Source_Address_Name_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "host certificate critical options",
         "source-address rejects non-address names before host-certificate policy");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_Host_Critical_Options_For_Test
        (Bad_Source_Address_IPv6_Trailing_Colon_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "host certificate critical options",
         "source-address rejects IPv6 literals with a single trailing colon");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_Host_Critical_Options_For_Test
        (Valid_Source_Address_IPv6_Compressed_Trailing_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Host_Key_Mismatch,
         "host certificate critical options",
         "source-address accepts valid IPv6 double-colon compression before host policy rejection");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_Host_Critical_Options_For_Test
        (Bad_Verify_Required_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "host certificate critical options",
         "empty-only host certificate options reject unexpected payload data");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_Host_Critical_Options_For_Test
        (No_Touch_Required_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Host_Key_Mismatch,
         "host certificate critical options",
         "empty no-touch-required option is rejected as user-certificate-only policy");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_Host_Critical_Options_For_Test
        (Duplicate_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Host_Key_Mismatch,
         "host certificate critical options",
         "duplicate critical option names are rejected as non-canonical");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_Host_Critical_Options_For_Test
        (Unsorted_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Host_Key_Mismatch,
         "host certificate critical options",
         "unsorted critical option names are rejected as non-canonical");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_User_Critical_Options_For_Test
        (Unknown_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "user certificate critical options",
         "unknown user-certificate critical options are canonical data for server-side CA policy");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_User_Critical_Options_For_Test
        (Source_Address_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "user certificate critical options",
         "valid user-certificate source-address option is accepted locally");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_User_Critical_Options_For_Test
        (Force_Command_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "user certificate critical options",
         "valid user-certificate force-command framing is accepted locally");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_User_Critical_Options_For_Test
        (Malformed_Source_Address_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "user certificate critical options",
         "malformed user-certificate source-address data fails closed");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_User_Critical_Options_For_Test
        (Bad_Source_Address_IPv6_Mask_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "user certificate critical options",
         "user-certificate source-address rejects invalid IPv6 masks");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_User_Critical_Options_For_Test
        (Bad_Source_Address_Name_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "user certificate critical options",
         "user-certificate source-address rejects DNS names as CIDR-list entries");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_User_Critical_Options_For_Test
        (Bad_Source_Address_IPv6_Trailing_Colon_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "user certificate critical options",
         "user-certificate source-address rejects a single IPv6 trailing colon");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_User_Critical_Options_For_Test
        (Valid_Source_Address_IPv6_Compressed_Trailing_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "user certificate critical options",
         "user-certificate source-address accepts valid IPv6 double-colon compression");

      Status_Value := SSH_Lib.Protocol.Certificates.Validate_User_Critical_Options_For_Test
        (Duplicate_Options);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "user certificate critical options",
         "duplicate user critical option names are rejected as non-canonical");

   end Assert_OpenSSH_Certificate_Critical_Option_Policy;

   procedure Assert_Known_Hosts_Record_Matching_Matrix is
      Host_Name       : constant String := "github.com";
      Other_Host      : constant String := "example.net";
      Alias_Host      : constant String := "host2";
      Default_Port_Host : constant String := "default-port.example.com";
      Port_Host       : constant String := "example.com";
      IPv4_Host       : constant String := "127.0.0.1";
      IPv6_Host       : constant String := "::1";
      Matrix_Path     : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path
          ("phase7_known_hosts_record_matching_matrix");
      Presented_Key   : constant SSH_Lib.Known_Hosts.Host_Key :=
        SSH_Lib.Tests.Fixtures.Known_Hosts.Fixture_Host_Key;
      Changed_Key     : constant SSH_Lib.Known_Hosts.Host_Key :=
        SSH_Lib.Known_Hosts.Create_Host_Key
          (SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm,
           SSH_Lib.Tests.Fixtures.Keys.Alternate_Host_Key_Blob);
      Trust_Result    : SSH_Lib.Known_Hosts.Verification_Result;
      Output_File     : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Matrix_Path);
      Ada.Text_IO.Put_Line (Output_File, "");
      Ada.Text_IO.Put_Line (Output_File, "# comment before trusted records");
      Ada.Text_IO.Put_Line
        (Output_File,
         Host_Name & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & " trailing comment");
      Ada.Text_IO.Put_Line
        (Output_File,
         "host1," & Alias_Host & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob);
      Ada.Text_IO.Put_Line
        (Output_File,
         "[" & Port_Host & "]:2222 "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob);
      Ada.Text_IO.Put_Line
        (Output_File,
         "[" & Default_Port_Host & "]:22 "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob);
      Ada.Text_IO.Put_Line
        (Output_File,
         IPv4_Host & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob);
      Ada.Text_IO.Put_Line
        (Output_File,
         "[" & IPv4_Host & "]:2222 "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob);
      Ada.Text_IO.Put_Line
        (Output_File,
         "[" & IPv6_Host & "]:2222 "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob);
      Ada.Text_IO.Close (Output_File);

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, Host_Name, 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Trusted,
             "known_hosts bare host matches default port");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, "GitHub.com", 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Trusted,
             "known_hosts host match is case-insensitive");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, Other_Host, 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Unknown,
             "known_hosts different host remains unknown");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, Alias_Host, 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Trusted,
             "known_hosts comma-separated alias matches");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, Default_Port_Host, 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Trusted,
             "known_hosts bracketed port 22 matches default port");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, Port_Host, 2222, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Trusted,
             "known_hosts bracketed host matches exact nonstandard port");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, Port_Host, 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Unknown,
             "known_hosts nonstandard port record does not match default port");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, Host_Name, 2222, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Unknown,
             "known_hosts bare host record does not match nonstandard port");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, IPv4_Host, 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Trusted,
             "known_hosts bare IPv4 selector matches default port");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, IPv4_Host, 2222, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Trusted,
             "known_hosts bracketed IPv4 selector matches explicit port");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, IPv6_Host, 2222, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Trusted,
             "known_hosts bracketed IPv6 selector matches explicit port");

      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Matrix_Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         Host_Name & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Alternate_Host_Key_Blob);
      Ada.Text_IO.Close (Output_File);

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, Host_Name, 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Mismatch,
             "known_hosts supported changed key reports mismatch");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Known_Hosts.To_Status (Trust_Result),
         CryptoLib.Errors.Host_Key_Mismatch,
         "known_hosts record matching", "changed key maps to Host_Key_Mismatch");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, Other_Host, 22, Changed_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Unknown,
             "known_hosts changed key for another host remains unknown");
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Assert_Known_Hosts_Record_Matching_Matrix;

   procedure Assert_Known_Hosts_Fail_Closed_Matching_Records is
      Host_Name    : constant String := "github.com";
      Matrix_Path  : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path
          ("phase7_known_hosts_fail_closed_matching_records");
      Presented_Key : constant SSH_Lib.Known_Hosts.Host_Key :=
        SSH_Lib.Tests.Fixtures.Known_Hosts.Fixture_Host_Key;
      Trust_Result : SSH_Lib.Known_Hosts.Verification_Result;

      procedure Write_Text (Content : String) is
         Output_File : Ada.Text_IO.File_Type;
      begin
         Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Matrix_Path);
         Ada.Text_IO.Put (Output_File, Content);
         Ada.Text_IO.Close (Output_File);
      exception
         when others =>
            if Ada.Text_IO.Is_Open (Output_File) then
               Ada.Text_IO.Close (Output_File);
            end if;
            raise;
      end Write_Text;
   begin
      Write_Text
        (Host_Name & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm
         & " bad@@base64" & Character'Val (10)
         & Host_Name & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & Character'Val (10));
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, Host_Name, 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Unsupported_Entry,
             "known_hosts malformed matching base64 fails closed before later trust");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Known_Hosts.To_Status (Trust_Result),
         CryptoLib.Errors.Unsupported_Feature,
         "known_hosts fail closed", "malformed matching base64 maps to Unsupported_Feature");

      Write_Text
        (Host_Name & " ssh-ed25519-cert-v01@openssh.com AAAA"
         & Character'Val (10)
         & Host_Name & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & Character'Val (10));
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, Host_Name, 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Unsupported_Entry,
             "known_hosts malformed matching host certificate fails closed before later trust");

      Write_Text
        (Host_Name & " ecdsa-sha2-nistp256 AAAA" & Character'Val (10));
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, Host_Name, 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Unsupported_Entry,
             "known_hosts unsupported matching key type is not trusted");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Known_Hosts.To_Status (Trust_Result),
         CryptoLib.Errors.Unsupported_Feature,
         "known_hosts fail closed", "unsupported matching key maps to Unsupported_Feature");

      Write_Text
        ("@cert-authority " & Host_Name & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & Character'Val (10));
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, Host_Name, 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Unknown,
             "known_hosts cert-authority marker does not trust raw host key");

      Write_Text
        ("@revoked " & Host_Name & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & Character'Val (10)
         & Host_Name & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & Character'Val (10));
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, Host_Name, 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Mismatch,
             "known_hosts revoked raw key blocks later trust");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Known_Hosts.To_Status (Trust_Result),
         CryptoLib.Errors.Host_Key_Mismatch,
         "known_hosts fail closed", "revoked raw key maps to Host_Key_Mismatch");

      Write_Text
        (Host_Name & " " & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm
         & Character'Val (10));
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, Host_Name, 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Unknown,
             "known_hosts missing key blob is not accepted as trust");

      Write_Text
        ("!" & Host_Name & "," & Host_Name & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & Character'Val (10));
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matrix_Path, Host_Name, 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Unknown,
             "known_hosts matching negated selector vetoes trust for that line");
   end Assert_Known_Hosts_Fail_Closed_Matching_Records;

   procedure Assert_Known_Hosts_Wildcard_And_Hashed_Matrix is
      Wildcard_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path
          ("phase19_known_hosts_wildcard_matrix");
      Hash_Path     : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path
          ("phase19_known_hosts_hashed_matrix");
      Presented_Key : constant SSH_Lib.Known_Hosts.Host_Key :=
        SSH_Lib.Tests.Fixtures.Known_Hosts.Fixture_Host_Key;
      Changed_Key   : constant SSH_Lib.Known_Hosts.Host_Key :=
        SSH_Lib.Known_Hosts.Create_Host_Key
          (SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm,
           SSH_Lib.Tests.Fixtures.Keys.Alternate_Host_Key_Blob);
      Trust_Result  : SSH_Lib.Known_Hosts.Verification_Result;

      procedure Write_Text (Path : String; Content : String) is
         Output_File : Ada.Text_IO.File_Type;
      begin
         Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Path);
         Ada.Text_IO.Put (Output_File, Content);
         Ada.Text_IO.Close (Output_File);
      exception
         when others =>
            if Ada.Text_IO.Is_Open (Output_File) then
               Ada.Text_IO.Close (Output_File);
            end if;
            raise;
      end Write_Text;
   begin
      Write_Text
        (Wildcard_Path,
         "*.example.com " & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm
         & " " & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & Character'Val (10));
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Wildcard_Path, "repo.example.com", 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Trusted,
             "known_hosts wildcard selector trusts matching host");
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Wildcard_Path, "repo.example.com", 22, Changed_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Mismatch,
             "known_hosts wildcard selector detects changed key");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Known_Hosts.To_Status (Trust_Result),
         CryptoLib.Errors.Host_Key_Mismatch,
         "known_hosts wildcard matrix", "wildcard changed key maps to Host_Key_Mismatch");
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Wildcard_Path, "repo.bad.test", 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Unknown,
             "known_hosts wildcard selector rejects unrelated host");

      Write_Text
        (Wildcard_Path,
         "!*.example.com,repo.example.com "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & Character'Val (10));
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Wildcard_Path, "repo.example.com", 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Unknown,
             "known_hosts negated wildcard vetoes positive selector on same line");

      Write_Text
        (Wildcard_Path,
         "!repo.example.com "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & Character'Val (10)
         & "api.example.com "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & Character'Val (10));
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Wildcard_Path, "repo.example.com", 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Unknown,
             "known_hosts negated-only selector does not create mismatch");

      Write_Text
        (Wildcard_Path,
         "@revoked !repo.example.com "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & Character'Val (10)
         & "repo.example.com "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & Character'Val (10));
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Wildcard_Path, "repo.example.com", 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Trusted,
             "known_hosts negated revoked selector does not revoke host");

      Write_Text
        (Wildcard_Path,
         "*.example.com,repo.example.com "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & Character'Val (10));
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Wildcard_Path, "repo.example.com", 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Trusted,
             "known_hosts wildcard and exact selector trust same line");
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Wildcard_Path, "api.example.com", 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Trusted,
             "known_hosts wildcard selector trusts sibling host");

      Write_Text
        (Hash_Path,
         "|1|YWJj|ZGVm "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & Character'Val (10));
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Hash_Path, "github.com", 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Unknown,
             "known_hosts malformed hashed selector remains unknown");

      Write_Text
        (Hash_Path,
         "|1|YWJj|s14BuiEH7+LNfU8Q1VfOntFnqiM= "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm & " "
         & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob
         & Character'Val (10));
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Hash_Path, "github.com", 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Trusted,
             "known_hosts hashed selector establishes trust");
      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Hash_Path, "GitHub.com", 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Trusted,
             "known_hosts hashed selector match is case-insensitive");
   end Assert_Known_Hosts_Wildcard_And_Hashed_Matrix;

   procedure Assert_Known_Hosts_Load_And_Key_Normalization is
      use Ada.Strings.Unbounded;

      Valid_RSA          : constant String :=
        "AAAAB3NzaC1yc2EAAAADAQABAAAABgCAAQIDBA==";
      Valid_RSA_Unpadded : constant String :=
        "AAAAB3NzaC1yc2EAAAADAQABAAAABgCAAQIDBA";
      Plain_Path         : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path
          ("phase7_known_hosts_load_plain");
      Missing_Path       : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path
          ("phase7_known_hosts_load_missing");
      Empty_Path         : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path
          ("phase7_known_hosts_load_empty");
      Presented_Key      : constant SSH_Lib.Known_Hosts.Host_Key :=
        SSH_Lib.Tests.Fixtures.Known_Hosts.Fixture_Host_Key;
      RSA_Key            : constant SSH_Lib.Known_Hosts.Host_Key :=
        SSH_Lib.Known_Hosts.Create_Host_Key ("ssh-rsa", Valid_RSA);
      RSA_Key_Unpadded   : constant SSH_Lib.Known_Hosts.Host_Key :=
        SSH_Lib.Known_Hosts.Create_Host_Key ("ssh-rsa", Valid_RSA_Unpadded);
      Data_Item          : SSH_Lib.Known_Hosts.Database;
      Public_Key_Item    : SSH_Lib.Keys.Public_Key;
      Public_Key_Blob    : constant Ada.Streams.Stream_Element_Array :=
        [0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57,
         0, 0, 0, 32, 0, 10, 13, 127, 128, 255, 49, 56, 63, 70, 77,
         84, 91, 98, 105, 112, 119, 126, 133, 140, 147, 154, 161,
         168, 175, 182, 189, 196, 203, 210, 217, 224];
      Trust_Result       : SSH_Lib.Known_Hosts.Verification_Result;
      Status_Value       : CryptoLib.Errors.Status;
      Output_File        : Ada.Text_IO.File_Type;
   begin
      Check (SSH_Lib.Known_Hosts.Is_Valid (Presented_Key),
             "known_hosts fixture Ed25519 host key is valid");
      Check (SSH_Lib.Known_Hosts.Is_Valid (RSA_Key),
             "known_hosts padded RSA fixture is valid");
      Check (SSH_Lib.Known_Hosts.Is_Valid (RSA_Key_Unpadded),
             "known_hosts unpadded RSA fixture is valid");
      Check (SSH_Lib.Known_Hosts.Equal (RSA_Key, RSA_Key_Unpadded),
             "known_hosts equality compares decoded RSA blobs");

      Remove_If_Present (Missing_Path);
      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Empty_Path);
      Ada.Text_IO.Close (Output_File);

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Missing_Path, "example.com", 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Unknown,
             "missing known_hosts file means unknown host");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Known_Hosts.To_Status (Trust_Result),
         CryptoLib.Errors.Host_Key_Unknown,
         "known_hosts load", "missing known_hosts verification maps to Host_Key_Unknown");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Empty_Path, "example.com", 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Unknown,
             "empty known_hosts file means unknown host");

      Ada.Text_IO.Create (Output_File, Ada.Text_IO.Out_File, Plain_Path);
      Ada.Text_IO.Put_Line
        (Output_File,
         "github.com " & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm
         & " " & SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Blob);
      Ada.Text_IO.Close (Output_File);

      Status_Value := SSH_Lib.Known_Hosts.Load (Plain_Path, Data_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "known_hosts load", "explicit known_hosts database load succeeds");
      Status_Value := SSH_Lib.Keys.Internal.Set_Public_Key
        (Public_Key_Item, SSH_Lib.Tests.Fixtures.Keys.Test_Host_Key_Algorithm, Public_Key_Blob);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Ok,
         "known_hosts load", "fixture public key initializes for loaded database check");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Known_Hosts.Check (Data_Item, "github.com", 22, Public_Key_Item),
         CryptoLib.Errors.Ok,
         "known_hosts load", "loaded known_hosts database trusts fixture host");
      Check (To_String (SSH_Lib.Known_Hosts.Default_File)'Length > 0,
             "known_hosts default file path is available");

      Status_Value := SSH_Lib.Known_Hosts.Load (Missing_Path, Data_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value,
         CryptoLib.Errors.Host_Key_Unknown,
         "known_hosts load", "missing known_hosts database load reports Host_Key_Unknown");
      Check (SSH_Lib.Known_Hosts.Check (Data_Item, "github.com", 22, Public_Key_Item)
             /= CryptoLib.Errors.Ok,
             "missing known_hosts database does not trust fixture host");
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         raise;
   end Assert_Known_Hosts_Load_And_Key_Normalization;

   procedure Assert_Host_Key_Verification_Order_And_Trust is
      Host_Name : constant String := "git.example.test";
      Nonstandard_Host : constant String := "port.example.test";
      Missing_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_host_key_missing_known_hosts");
      Match_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_host_key_matching_known_hosts");
      Changed_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_host_key_changed_known_hosts");
      Unsupported_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_host_key_unsupported_known_hosts");
      Malformed_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_host_key_malformed_known_hosts");
      Unsupported_Marker_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_host_key_unsupported_marker_known_hosts");
      Hashed_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_host_key_hashed_known_hosts");
      Negated_Hashed_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_host_key_negated_hashed_known_hosts");
      Nonmatching_Hashed_Marker_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_host_key_nonmatching_hashed_marker_known_hosts");
      Matching_Hashed_Unsupported_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_host_key_matching_hashed_unsupported_known_hosts");
      Matching_Hashed_Malformed_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_host_key_matching_hashed_malformed_known_hosts");
      Unsupported_Hash_Version_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_host_key_unsupported_hash_version_known_hosts");
      Malformed_Hashed_Selector_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_host_key_malformed_hashed_selector_known_hosts");
      Malformed_Bracketed_Selector_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_host_key_malformed_bracketed_selector_known_hosts");
      Empty_Host_List_Member_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_host_key_empty_host_list_member_known_hosts");
      Wildcard_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_host_key_wildcard_known_hosts");
      Port_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase19_host_key_port_known_hosts");
      Cert_Authority_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase259_host_key_cert_authority_known_hosts");
      Ed25519_Cert_Authority_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase259_host_key_ed25519_cert_authority_known_hosts");
      Wrong_Cert_Authority_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase259_host_key_wrong_cert_authority_known_hosts");
      Revoked_Cert_Authority_Path : constant String :=
        SSH_Lib.Tests.Fixtures.Temp_Paths.Path ("phase259_host_key_revoked_cert_authority_known_hosts");
      Presented_Key : constant SSH_Lib.Known_Hosts.Host_Key :=
        SSH_Lib.Tests.Fixtures.Known_Hosts.Fixture_Host_Key;
      Presented_Certificate : constant SSH_Lib.Known_Hosts.Host_Key :=
        SSH_Lib.Known_Hosts.Create_Host_Key
          (Test_Host_Certificate_Algorithm, Test_Host_Certificate_Blob);
      Presented_Certified_Raw_Key : constant SSH_Lib.Known_Hosts.Host_Key :=
        SSH_Lib.Known_Hosts.Create_Host_Key
          ("ssh-ed25519", Test_Certified_Host_Key_Blob);
      Presented_Ed25519_CA_Certificate : constant SSH_Lib.Known_Hosts.Host_Key :=
        SSH_Lib.Known_Hosts.Create_Host_Key
          (Test_Host_Certificate_Algorithm,
           Test_Ed25519_CA_Host_Certificate_Blob);
      Trust_Result : SSH_Lib.Known_Hosts.Verification_Result;
   begin
      Remove_If_Present (Missing_Path);
      SSH_Lib.Tests.Fixtures.Known_Hosts.Write_Matching_File
        (Match_Path, Host_Name);
      SSH_Lib.Tests.Fixtures.Known_Hosts.Write_Changed_File
        (Changed_Path, Host_Name);
      Write_Unsupported_Key_Type_File (Unsupported_Path, Host_Name);
      Write_Malformed_Key_File (Malformed_Path, Host_Name);
      Write_Unsupported_Marker_File (Unsupported_Marker_Path, Host_Name);
      Write_Hashed_Entry_File (Hashed_Path);
      Write_Negated_Hashed_Veto_File (Negated_Hashed_Path, Host_Name);
      Write_Nonmatching_Hashed_Unsupported_Marker_File
        (Nonmatching_Hashed_Marker_Path, Host_Name);
      Write_Matching_Hashed_Unsupported_Key_File
        (Matching_Hashed_Unsupported_Path, Host_Name);
      Write_Matching_Hashed_Malformed_Key_File
        (Matching_Hashed_Malformed_Path, Host_Name);
      Write_Unsupported_Hash_Version_File
        (Unsupported_Hash_Version_Path, Host_Name);
      Write_Malformed_Hashed_Selector_File
        (Malformed_Hashed_Selector_Path, Host_Name);
      Write_Malformed_Bracketed_Selector_File
        (Malformed_Bracketed_Selector_Path, Host_Name);
      Write_Empty_Host_List_Member_File
        (Empty_Host_List_Member_Path, Host_Name);
      Write_Wildcard_File (Wildcard_Path);
      SSH_Lib.Tests.Fixtures.Known_Hosts.Write_Matching_File
        (Port_Path, Nonstandard_Host, 2222);
      Write_Cert_Authority_File
        (Cert_Authority_Path);
      Write_Ed25519_Cert_Authority_File
        (Ed25519_Cert_Authority_Path);
      Write_Wrong_Cert_Authority_File
        (Wrong_Cert_Authority_Path);
      Write_Revoked_Cert_Authority_File
        (Revoked_Cert_Authority_Path);

      Check
        (SSH_Lib.Known_Hosts.Is_Valid (Presented_Certificate),
         "phase259 realistic OpenSSH host certificate fixture is a valid host key");
      Check
        (SSH_Lib.Known_Hosts.Is_Valid (Presented_Certified_Raw_Key),
         "phase259 certified raw host key fixture is valid");
      Check
        (SSH_Lib.Known_Hosts.Is_Valid (Presented_Ed25519_CA_Certificate),
         "phase259 Ed25519 CA host certificate fixture is valid");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Missing_Path, Host_Name, 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Unknown,
             "valid KEX signature but host absent from known_hosts is unknown");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Host_Key_Unknown,
         "host-key security", "valid signature plus absent known_hosts returns Host_Key_Unknown");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Changed_Path, Host_Name, 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Mismatch,
             "valid KEX signature but different known_hosts key is mismatch");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Host_Key_Mismatch,
         "host-key security", "valid signature plus changed known_hosts returns Host_Key_Mismatch");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Match_Path, Host_Name, 22, Presented_Key);
      Check (Trust_Result = SSH_Lib.Known_Hosts.Trusted,
             "matching known_hosts record is trusted only after signature success");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Handshake_Failed, Trust_Result),
         CryptoLib.Errors.Handshake_Failed,
         "host-key security", "invalid signature is rejected before known_hosts trust");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.May_Authenticate
           (CryptoLib.Errors.Handshake_Failed, Trust_Result),
         CryptoLib.Errors.Handshake_Failed,
         "host-key security", "authentication is blocked after invalid host-key signature");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.May_Authenticate
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Ok,
         "host-key security", "authentication may begin after signature and known_hosts trust");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Authentication_Guards.Can_Start_Userauth
           (Encrypted_Mode_Active => True,
            Host_Key_Trusted      => False),
         CryptoLib.Errors.Host_Key_Unknown,
         "host-key security", "known_hosts trust is checked before authentication");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Unsupported_Path, Host_Name, 22, Presented_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Unsupported_Feature,
         "host-key security", "unsupported matching known_hosts key type is not trusted");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Malformed_Path, Host_Name, 22, Presented_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Unsupported_Feature,
         "host-key security", "malformed matching known_hosts line fails closed");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Unsupported_Marker_Path, Host_Name, 22, Presented_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Unsupported_Feature,
         "host-key security", "unsupported matching known_hosts marker fails closed before later trust");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Hashed_Path, Host_Name, 22, Presented_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Ok,
         "host-key security", "hashed known_hosts entry can establish trust");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Negated_Hashed_Path, Host_Name, 22, Presented_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Host_Key_Unknown,
         "host-key security", "negated hashed known_hosts selector vetoes only its line");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Nonmatching_Hashed_Marker_Path, Host_Name, 22, Presented_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Ok,
         "host-key security", "nonmatching hashed unsupported marker does not mask later trust");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matching_Hashed_Unsupported_Path, Host_Name, 22, Presented_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Unsupported_Feature,
         "host-key security", "matching hashed unsupported key fails closed before later trust");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Matching_Hashed_Malformed_Path, Host_Name, 22, Presented_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Unsupported_Feature,
         "host-key security", "matching hashed malformed key fails closed before later trust");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Unsupported_Hash_Version_Path, Host_Name, 22, Presented_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Unsupported_Feature,
         "host-key security", "unknown hashed selector version fails closed before later trust");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Malformed_Hashed_Selector_Path, Host_Name, 22, Presented_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Ok,
         "host-key security", "malformed hashed selector does not mask later trust");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Malformed_Bracketed_Selector_Path, Host_Name, 22, Presented_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Ok,
         "host-key security", "malformed bracketed known_hosts selector does not mask later trust");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Empty_Host_List_Member_Path, Host_Name, 22, Presented_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Ok,
         "host-key security", "empty known_hosts host-list members do not mask later trust");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Wildcard_Path, Host_Name, 22, Presented_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Ok,
         "host-key security", "wildcard known_hosts entry can establish trust");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Port_Path, Nonstandard_Host, 22, Presented_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Host_Key_Unknown,
         "host-key security", "bare host does not trust nonstandard port entry");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Port_Path, Nonstandard_Host, 2222, Presented_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Ok,
         "host-key security", "explicit [host]:port known_hosts entry trusts exact port only");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Cert_Authority_Path, "cert.example.test", 22, Presented_Certificate);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Ok,
         "host-key security", "realistic host certificate signed by @cert-authority CA is trusted");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Cert_Authority_Path, "repo.cert.example.test", 22, Presented_Certificate);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Ok,
         "host-key security", "realistic host certificate wildcard principal is trusted");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Ed25519_Cert_Authority_Path, "ed.cert.example.test", 22,
         Presented_Ed25519_CA_Certificate);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Ok,
         "host-key security", "host certificate signed by Ed25519 @cert-authority CA is trusted");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Cert_Authority_Path, "wrong.example.test", 22, Presented_Certificate);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Host_Key_Mismatch,
         "host-key security", "host certificate principal mismatch fails closed");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Wrong_Cert_Authority_Path, "cert.example.test", 22, Presented_Certificate);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Host_Key_Mismatch,
         "host-key security", "host certificate signed by another CA is not trusted");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Revoked_Cert_Authority_Path, "cert.example.test", 22, Presented_Certificate);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Host_Key_Mismatch,
         "host-key security", "revoked CA blocks later cert-authority trust for host certificate");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Cert_Authority_Path, "cert.example.test", 22, Presented_Certified_Raw_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result),
         CryptoLib.Errors.Host_Key_Unknown,
         "host-key security", "cert-authority record does not trust the raw certified host key");

      Trust_Result := SSH_Lib.Known_Hosts.Verify
        (Changed_Path, Host_Name, 22, Presented_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Ok, Trust_Result, Verification_Enabled => False),
         CryptoLib.Errors.Ok,
         "host-key security", "explicit host-key verification bypass only skips known_hosts trust");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Host_Key_Guards.Trust_After_Signature
           (CryptoLib.Errors.Handshake_Failed, Trust_Result, Verification_Enabled => False),
         CryptoLib.Errors.Handshake_Failed,
         "host-key security", "verification bypass does not bypass invalid signature");
   end Assert_Host_Key_Verification_Order_And_Trust;

   function Public_Key_Blob_For_Test return Ada.Streams.Stream_Element_Array is
   begin
      return
        [0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57,
         0, 0, 0, 32, 0, 10, 13, 127, 128, 255, 49, 56, 63, 70, 77,
         84, 91, 98, 105, 112, 119, 126, 133, 140, 147, 154, 161,
         168, 175, 182, 189, 196, 203, 210, 217, 224];
   end Public_Key_Blob_For_Test;

   function Alternate_Public_Key_Blob_For_Test return Ada.Streams.Stream_Element_Array is
   begin
      return
        [0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57,
         0, 0, 0, 32, 0, 10, 13, 127, 128, 255, 49, 56, 63, 70, 77,
         84, 91, 98, 105, 112, 119, 126, 133, 140, 147, 154, 161,
         168, 175, 182, 189, 196, 203, 210, 217, 225];
   end Alternate_Public_Key_Blob_For_Test;

   function Uint64_Bytes (Value : Interfaces.Unsigned_64) return Ada.Streams.Stream_Element_Array is
      Result : Ada.Streams.Stream_Element_Array (1 .. 8);
      Working_Value : Interfaces.Unsigned_64 := Value;
   begin
      for Index_Value in reverse Result'Range loop
         Result (Index_Value) := Ada.Streams.Stream_Element (Working_Value mod 256);
         Working_Value := Working_Value / 256;
      end loop;
      return Result;
   end Uint64_Bytes;

   procedure Append_SSH_String
     (Buffer_Item : in out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Data        : Ada.Streams.Stream_Element_Array)
   is
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Buffer_Item,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Data)));
      Check (Status_Value = CryptoLib.Errors.Ok,
             "host certificate fixture string append");
   end Append_SSH_String;

   function Principal_List
     (First_Principal  : String;
      Second_Principal : String := "")
      return Ada.Streams.Stream_Element_Array
   is
      Buffer_Item : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   begin
      Append_SSH_String (Buffer_Item, Bytes (First_Principal));
      if Second_Principal'Length /= 0 then
         Append_SSH_String (Buffer_Item, Bytes (Second_Principal));
      end if;
      return SSH_Lib.Protocol.Buffers.To_Array (Buffer_Item);
   end Principal_List;

   function Minimal_Host_Certificate_Blob
     (Certificate_Key_Blob : Ada.Streams.Stream_Element_Array;
      Signature_Key_Blob   : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array
   is
      Buffer_Item : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
      Empty_Value : Ada.Streams.Stream_Element_Array (1 .. 0);
   begin
      Append_SSH_String (Buffer_Item, Bytes ("ssh-ed25519-cert-v01@openssh.com"));
      Append_SSH_String (Buffer_Item, Bytes ("nonce"));
      Append_SSH_String
        (Buffer_Item,
         Certificate_Key_Blob (Certificate_Key_Blob'First + 19 .. Certificate_Key_Blob'Last));
      Status_Value := SSH_Lib.Protocol.Buffers.Append (Buffer_Item, Uint64_Bytes (1));
      Check (Status_Value = CryptoLib.Errors.Ok, "host certificate serial append");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Buffer_Item, SSH_Lib.Protocol.Numbers.Encode_Uint32 (2));
      Check (Status_Value = CryptoLib.Errors.Ok, "host certificate type append");
      Append_SSH_String (Buffer_Item, Bytes ("host-cert-revocation-edge"));
      Append_SSH_String (Buffer_Item, Empty_Value);
      Status_Value := SSH_Lib.Protocol.Buffers.Append (Buffer_Item, Uint64_Bytes (0));
      Check (Status_Value = CryptoLib.Errors.Ok, "host certificate valid-after append");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Buffer_Item, Uint64_Bytes (16#FFFF_FFFF_FFFF_FFFF#));
      Check (Status_Value = CryptoLib.Errors.Ok, "host certificate valid-before append");
      Append_SSH_String (Buffer_Item, Empty_Value);
      Append_SSH_String (Buffer_Item, Empty_Value);
      Append_SSH_String (Buffer_Item, Empty_Value);
      Append_SSH_String (Buffer_Item, Signature_Key_Blob);
      Append_SSH_String (Buffer_Item, Empty_Value);
      return SSH_Lib.Protocol.Buffers.To_Array (Buffer_Item);
   end Minimal_Host_Certificate_Blob;

   procedure Assert_Host_Certificate_Revocation_Edges is
      CA_Key_Blob        : constant Ada.Streams.Stream_Element_Array := Public_Key_Blob_For_Test;
      Alternate_Key_Blob : constant Ada.Streams.Stream_Element_Array := Alternate_Public_Key_Blob_For_Test;
      Certificate_Blob   : constant Ada.Streams.Stream_Element_Array :=
        Minimal_Host_Certificate_Blob (CA_Key_Blob, CA_Key_Blob);
      Status_Value       : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.Protocol.Certificates.Host_Certificate_Signed_By_Public_Key
        (Certificate_Blob, "ssh-ed25519-cert-v01@openssh.com", CA_Key_Blob);
      Check (Status_Value = CryptoLib.Errors.Ok,
             "phase19 pass264 host certificate exposes matching CA for revocation checks");

      Status_Value := SSH_Lib.Protocol.Certificates.Host_Certificate_Signed_By_Public_Key
        (Certificate_Blob, "ssh-ed25519-cert-v01@openssh.com", Alternate_Key_Blob);
      Check (Status_Value = CryptoLib.Errors.Host_Key_Mismatch,
             "phase19 pass264 host certificate CA revocation helper rejects unrelated CA");

      Status_Value := SSH_Lib.Protocol.Certificates.Host_Certificate_Signed_By_Public_Key
        (CA_Key_Blob, "ssh-ed25519-cert-v01@openssh.com", CA_Key_Blob);
      Check (Status_Value /= CryptoLib.Errors.Ok,
             "phase19 pass264 raw key is not accepted as host certificate for CA revocation");

      Check
        (SSH_Lib.Protocol.Certificates.Host_Principals_Match_For_Test
           (Principal_List ("*.example.test"), "git.example.test", 22),
         "phase19 pass271 host certificate wildcard principal matches canonical host");
      Check
        (SSH_Lib.Protocol.Certificates.Host_Principals_Match_For_Test
           (Principal_List ("[*.example.test]:2222"), "git.example.test", 2222),
         "phase19 pass271 bracketed wildcard principal matches explicit non-default port");
      Check
        (not SSH_Lib.Protocol.Certificates.Host_Principals_Match_For_Test
           (Principal_List ("[*.example.test]:2222"), "git.example.test", 22),
         "phase19 pass271 bracketed wildcard principal does not match default-port host");
      Check
        (SSH_Lib.Protocol.Certificates.Host_Principals_Match_For_Test
           (Principal_List ("unrelated.example.test", "*.example.test"),
            "git.example.test", 22),
         "phase19 pass271 later wildcard principal is considered");
      Check
        (not SSH_Lib.Protocol.Certificates.Host_Principals_Match_For_Test
           (Principal_List ("*.example.test"), "git.bad.test", 22),
         "phase19 pass271 wildcard principal rejects unrelated host");
   end Assert_Host_Certificate_Revocation_Edges;

end SSH_Lib.Tests.Fixtures.Host_Key_Security;
