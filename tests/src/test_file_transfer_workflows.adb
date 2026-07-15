with Ada.Directories;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with GNAT.OS_Lib;
with Interfaces;

with Hostkit.Fs;

with CryptoLib.Errors;
with CryptoLib.Hashes;

with SSH_Lib.File_Transfer;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.SFTP;
with SSH_Lib.Sessions;

procedure Test_File_Transfer_Workflows is
   use Ada.Strings.Unbounded;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.Errors.Status;
   use type Interfaces.Unsigned_64;
   use type SSH_Lib.File_Transfer.Inventory_Entry_Kind;

   procedure Check (Condition : Boolean; Message : String) is
   begin
      if not Condition then
         raise Program_Error with Message;
      end if;
   end Check;

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

   function SHA256_Array
     (Data : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array
   is
      Digest : constant CryptoLib.Hashes.SHA256_Digest :=
        CryptoLib.Hashes.SHA256 (Data);
      Result : Ada.Streams.Stream_Element_Array (1 .. 32);
   begin
      for Index in Digest'Range loop
         Result (Ada.Streams.Stream_Element_Offset (Index)) := Digest (Index);
      end loop;
      return Result;
   end SHA256_Array;

   procedure Remove_Local_Tree_If_Exists (Path : String) is
   begin
      if Ada.Directories.Exists (Path) then
         Ada.Directories.Delete_Tree (Path);
      end if;
   exception
      when others =>
         null;
   end Remove_Local_Tree_If_Exists;

   procedure Check_Bad_Manifest (Manifest_Text : String) is
      Parsed_Bad : SSH_Lib.File_Transfer.Inventory_Result;
      Status_Bad : CryptoLib.Errors.Status;
   begin
      Status_Bad := SSH_Lib.File_Transfer.Parse_Inventory_Manifest
        (Manifest_Text, Parsed_Bad);
      Check (Status_Bad = CryptoLib.Errors.Read_Failed,
             "malformed digest manifest rejected");
   end Check_Bad_Manifest;

   function Make_Entry
     (Path             : String;
      Kind             : SSH_Lib.File_Transfer.Inventory_Entry_Kind;
      Size             : Interfaces.Unsigned_64 := 0;
      Size_Known       : Boolean := False;
      Digest_Algorithm : String := "";
      Digest_Data      : Ada.Streams.Stream_Element_Array :=
        Ada.Streams.Stream_Element_Array'(1 .. 0 => 0);
      Link_Target      : String := "")
      return SSH_Lib.File_Transfer.Inventory_Entry
   is
      Attributes : SSH_Lib.SFTP.File_Attributes;
      Digest     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status     : CryptoLib.Errors.Status;
   begin
      Attributes := (others => <>);
      Attributes.Size_Known := Size_Known;
      Attributes.Size := Size;
      if Digest_Data'Length > 0 then
         Status := SSH_Lib.Protocol.Buffers.Set (Digest, Digest_Data);
         Check (Status = CryptoLib.Errors.Ok, "digest fixture accepted");
      else
         SSH_Lib.Protocol.Buffers.Clear (Digest);
      end if;
      return
        (Path             => To_Unbounded_String (Path),
         Kind             => Kind,
         Attributes       => Attributes,
         Link_Target      => To_Unbounded_String (Link_Target),
         Digest_Algorithm => To_Unbounded_String (Digest_Algorithm),
         Digest           => Digest);
   end Make_Entry;

   Inventory : SSH_Lib.File_Transfer.Inventory_Result;
   Parsed    : SSH_Lib.File_Transfer.Inventory_Result;
   Manifest  : Unbounded_String;
   Status    : CryptoLib.Errors.Status;
   Session   : SSH_Lib.Sessions.Session;
   Result    : SSH_Lib.File_Transfer.Workflow_Result;
   Bad_Manifest : Unbounded_String;
begin
   Inventory.Result.Operation := SSH_Lib.File_Transfer.Inventory_Workflow;
   Inventory.Result.Status := CryptoLib.Errors.Ok;
   Inventory.Entries.Append
     (Make_Entry
        ("/remote/root",
         SSH_Lib.File_Transfer.Inventory_Directory));
   Inventory.Entries.Append
     (Make_Entry
        ("/remote/root/file%" & Character'Val (9) & "name",
         SSH_Lib.File_Transfer.Inventory_File,
         42,
         True,
         "sha256",
         Ada.Streams.Stream_Element_Array'(1 => 16#AB#, 2 => 16#CD#)));
   Inventory.Entries.Append
     (Make_Entry
        ("/remote/root/link",
         SSH_Lib.File_Transfer.Inventory_Symlink,
         Link_Target => "file%" & Character'Val (9) & "name"));

   Manifest := SSH_Lib.File_Transfer.Inventory_Manifest (Inventory);
   Check
     (Index (Manifest, "SSH_LIB_INVENTORY" & Character'Val (9) & "3") = 1,
      "manifest header");
   Check (Index (Manifest, "%25%09") /= 0, "manifest escaping");
   Check (Index (Manifest, "link" & Character'Val (9) & "file%25%09name") /= 0,
          "manifest preserves symlink target");

   Status := SSH_Lib.File_Transfer.Parse_Inventory_Manifest
     (To_String (Manifest), Parsed);
   Check (Status = CryptoLib.Errors.Ok, "manifest parses");
   Check (Natural (Parsed.Entries.Length) = 3, "manifest entry count");
   Check
     (To_String (Parsed.Entries.Element (1).Path) =
      "/remote/root/file%" & Character'Val (9) & "name",
      "manifest unescapes path");
   Check
     (Parsed.Entries.Element (1).Attributes.Size_Known
      and then Parsed.Entries.Element (1).Attributes.Size = 42,
      "manifest preserves size");
   Check
     (To_String (Parsed.Entries.Element (1).Digest_Algorithm) = "sha256",
      "manifest preserves digest algorithm");
   Check
     (SSH_Lib.Protocol.Buffers.Length (Parsed.Entries.Element (1).Digest) = 2,
      "manifest preserves digest bytes");
   Check
     (Parsed.Entries.Element (2).Kind = SSH_Lib.File_Transfer.Inventory_Symlink
      and then To_String (Parsed.Entries.Element (2).Link_Target) =
        "file%" & Character'Val (9) & "name",
      "manifest round-trips symlink target");

   Status := SSH_Lib.File_Transfer.Parse_Inventory_Manifest
     ("SSH_LIB_INVENTORY" & Character'Val (9) & "1"
      & Character'Val (10) & "F" & Character'Val (9) & "7"
      & Character'Val (9) & "/legacy/file" & Character'Val (10),
      Parsed);
   Check (Status = CryptoLib.Errors.Ok, "legacy manifest parses");
   Check
     (Natural (Parsed.Entries.Length) = 1
      and then To_String (Parsed.Entries.Element (0).Path) = "/legacy/file",
      "legacy manifest path");

   Status := SSH_Lib.File_Transfer.Parse_Inventory_Manifest
     ("not-a-manifest", Parsed);
   Check (Status = CryptoLib.Errors.Read_Failed, "invalid manifest rejected");

   Check_Bad_Manifest
     ("SSH_LIB_INVENTORY" & Character'Val (9) & "2" & Character'Val (10)
      & "F" & Character'Val (9) & "1" & Character'Val (9) & "sha256"
      & Character'Val (9) & "ABC" & Character'Val (9) & "/bad/hex"
      & Character'Val (10));
   Check_Bad_Manifest
     ("SSH_LIB_INVENTORY" & Character'Val (9) & "2" & Character'Val (10)
      & "F" & Character'Val (9) & "1" & Character'Val (9) & "-"
      & Character'Val (9) & "AB" & Character'Val (9) & "/missing/algorithm"
      & Character'Val (10));
   Check_Bad_Manifest
     ("SSH_LIB_INVENTORY" & Character'Val (9) & "2" & Character'Val (10)
      & "F" & Character'Val (9) & "1" & Character'Val (9) & "sha256"
      & Character'Val (9) & "-" & Character'Val (9) & "/missing/digest"
      & Character'Val (10));
   Check_Bad_Manifest
     ("SSH_LIB_INVENTORY" & Character'Val (9) & "2" & Character'Val (10)
      & "F" & Character'Val (9) & "1" & Character'Val (9) & "-"
      & Character'Val (9) & "-" & Character'Val (9) & "/extra"
      & Character'Val (9) & "tab" & Character'Val (10));
   Check_Bad_Manifest
     ("SSH_LIB_INVENTORY" & Character'Val (9) & "3" & Character'Val (10)
      & "L" & Character'Val (9) & "-" & Character'Val (9) & "-"
      & Character'Val (9) & "-" & Character'Val (9) & "/missing-target"
      & Character'Val (9) & "-" & Character'Val (10));
   Check_Bad_Manifest
     ("SSH_LIB_INVENTORY" & Character'Val (9) & "3" & Character'Val (10)
      & "F" & Character'Val (9) & "1" & Character'Val (9) & "-"
      & Character'Val (9) & "-" & Character'Val (9) & "/file"
      & Character'Val (9) & "unexpected-target" & Character'Val (10));

   Bad_Manifest := To_Unbounded_String
     ("SSH_LIB_INVENTORY" & Character'Val (9) & "2" & Character'Val (10)
      & "F" & Character'Val (9) & "1" & Character'Val (9) & "-"
      & Character'Val (9) & "-" & Character'Val (9) & "/dup"
      & Character'Val (10)
      & "F" & Character'Val (9) & "1" & Character'Val (9) & "-"
      & Character'Val (9) & "-" & Character'Val (9) & "/dup"
      & Character'Val (10));
   Status := SSH_Lib.File_Transfer.Parse_Inventory_Manifest
     (To_String (Bad_Manifest), Parsed);
   Check (Status = CryptoLib.Errors.Read_Failed,
          "duplicate manifest path rejected");

   Result := SSH_Lib.File_Transfer.Restore_From_Inventory
     (Session,
      Inventory,
      "/different/root",
      "/tmp/ssh_lib_restore_target");
   Check
     (Result.Status = CryptoLib.Errors.Invalid_Command,
      "restore rejects inventory outside source root before network I/O");

   Remove_Local_Tree_If_Exists ("/tmp/ssh_lib_restore_verified");
   Ada.Directories.Create_Path ("/tmp/ssh_lib_restore_verified");
   Write_Test_File
     ("/tmp/ssh_lib_restore_verified/file.txt",
      Bytes_From_String ("verified-local"));
   Parsed := (others => <>);
   Parsed.Result.Operation := SSH_Lib.File_Transfer.Inventory_Workflow;
   Parsed.Result.Status := CryptoLib.Errors.Ok;
   Parsed.Entries.Append
     (Make_Entry
        ("/remote/source/file.txt",
         SSH_Lib.File_Transfer.Inventory_File,
         14,
         True,
         "sha256",
         SHA256_Array (Bytes_From_String ("verified-local"))));
   Result := SSH_Lib.File_Transfer.Restore_From_Inventory
     (Session,
      Parsed,
      "/remote/source",
      "/tmp/ssh_lib_restore_verified",
      SSH_Lib.File_Transfer.Skip_Existing);
   Check
     (Result.Status = CryptoLib.Errors.Ok and then Result.Verified,
      "restore verifies skipped local digest");
   Parsed.Entries.Replace_Element
     (0,
      Make_Entry
        ("/remote/source/file.txt",
         SSH_Lib.File_Transfer.Inventory_File,
         14,
         True,
         "sha256",
         SHA256_Array (Bytes_From_String ("different-data"))));
   Result := SSH_Lib.File_Transfer.Restore_From_Inventory
     (Session,
      Parsed,
      "/remote/source",
      "/tmp/ssh_lib_restore_verified",
      SSH_Lib.File_Transfer.Skip_Existing);
   Check
     (Result.Status = CryptoLib.Errors.Remote_Failure,
      "restore rejects skipped file with mismatched digest");
   Remove_Local_Tree_If_Exists ("/tmp/ssh_lib_restore_verified");

   Ada.Directories.Create_Path ("/tmp/ssh_lib_restore_verified");
   Write_Test_File
     ("/tmp/ssh_lib_restore_verified/empty.bin",
      Ada.Streams.Stream_Element_Array'(1 .. 0 => 0));
   Parsed := (others => <>);
   Parsed.Result.Operation := SSH_Lib.File_Transfer.Inventory_Workflow;
   Parsed.Result.Status := CryptoLib.Errors.Ok;
   Parsed.Entries.Append
     (Make_Entry
        ("/remote/source/empty.bin",
         SSH_Lib.File_Transfer.Inventory_File,
         0,
         True,
         "md5",
         Ada.Streams.Stream_Element_Array'
           (1  => 16#D4#, 2  => 16#1D#, 3  => 16#8C#, 4  => 16#D9#,
            5  => 16#8F#, 6  => 16#00#, 7  => 16#B2#, 8  => 16#04#,
            9  => 16#E9#, 10 => 16#80#, 11 => 16#09#, 12 => 16#98#,
            13 => 16#EC#, 14 => 16#F8#, 15 => 16#42#, 16 => 16#7E#)));
   Result := SSH_Lib.File_Transfer.Restore_From_Inventory
     (Session,
      Parsed,
      "/remote/source",
      "/tmp/ssh_lib_restore_verified",
      SSH_Lib.File_Transfer.Skip_Existing);
   Check
     (Result.Status = CryptoLib.Errors.Ok and then Result.Verified,
      "restore verifies skipped local md5 digest");
   Parsed.Entries.Replace_Element
     (0,
      Make_Entry
        ("/remote/source/empty.bin",
         SSH_Lib.File_Transfer.Inventory_File,
         0,
         True,
         "sha3-256",
         SHA256_Array (Bytes_From_String (""))));
   Result := SSH_Lib.File_Transfer.Restore_From_Inventory
     (Session,
      Parsed,
      "/remote/source",
      "/tmp/ssh_lib_restore_verified",
      SSH_Lib.File_Transfer.Skip_Existing);
   Check
     (Result.Status = CryptoLib.Errors.Remote_Failure,
      "restore rejects unsupported local digest algorithm");
   Remove_Local_Tree_If_Exists ("/tmp/ssh_lib_restore_verified");

   Remove_Local_Tree_If_Exists ("/tmp/ssh_lib_restore_symlink");
   Parsed := (others => <>);
   Parsed.Result.Operation := SSH_Lib.File_Transfer.Inventory_Workflow;
   Parsed.Result.Status := CryptoLib.Errors.Ok;
   Parsed.Entries.Append
     (Make_Entry
        ("/remote/source/link.txt",
         SSH_Lib.File_Transfer.Inventory_Symlink,
         Link_Target => "target.txt"));
   Result := SSH_Lib.File_Transfer.Restore_From_Inventory
     (Session,
      Parsed,
      "/remote/source",
      "/tmp/ssh_lib_restore_symlink");
   Check
     (Result.Status = CryptoLib.Errors.Ok and then Result.Items_Processed = 1,
      "restore creates local symlink from inventory target");
   --  Hostkit.Fs.Is_Link, not GNAT.OS_Lib.Is_Symbolic_Link: the latter answers False
   --  for every path on Windows (it wants an lstat there is none of), so it would fail a
   --  link that was created just fine.
   Check
     (Hostkit.Fs.Is_Link ("/tmp/ssh_lib_restore_symlink/link.txt"),
      "restored inventory symlink is a local symbolic link");
   Remove_Local_Tree_If_Exists ("/tmp/ssh_lib_restore_symlink");

   SSH_Lib.Protocol.Buffers.Clear (Result.Digest);
   Ada.Text_IO.Put_Line ("test_file_transfer_workflows passed");
end Test_File_Transfer_Workflows;
