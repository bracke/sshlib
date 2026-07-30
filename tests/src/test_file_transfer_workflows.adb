with Ada.Directories;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Interfaces;
with GNAT.Directory_Operations;

with Hostkit.Fs;

with CryptoLib.Errors;
with CryptoLib.Hashes;

with SSH_Lib.File_Transfer;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.SFTP;
with SSH_Lib.Channels;
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

   --  Ada.Directories.Delete_Tree cannot remove a tree holding a dangling
   --  symlink: it asks each entry its Kind, which follows the link and raises
   --  when the target is not there. This used to be Delete_Tree under a
   --  "when others => null", so the failure was silent, the tree survived, and
   --  the next run of the suite failed creating the link again with EEXIST.
   --  That is what it did -- the symlink check below passed once, on a machine
   --  that had never run it, and failed on every run afterwards. Unlink links
   --  rather than descending through them, and let a real failure raise.
   procedure Remove_Local_Tree_If_Exists (Path : String) is

      procedure Remove (Item : String);

      procedure Remove (Item : String) is
         Handle : GNAT.Directory_Operations.Dir_Type;
         Name   : String (1 .. 1024);
         Last   : Natural;
      begin
         --  Asked before Exists, which answers False for a dangling link.
         if Hostkit.Fs.Is_Link (Item) then
            if not Hostkit.Fs.Delete_Link (Item) then
               raise Program_Error with "cannot unlink " & Item;
            end if;
            return;
         end if;

         if not Ada.Directories.Exists (Item) then
            return;
         end if;

         if Ada.Directories."=" (Ada.Directories.Kind (Item),
                                  Ada.Directories.Directory)
         then
            --  Read the directory with GNAT.Directory_Operations rather than
            --  Ada.Directories: the latter stats every entry and silently
            --  drops the ones it cannot stat (a-direct.adb appends an entry
            --  only when the attribute call errored or the file exists), so a
            --  dangling symlink is not merely mis-Kinded, it is not listed at
            --  all. Deleting what you can see then leaves the directory
            --  non-empty and Delete_Directory fails. readdir does not stat.
            GNAT.Directory_Operations.Open (Handle, Item);
            loop
               GNAT.Directory_Operations.Read (Handle, Name, Last);
               exit when Last = 0;
               declare
                  Simple : constant String := Name (1 .. Last);
               begin
                  if Simple /= "." and then Simple /= ".." then
                     Remove (Ada.Directories.Compose (Item, Simple));
                  end if;
               end;
            end loop;
            GNAT.Directory_Operations.Close (Handle);
            Ada.Directories.Delete_Directory (Item);
         else
            Ada.Directories.Delete_File (Item);
         end if;
      end Remove;

   begin
      Remove (Path);
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

   --  A dangling symlink already at the target path. This is the ordinary
   --  case, not an exotic one: restoring a tree writes each link when its
   --  inventory entry comes up, so a link whose target is later in the tree
   --  -- or outside it -- dangles until the target arrives, and re-running a
   --  restore meets it. Ada.Directories.Exists follows the link and answers
   --  False, so the conflict policy used to see nothing to resolve and
   --  symlink() then failed EEXIST under every policy: Overwrite_Existing
   --  reported Remote_Failure rather than overwriting.
   Remove_Local_Tree_If_Exists ("/tmp/ssh_lib_restore_symlink");
   Ada.Directories.Create_Path ("/tmp/ssh_lib_restore_symlink");
   Check
     (Hostkit.Fs.Create_Link
        ("nowhere.txt", "/tmp/ssh_lib_restore_symlink/link.txt"),
      "a dangling symlink can be planted for the conflict test");
   Check
     (not Ada.Directories.Exists ("/tmp/ssh_lib_restore_symlink/link.txt")
        and then Hostkit.Fs.Is_Link ("/tmp/ssh_lib_restore_symlink/link.txt"),
      "and Exists does not see it while Is_Link does");
   Result := SSH_Lib.File_Transfer.Restore_From_Inventory
     (Session,
      Parsed,
      "/remote/source",
      "/tmp/ssh_lib_restore_symlink",
      SSH_Lib.File_Transfer.Overwrite_Existing);
   Check
     (Result.Status = CryptoLib.Errors.Ok and then Result.Items_Processed = 1,
      "restore overwrites a dangling symlink rather than failing EEXIST");
   declare
      Link_Target : Ada.Strings.Unbounded.Unbounded_String;
   begin
      Check
        (Hostkit.Fs.Read_Link_Target
           ("/tmp/ssh_lib_restore_symlink/link.txt", Link_Target)
           and then Ada.Strings.Unbounded.To_String (Link_Target)
                      = "target.txt",
         "and the overwritten link points at the inventory target");
   end;

   --  The other two policies must now see it too.
   Result := SSH_Lib.File_Transfer.Restore_From_Inventory
     (Session,
      Parsed,
      "/remote/source",
      "/tmp/ssh_lib_restore_symlink",
      SSH_Lib.File_Transfer.Skip_Existing);
   Check
     (Result.Status = CryptoLib.Errors.Ok and then Result.Items_Processed = 1,
      "restore skips an existing symlink instead of failing on it");
   Result := SSH_Lib.File_Transfer.Restore_From_Inventory
     (Session,
      Parsed,
      "/remote/source",
      "/tmp/ssh_lib_restore_symlink",
      SSH_Lib.File_Transfer.Fail_If_Exists);
   Check
     (Result.Status = CryptoLib.Errors.Remote_Failure,
      "and Fail_If_Exists refuses an existing symlink");
   Remove_Local_Tree_If_Exists ("/tmp/ssh_lib_restore_symlink");

   --  Sync_Directory with Delete_Extra clears the local tree before it
   --  downloads. It used to do that with Ada.Directories.Delete_Tree, which
   --  asks GNAT.OS_Lib.Is_Directory about each entry -- a stat, so it follows
   --  a link. A symbolic link to a directory inside the tree was therefore
   --  recursed into and the link *target's* contents deleted: files outside
   --  the tree the caller asked to remove. That is the check below, and it
   --  fails loudly if the old call comes back.
   --
   --  The channel is never connected. It does not need to be: the deletion
   --  happens before the first byte of SFTP traffic, so the download failing
   --  afterwards is expected and says nothing about what is being tested.
   declare
      Channel   : SSH_Lib.Channels.Channel;
      Root      : constant String := "/tmp/ssh_lib_sync_delete";
      Tree      : constant String := Root & "/tree";
      Outside   : constant String := Root & "/outside";
      Precious  : constant String := Outside & "/precious.txt";
      Options   : SSH_Lib.SFTP.Sync_Options :=
        SSH_Lib.SFTP.Default_Sync_Options;
      Sync_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Sync_Status);
   begin
      Remove_Local_Tree_If_Exists (Root);
      Ada.Directories.Create_Path (Tree & "/sub");
      Ada.Directories.Create_Path (Outside);
      Write_Test_File (Precious, Bytes_From_String ("precious"));
      Write_Test_File
        (Tree & "/sub/inner.txt", Bytes_From_String ("inner"));
      Check
        (Hostkit.Fs.Create_Link (Outside, Tree & "/linkdir"),
         "a link to a directory outside the tree can be planted");
      Check
        (Hostkit.Fs.Create_Link ("/nowhere/at/all", Tree & "/dangling"),
         "and a dangling link beside it");

      Options.Delete_Extra := True;
      Sync_Status := SSH_Lib.SFTP.Sync_Directory
        (Channel,
         SSH_Lib.SFTP.Sync_Download,
         "/remote/tree",
         Tree,
         Options => Options);

      --  The tree's contents are what Delete_Extra clears. The root itself
      --  comes back empty: Download_Directory calls Create_Path on the local
      --  path before it fetches anything, so asking whether the root exists
      --  says nothing either way.
      Check
        (not Ada.Directories.Exists (Tree & "/sub"),
         "Delete_Extra clears the local tree's contents");
      Check
        (not Hostkit.Fs.Is_Link (Tree & "/dangling"),
         "including a dangling link, which Delete_Tree could not remove");
      Check
        (not Hostkit.Fs.Is_Link (Tree & "/linkdir"),
         "and the link to a directory outside the tree");
      Check
        (Ada.Directories.Exists (Precious),
         "but it does not follow that link out and delete what it points at");
      Remove_Local_Tree_If_Exists (Root);
   end;

   SSH_Lib.Protocol.Buffers.Clear (Result.Digest);
   Ada.Text_IO.Put_Line ("test_file_transfer_workflows passed");
end Test_File_Transfer_Workflows;
