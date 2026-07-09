with Ada.Command_Line;
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.Strings.Fixed;
with Ada.Strings.Maps.Constants;
with Ada.Text_IO;

procedure Check_Package_Tree is
   use Ada.Strings.Fixed;
   use type Ada.Directories.File_Kind;
   Failure_Count : Natural := 0;
   Source_Worktree_Mode : constant Boolean :=
     Ada.Directories.Exists (".git")
     and then not
       (Ada.Environment_Variables.Exists ("SSH_LIB_PACKAGE_TREE_STRICT")
        and then Ada.Environment_Variables.Value ("SSH_LIB_PACKAGE_TREE_STRICT") = "1");

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   function Lower (Value : String) return String is
   begin
      return Ada.Strings.Fixed.Translate
        (Value, Ada.Strings.Maps.Constants.Lower_Case_Map);
   end Lower;

   function Has_Suffix (Value : String; Suffix : String) return Boolean is
   begin
      return Value'Length >= Suffix'Length
        and then Value (Value'Last - Suffix'Length + 1 .. Value'Last) = Suffix;
   end Has_Suffix;

   function Is_Forbidden_File (Path : String; Name_Text : String) return Boolean is
      Path_Lower : constant String := Lower (Path);
      Name_Lower : constant String := Lower (Name_Text);
   begin
      if Source_Worktree_Mode
        and then
          (Has_Suffix (Name_Lower, ".tmp")
           or else Has_Suffix (Name_Lower, ".log")
           or else Has_Suffix (Name_Lower, ".bak"))
      then
         return False;
      end if;

      return Name_Text = ".DS_Store"
        or else Has_Suffix (Name_Lower, ".o")
        or else Has_Suffix (Name_Lower, ".ali")
        or else Has_Suffix (Name_Lower, ".exe")
        or else Has_Suffix (Name_Lower, ".dll")
        or else Has_Suffix (Name_Lower, ".so")
        or else Has_Suffix (Name_Lower, ".dylib")
        or else Has_Suffix (Name_Lower, ".a")
        or else Has_Suffix (Name_Lower, ".tmp")
        or else Has_Suffix (Name_Lower, ".log")
        or else Has_Suffix (Name_Lower, ".bak")
        or else Has_Suffix (Name_Lower, ".swp")
        or else Index (Path_Lower, "ssh_auth_sock") /= 0
        or else Index (Path_Lower, "/.ssh/") /= 0
        or else Name_Lower = "known_hosts"
        or else Name_Lower = "known_hosts.old"
        or else Name_Lower = "id_rsa"
        or else Name_Lower = "id_ed25519";
   end Is_Forbidden_File;

   function Is_Forbidden_Directory (Name_Text : String) return Boolean is
   begin
      if Source_Worktree_Mode
        and then
          (Name_Text = ".git"
           or else Name_Text = "obj"
           or else Name_Text = "bin"
           or else Name_Text = "coverage")
      then
         return False;
      end if;

      return Name_Text = ".git"
        or else Name_Text = "obj"
        or else Name_Text = "bin"
        or else Name_Text = "coverage";
   end Is_Forbidden_Directory;

   procedure Scan (Directory_Path : String) is
      Search_Item : Ada.Directories.Search_Type;
      Directory_Item : Ada.Directories.Directory_Entry_Type;
   begin
      Ada.Directories.Start_Search
        (Search    => Search_Item,
         Directory => Directory_Path,
         Pattern   => "*",
         Filter    => [Ada.Directories.Ordinary_File => True,
                       Ada.Directories.Directory => True,
                       Ada.Directories.Special_File => True]);

      while Ada.Directories.More_Entries (Search_Item) loop
         Ada.Directories.Get_Next_Entry (Search_Item, Directory_Item);
         declare
            Full_Path : constant String := Ada.Directories.Full_Name (Directory_Item);
            Name_Text : constant String := Ada.Directories.Simple_Name (Directory_Item);
            Kind_Value : constant Ada.Directories.File_Kind :=
              Ada.Directories.Kind (Directory_Item);
         begin
            if Kind_Value = Ada.Directories.Directory then
               if Source_Worktree_Mode
                 and then
                   (Name_Text = ".git"
                    or else Name_Text = "obj"
                    or else Name_Text = "bin"
                    or else Name_Text = "coverage")
               then
                  null;
               elsif Is_Forbidden_Directory (Name_Text) then
                  Fail ("forbidden directory in package tree: " & Full_Path);
               elsif Name_Text /= "." and then Name_Text /= ".." then
                  Scan (Full_Path);
               end if;
            elsif Kind_Value = Ada.Directories.Special_File then
               Fail ("special file is not allowed in package tree: " & Full_Path);
            elsif Is_Forbidden_File (Full_Path, Name_Text) then
               Fail ("forbidden file in package tree: " & Full_Path);
            end if;
         end;
      end loop;

      Ada.Directories.End_Search (Search_Item);
   exception
      when others =>
         if Ada.Directories.More_Entries (Search_Item) then
            Ada.Directories.End_Search (Search_Item);
         end if;
         Fail ("unable to scan directory: " & Directory_Path);
   end Scan;

begin
   Scan (".");

   if Ada.Directories.Exists ("tests/fixtures/keys")
     and then not Ada.Directories.Exists ("tests/fixtures/keys/README.md")
   then
      Fail ("test fixture keys require tests/fixtures/keys/README.md");
   end if;

   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("package tree guard passed");
   else
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Package_Tree;
