with Ada.Directories;
with Ada.Streams.Stream_IO;
with Ada.Text_IO;
with Ada.Unchecked_Deallocation;
with CryptoLib.Hashes;
with GNAT.Expect;
with GNAT.OS_Lib;
with Interfaces;
with Interfaces.C;
with SSH_Lib.Protocol.Channels;
with Zlib;

package body SSH_Lib.Git is
   use CryptoLib.Errors;
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use SSH_Lib.Protocol.Buffers;
   use type Ada.Directories.File_Size;
   use type Ada.Streams.Stream_IO.Count;
   use type GNAT.OS_Lib.File_Descriptor;
   use type GNAT.OS_Lib.String_Access;
   use type Interfaces.C.int;
   package Stream_IO renames Ada.Streams.Stream_IO;
   Maximum_Packed_Refs_File_Length : constant Stream_IO.Count := 1_048_576;
   Maximum_Reflog_File_Length : constant Stream_IO.Count := 1_048_576;
   Maximum_Config_File_Length : constant Stream_IO.Count := 1_048_576;
   Maximum_Index_File_Length : constant Stream_IO.Count := 16_777_216;
   Maximum_Worktree_File_Length : constant Natural := 1_048_576;
   Maximum_Credential_Helper_Output_Length : constant Natural := 65_536;

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

   type Tree_Traversal_Scratch is record
      Pack_Checksums_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length * 16));
      Pack_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Index_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Base_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Delta_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Workspace : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Pack_Checksum_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
   end record;

   type Tree_Traversal_Scratch_Access is access Tree_Traversal_Scratch;
   procedure Free_Tree_Traversal_Scratch is new Ada.Unchecked_Deallocation
     (Tree_Traversal_Scratch, Tree_Traversal_Scratch_Access);

   function Hex_Value (Item : Stream_Element) return Natural is
   begin
      if Item >= Character'Pos ('0')
        and then Item <= Character'Pos ('9')
      then
         return Natural (Item - Character'Pos ('0'));
      elsif Item >= Character'Pos ('a')
        and then Item <= Character'Pos ('f')
      then
         return 10 + Natural (Item - Character'Pos ('a'));
      elsif Item >= Character'Pos ('A')
        and then Item <= Character'Pos ('F')
      then
         return 10 + Natural (Item - Character'Pos ('A'));
      else
         return 16;
      end if;
   exception
      when others =>
         return 16;
   end Hex_Value;

   function Hex_Digit (Value : Natural) return Stream_Element is
   begin
      if Value < 10 then
         return Stream_Element (Character'Pos ('0') + Value);
      else
         return Stream_Element (Character'Pos ('a') + Value - 10);
      end if;
   end Hex_Digit;

   function Valid_Repository_Root (Path : String) return Boolean is
   begin
      if Path'Length = 0
        or else Path'Length > Maximum_Repository_Path_Length
      then
         return False;
      end if;

      for Ch of Path loop
         if Ch = Character'Val (0)
           or else Ch = Character'Val (10)
           or else Ch = Character'Val (13)
         then
            return False;
         end if;
      end loop;
      return True;
   exception
      when others =>
         return False;
   end Valid_Repository_Root;

   function Valid_Worktree_Path (Path : String) return Boolean is
      Component_First : Positive := Path'First;

      function Bad_Component (First, Last : Positive) return Boolean is
      begin
         return
           First > Last
           or else (First = Last and then Path (First) = '.')
           or else
             (Last = First + 1
              and then Path (First) = '.'
              and then Path (Last) = '.');
      end Bad_Component;
   begin
      if Path'Length = 0
        or else Path'Length > Maximum_Ref_Name_Length
        or else Path (Path'First) = '/'
        or else Path (Path'Last) = '/'
      then
         return False;
      end if;

      for Index in Path'Range loop
         if Path (Index) = Character'Val (0)
           or else Path (Index) = Character'Val (10)
           or else Path (Index) = Character'Val (13)
         then
            return False;
         elsif Path (Index) = '/' then
            if Bad_Component (Component_First, Index - 1) then
               return False;
            end if;
            Component_First := Index + 1;
         end if;
      end loop;

      return not Bad_Component (Component_First, Path'Last);
   exception
      when others =>
         return False;
   end Valid_Worktree_Path;

   function Pathspec_Matches
     (Path     : String;
      Pathspec : String;
      Matches  : out Boolean)
      return Status
   is
      function Valid_Pathspec_Text return Boolean is
         Component_First : Positive := Pathspec'First;
         Effective_Last  : Natural := Pathspec'Last;
         Wildcard_Count  : Natural := 0;

         function Bad_Component (First, Last : Natural) return Boolean is
         begin
            return
              First > Last
              or else (First = Last and then Pathspec (First) = '.')
              or else
                (Last = First + 1
                 and then Pathspec (First) = '.'
                 and then Pathspec (Last) = '.');
         end Bad_Component;
      begin
         if Pathspec = "." then
            return True;
         elsif Pathspec'Length = 0
           or else Pathspec'Length > Maximum_Ref_Name_Length
           or else Pathspec (Pathspec'First) = '/'
         then
            return False;
         end if;

         if Pathspec (Pathspec'Last) = '/' then
            if Pathspec'Length = 1 then
               return False;
            end if;
            Effective_Last := Pathspec'Last - 1;
         end if;

         for Index in Pathspec'First .. Effective_Last loop
            if Pathspec (Index) = Character'Val (0)
              or else Pathspec (Index) = Character'Val (10)
              or else Pathspec (Index) = Character'Val (13)
            then
               return False;
            elsif Pathspec (Index) = '*' then
               Wildcard_Count := Wildcard_Count + 1;
               if Wildcard_Count > 1 then
                  return False;
               end if;
            elsif Pathspec (Index) = '/' then
               if Bad_Component (Component_First, Index - 1) then
                  return False;
               end if;
               Component_First := Index + 1;
            end if;
         end loop;

         return not Bad_Component (Component_First, Effective_Last);
      exception
         when others =>
            return False;
      end Valid_Pathspec_Text;

      function Single_Wildcard_Matches (Pattern, Text : String) return Boolean is
         Star : Natural := 0;
      begin
         for Index in Pattern'Range loop
            if Pattern (Index) = '*' then
               Star := Index;
               exit;
            end if;
         end loop;

         if Star = 0 then
            return Pattern = Text;
         end if;

         declare
            Prefix_Length : constant Natural := Star - Pattern'First;
            Suffix_Length : constant Natural := Pattern'Last - Star;
         begin
            if Text'Length < Prefix_Length + Suffix_Length then
               return False;
            end if;

            if Prefix_Length > 0 then
               for Offset in 0 .. Prefix_Length - 1 loop
                  if Text (Text'First + Offset)
                    /= Pattern (Pattern'First + Offset)
                  then
                     return False;
                  end if;
               end loop;
            end if;

            if Suffix_Length > 0 then
               for Offset in 0 .. Suffix_Length - 1 loop
                  if Text (Text'Last - Suffix_Length + 1 + Offset)
                    /= Pattern (Star + 1 + Offset)
                  then
                     return False;
                  end if;
               end loop;
            end if;
            return True;
         end;
      exception
         when others =>
            return False;
      end Single_Wildcard_Matches;
   begin
      Matches := False;
      if not Valid_Worktree_Path (Path)
        or else not Valid_Pathspec_Text
      then
         return Invalid_Command;
      end if;

      if Pathspec = "." then
         Matches := True;
      elsif Pathspec (Pathspec'Last) = '/' then
         Matches :=
           Path'Length > Pathspec'Length
           and then Path (Path'First .. Path'First + Pathspec'Length - 1)
             = Pathspec;
      else
         Matches := Single_Wildcard_Matches (Pathspec, Path);
      end if;
      return Ok;
   exception
      when Constraint_Error =>
         Matches := False;
         return Invalid_Command;
      when others =>
         Matches := False;
         return Internal_Error;
   end Pathspec_Matches;

   function Git_Directory (Repository_Root : String) return String is
   begin
      return Ada.Directories.Compose (Repository_Root, ".git");
   end Git_Directory;

   function Git_Path
     (Repository_Root : String;
      Relative_Path   : String)
      return String
   is
   begin
      return Git_Directory (Repository_Root) & "/" & Relative_Path;
   end Git_Path;

   function Worktree_Path
     (Repository_Root : String;
      Relative_Path   : String)
      return String
   is
      Result          : Unbounded_String := To_Unbounded_String (Repository_Root);
      Component_First : Positive := Relative_Path'First;
   begin
      for Index in Relative_Path'Range loop
         if Relative_Path (Index) = '/' then
            Result :=
              To_Unbounded_String
                (Ada.Directories.Compose
                   (To_String (Result),
                    Relative_Path (Component_First .. Index - 1)));
            Component_First := Index + 1;
         end if;
      end loop;

      return
        Ada.Directories.Compose
          (To_String (Result),
           Relative_Path (Component_First .. Relative_Path'Last));
   end Worktree_Path;

   function Config_File_Path (Repository_Root : String) return String is
   begin
      return Git_Path (Repository_Root, "config");
   end Config_File_Path;

   function Index_File_Path (Repository_Root : String) return String is
   begin
      return Git_Path (Repository_Root, "index");
   end Index_File_Path;

   function Kind_Name (Kind : Pack_Object_Kind) return String is
   begin
      case Kind is
         when Pack_Commit =>
            return "commit";
         when Pack_Tree =>
            return "tree";
         when Pack_Blob =>
            return "blob";
         when Pack_Tag =>
            return "tag";
         when others =>
            return "";
      end case;
   end Kind_Name;

   function Kind_From_Name
     (Name : String;
      Kind : out Pack_Object_Kind)
      return Boolean
   is
   begin
      Kind := Pack_Blob;
      if Name = "commit" then
         Kind := Pack_Commit;
      elsif Name = "tree" then
         Kind := Pack_Tree;
      elsif Name = "blob" then
         Kind := Pack_Blob;
      elsif Name = "tag" then
         Kind := Pack_Tag;
      else
         return False;
      end if;
      return True;
   exception
      when others =>
         Kind := Pack_Blob;
         return False;
   end Kind_From_Name;

   function Hex_Character (Item : Character) return Boolean is
   begin
      return
        (Item in '0' .. '9')
        or else (Item in 'a' .. 'f')
        or else (Item in 'A' .. 'F');
   exception
      when others =>
         return False;
   end Hex_Character;

   function Ends_With
     (Text   : String;
      Suffix : String)
      return Boolean
   is
   begin
      if Text'Length < Suffix'Length then
         return False;
      end if;
      return Text (Text'Last - Suffix'Length + 1 .. Text'Last) = Suffix;
   exception
      when others =>
         return False;
   end Ends_With;

   function Safe_Ref_Component (Component : String) return Boolean is
   begin
      if Component'Length = 0
        or else Component (Component'First) = '.'
        or else Ends_With (Component, ".lock")
      then
         return False;
      end if;

      return True;
   exception
      when others =>
         return False;
   end Safe_Ref_Component;

   function Encode_Header
     (Packet_Length : Natural)
      return Stream_Element_Array
   is
   begin
      return
        [1 => Hex_Digit ((Packet_Length / 4096) mod 16),
         2 => Hex_Digit ((Packet_Length / 256) mod 16),
         3 => Hex_Digit ((Packet_Length / 16) mod 16),
         4 => Hex_Digit (Packet_Length mod 16)];
   end Encode_Header;

   function Encode_Special_Pkt_Line
     (Packet_Length : Natural)
      return Packet_Buffer
   is
      Result : Packet_Buffer;
      Ignored_Status : Status;
   begin
      if Packet_Length > 2 then
         return Result;
      end if;

      Ignored_Status := Append (Result, Encode_Header (Packet_Length));
      return Result;
   exception
      when others =>
         return Result;
   end Encode_Special_Pkt_Line;

   function U32_At
     (Data  : Stream_Element_Array;
      First : Stream_Element_Offset)
      return Natural
   is
      Value : Natural := 0;
   begin
      for Offset in 0 .. 3 loop
         if Value
           > (Natural'Last
              - Natural (Data (First + Stream_Element_Offset (Offset)))) / 256
         then
            raise Constraint_Error;
         end if;
         Value :=
           Value * 256
           + Natural (Data (First + Stream_Element_Offset (Offset)));
      end loop;
      return Value;
   end U32_At;

   function U32_Raw_At
     (Data  : Stream_Element_Array;
      First : Stream_Element_Offset)
      return Interfaces.Unsigned_32
   is
      use type Interfaces.Unsigned_32;

      Value : Interfaces.Unsigned_32 := 0;
   begin
      for Offset in 0 .. 3 loop
         Value :=
           Interfaces.Shift_Left (Value, 8)
           or Interfaces.Unsigned_32
                (Data (First + Stream_Element_Offset (Offset)));
      end loop;
      return Value;
   end U32_Raw_At;

   function SHA1_Digest_Matches
     (Digest : CryptoLib.Hashes.SHA1_Digest;
      Data   : Stream_Element_Array)
      return Boolean
   is
      Cursor : Stream_Element_Offset := Data'First;
   begin
      if Data'Length /= Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
      then
         return False;
      end if;

      for Digest_Index in Digest'Range loop
         if Digest (Digest_Index) /= Data (Cursor) then
            return False;
         end if;
         Cursor := Cursor + 1;
      end loop;

      return True;
   exception
      when others =>
         return False;
   end SHA1_Digest_Matches;

   function Pack_Kind_From_Code
     (Code : Natural;
      Kind : out Pack_Object_Kind)
      return Status
   is
   begin
      case Code is
         when 1 =>
            Kind := Pack_Commit;
         when 2 =>
            Kind := Pack_Tree;
         when 3 =>
            Kind := Pack_Blob;
         when 4 =>
            Kind := Pack_Tag;
         when 6 =>
            Kind := Pack_OFS_Delta;
         when 7 =>
            Kind := Pack_REF_Delta;
         when others =>
            return Invalid_Command;
      end case;
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Pack_Kind_From_Code;

   function Safe_Repository_Path (Repository_Path : String) return Boolean is
   begin
      if Repository_Path'Length = 0
        or else Repository_Path'Length > Maximum_Repository_Path_Length
      then
         return False;
      end if;

      for Path_Character of Repository_Path loop
         if Path_Character = Character'Val (0)
           or else Path_Character = Character'Val (10)
           or else Path_Character = Character'Val (13)
         then
            return False;
         end if;
      end loop;

      return True;
   end Safe_Repository_Path;

   function Quote_For_Remote_Command
     (Repository_Path : String;
      Quoted_Text     : out Unbounded_String)
      return CryptoLib.Errors.Status
   is
   begin
      Quoted_Text := Null_Unbounded_String;

      if not Safe_Repository_Path (Repository_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Append (Quoted_Text, "'");
      for Path_Character of Repository_Path loop
         if Path_Character = Character'Val (39) then
            Append (Quoted_Text, "'\''");
         else
            Append (Quoted_Text, Path_Character);
         end if;
      end loop;
      Append (Quoted_Text, "'");

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Quoted_Text := Null_Unbounded_String;
         return CryptoLib.Errors.Invalid_Command;
   end Quote_For_Remote_Command;

   function Build_Command
     (Program_Name    : String;
      Repository_Path : String;
      Command         : out Unbounded_String)
      return CryptoLib.Errors.Status
   is
      Quoted_Text : Unbounded_String;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Command := Null_Unbounded_String;
      Status_Value := Quote_For_Remote_Command (Repository_Path, Quoted_Text);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      declare
         Candidate : constant String := Program_Name & " " & To_String (Quoted_Text);
      begin
         if not SSH_Lib.Protocol.Channels.Valid_Command (Candidate) then
            Command := Null_Unbounded_String;
            return CryptoLib.Errors.Invalid_Command;
         end if;

         Command := To_Unbounded_String (Candidate);
      end;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Command := Null_Unbounded_String;
         return CryptoLib.Errors.Invalid_Command;
   end Build_Command;

   function Build_Upload_Pack_Command
     (Repository_Path : String;
      Command         : out Unbounded_String)
      return CryptoLib.Errors.Status
   is
   begin
      return Build_Command ("git-upload-pack", Repository_Path, Command);
   end Build_Upload_Pack_Command;

   function Build_Receive_Pack_Command
     (Repository_Path : String;
      Command         : out Unbounded_String)
      return CryptoLib.Errors.Status
   is
   begin
      return Build_Command ("git-receive-pack", Repository_Path, Command);
   end Build_Receive_Pack_Command;

   function Upload_Pack_Command
     (Repository_Path : String)
      return String
   is
      Command : Unbounded_String;
      Status_Value : constant CryptoLib.Errors.Status :=
        Build_Upload_Pack_Command (Repository_Path, Command);
   begin
      if Status_Value /= CryptoLib.Errors.Ok then
         raise Constraint_Error with "invalid SSH Git repository path";
      end if;

      return To_String (Command);
   end Upload_Pack_Command;

   function Receive_Pack_Command
     (Repository_Path : String)
      return String
   is
      Command : Unbounded_String;
      Status_Value : constant CryptoLib.Errors.Status :=
        Build_Receive_Pack_Command (Repository_Path, Command);
   begin
      if Status_Value /= CryptoLib.Errors.Ok then
         raise Constraint_Error with "invalid SSH Git repository path";
      end if;

      return To_String (Command);
   end Receive_Pack_Command;

   function Initialize_Repository_State
     (Repository_Root : String)
      return Status
   is
      Git_Path_Value : constant String := Git_Directory (Repository_Root);

      procedure Write_Text_File (Path : String; Text : String) is
         File : Stream_IO.File_Type;
         Data : Stream_Element_Array (1 .. Stream_Element_Offset (Text'Length));
      begin
         for Index in Text'Range loop
            Data (Stream_Element_Offset (Index - Text'First + 1)) :=
              Stream_Element (Character'Pos (Text (Index)));
         end loop;
         Stream_IO.Create (File, Stream_IO.Out_File, Path);
         Stream_IO.Write (File, Data);
         Stream_IO.Close (File);
      exception
         when others =>
            if Stream_IO.Is_Open (File) then
               Stream_IO.Close (File);
            end if;
            raise;
      end Write_Text_File;
   begin
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Ada.Directories.Create_Path (Repository_Root);
      Ada.Directories.Create_Path (Git_Path_Value);
      Ada.Directories.Create_Path (Git_Path (Repository_Root, "objects"));
      Ada.Directories.Create_Path (Git_Path (Repository_Root, "refs"));
      Ada.Directories.Create_Path (Git_Path (Repository_Root, "refs/heads"));
      Ada.Directories.Create_Path (Git_Path (Repository_Root, "refs/tags"));
      Write_Text_File
        (Git_Path (Repository_Root, "HEAD"),
         "ref: refs/heads/main" & Character'Val (10));
      Write_Text_File
        (Config_File_Path (Repository_Root),
         "[core]" & Character'Val (10)
         & Character'Val (9) & "repositoryformatversion = 0" & Character'Val (10)
         & Character'Val (9) & "filemode = true" & Character'Val (10)
         & Character'Val (9) & "bare = false" & Character'Val (10));
      return Ok;
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Initialize_Repository_State;

   function Write_Empty_Index
     (Repository_Root : String)
      return Status
   is
      Path : constant String := Index_File_Path (Repository_Root);
      File : Stream_IO.File_Type;
      Index_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (12 + Object_ID_SHA1_Raw_Length)) :=
          [others => 0];
      Digest_Value : CryptoLib.Hashes.SHA1_Digest;

      procedure Store_U32
        (Value : Natural;
         Data  : in out Stream_Element_Array;
         First : Stream_Element_Offset)
      is
      begin
         Data (First) := Stream_Element ((Value / 16#01_00_00_00#) mod 256);
         Data (First + 1) := Stream_Element ((Value / 16#00_01_00_00#) mod 256);
         Data (First + 2) := Stream_Element ((Value / 16#00_00_01_00#) mod 256);
         Data (First + 3) := Stream_Element (Value mod 256);
      end Store_U32;
   begin
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Index_Data (1) := Character'Pos ('D');
      Index_Data (2) := Character'Pos ('I');
      Index_Data (3) := Character'Pos ('R');
      Index_Data (4) := Character'Pos ('C');
      Store_U32 (2, Index_Data, 5);
      Store_U32 (0, Index_Data, 9);
      Digest_Value :=
        CryptoLib.Hashes.SHA1
          (Index_Data (Index_Data'First .. Index_Data'First + 11));
      declare
         Cursor : Stream_Element_Offset := Index_Data'Last
           - Stream_Element_Offset (Object_ID_SHA1_Raw_Length) + 1;
      begin
         for Digest_Index in Digest_Value'Range loop
            Index_Data (Cursor) := Digest_Value (Digest_Index);
            Cursor := Cursor + 1;
         end loop;
      end;

      Ada.Directories.Create_Path
        (Ada.Directories.Containing_Directory (Path));
      Stream_IO.Create (File, Stream_IO.Out_File, Path);
      Stream_IO.Write (File, Index_Data);
      Stream_IO.Close (File);
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Write_Failed;
   end Write_Empty_Index;

   function Read_Index_Header
     (Repository_Root : String;
      Version         : out Natural;
      Entry_Count     : out Natural)
      return Status
   is
      Path : constant String := Index_File_Path (Repository_Root);
      File : Stream_IO.File_Type;
      File_Size : Stream_IO.Count;
      Last : Stream_Element_Offset;
   begin
      Version := 0;
      Entry_Count := 0;

      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Stream_IO.Open (File, Stream_IO.In_File, Path);
      File_Size := Stream_IO.Size (File);
      if File_Size < Stream_IO.Count (12 + Object_ID_SHA1_Raw_Length)
        or else File_Size > Maximum_Index_File_Length
      then
         Stream_IO.Close (File);
         return Invalid_Command;
      end if;

      declare
         Data : Stream_Element_Array (1 .. Stream_Element_Offset (File_Size));
      begin
         Stream_IO.Read (File, Data, Last);
         Stream_IO.Close (File);
         if Last /= Data'Last then
            return Read_Failed;
         elsif Data (1) /= Character'Pos ('D')
           or else Data (2) /= Character'Pos ('I')
           or else Data (3) /= Character'Pos ('R')
           or else Data (4) /= Character'Pos ('C')
         then
            return Invalid_Command;
         end if;

         Version := U32_At (Data, 5);
         Entry_Count := U32_At (Data, 9);
         if Version < 2 or else Version > 4 then
            Version := 0;
            Entry_Count := 0;
            return Unsupported_Feature;
         elsif not SHA1_Digest_Matches
           (CryptoLib.Hashes.SHA1
              (Data
                 (Data'First
                  .. Data'Last
                     - Stream_Element_Offset (Object_ID_SHA1_Raw_Length))),
            Data
              (Data'Last - Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
               + 1
               .. Data'Last))
         then
            Version := 0;
            Entry_Count := 0;
            return Invalid_Command;
         end if;
      end;

      return Ok;
   exception
      when Constraint_Error =>
         Version := 0;
         Entry_Count := 0;
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Invalid_Command;
      when others =>
         Version := 0;
         Entry_Count := 0;
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Read_Failed;
   end Read_Index_Header;

   function Build_Index_Entry
     (File_Mode  : Natural;
      Path       : String;
      Object_ID  : Stream_Element_Array;
      File_Size  : Natural;
      Entry_Data : out Stream_Element_Array;
      Last       : out Stream_Element_Offset)
      return Status
   is
      Fixed_Length : constant Natural := 62;
      Required_Length : Natural := 0;

      function Valid_Index_Mode (Mode : Natural) return Boolean is
      begin
         return
           Mode = 8#100644#
           or else Mode = 8#100755#
           or else Mode = 8#120000#
           or else Mode = 8#160000#;
      end Valid_Index_Mode;

      procedure Store_U16
        (Value : Natural;
         Data  : in out Stream_Element_Array;
         First : Stream_Element_Offset)
      is
      begin
         Data (First) := Stream_Element ((Value / 16#100#) mod 256);
         Data (First + 1) := Stream_Element (Value mod 256);
      end Store_U16;

      procedure Store_U32
        (Value : Natural;
         Data  : in out Stream_Element_Array;
         First : Stream_Element_Offset)
      is
      begin
         Data (First) := Stream_Element ((Value / 16#01_00_00_00#) mod 256);
         Data (First + 1) := Stream_Element ((Value / 16#00_01_00_00#) mod 256);
         Data (First + 2) := Stream_Element ((Value / 16#00_00_01_00#) mod 256);
         Data (First + 3) := Stream_Element (Value mod 256);
      end Store_U32;
   begin
      Last := Entry_Data'First - 1;

      if not Valid_Index_Mode (File_Mode)
        or else not Valid_Worktree_Path (Path)
        or else Path'Length > 4095
        or else Object_ID'Length
          /= Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
      then
         return Invalid_Command;
      end if;

      Required_Length := Fixed_Length + Path'Length + 1;
      if Required_Length mod 8 /= 0 then
         Required_Length := Required_Length + (8 - Required_Length mod 8);
      end if;

      if Entry_Data'Length < Stream_Element_Offset (Required_Length) then
         return Read_Failed;
      end if;

      Entry_Data
        (Entry_Data'First
         .. Entry_Data'First + Stream_Element_Offset (Required_Length) - 1) :=
           [others => 0];
      Store_U32
        (File_Mode,
         Entry_Data,
         Entry_Data'First + Stream_Element_Offset (24));
      Store_U32
        (File_Size,
         Entry_Data,
         Entry_Data'First + Stream_Element_Offset (36));
      Entry_Data
        (Entry_Data'First + Stream_Element_Offset (40)
         .. Entry_Data'First + Stream_Element_Offset (59)) := Object_ID;
      Store_U16
        (Path'Length,
         Entry_Data,
         Entry_Data'First + Stream_Element_Offset (60));

      declare
         Cursor : Stream_Element_Offset :=
           Entry_Data'First + Stream_Element_Offset (Fixed_Length);
      begin
         for Index in Path'Range loop
            Entry_Data (Cursor) := Character'Pos (Path (Index));
            Cursor := Cursor + 1;
         end loop;
      end;

      Last :=
        Entry_Data'First + Stream_Element_Offset (Required_Length) - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Entry_Data'First - 1;
         return Invalid_Command;
      when others =>
         Last := Entry_Data'First - 1;
         return Internal_Error;
   end Build_Index_Entry;

   function Write_Index
     (Repository_Root : String;
      Entry_Data      : Stream_Element_Array;
      Entry_Count     : Natural)
      return Status
   is
      Path : constant String := Index_File_Path (Repository_Root);
      File : Stream_IO.File_Type;
      Header_Length : constant Natural := 12;
      Total_Length : Natural := 0;
      Digest_Value : CryptoLib.Hashes.SHA1_Digest;

      procedure Store_U32
        (Value : Natural;
         Data  : in out Stream_Element_Array;
         First : Stream_Element_Offset)
      is
      begin
         Data (First) := Stream_Element ((Value / 16#01_00_00_00#) mod 256);
         Data (First + 1) := Stream_Element ((Value / 16#00_01_00_00#) mod 256);
         Data (First + 2) := Stream_Element ((Value / 16#00_00_01_00#) mod 256);
         Data (First + 3) := Stream_Element (Value mod 256);
      end Store_U32;
   begin
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      elsif Entry_Count = 0 and then Entry_Data'Length /= 0 then
         return Invalid_Command;
      elsif Entry_Count > 0 and then Entry_Data'Length = 0 then
         return Invalid_Command;
      elsif Entry_Data'Length
        > Stream_Element_Offset
            (Maximum_Index_File_Length
             - Stream_IO.Count (Header_Length + Object_ID_SHA1_Raw_Length))
      then
         return Unsupported_Feature;
      end if;

      Total_Length :=
        Header_Length
        + Natural (Entry_Data'Length)
        + Object_ID_SHA1_Raw_Length;
      declare
         Index_Data : Stream_Element_Array
           (1 .. Stream_Element_Offset (Total_Length)) := [others => 0];
         Entry_First : constant Stream_Element_Offset :=
           Index_Data'First + Stream_Element_Offset (Header_Length);
      begin
         Index_Data (1) := Character'Pos ('D');
         Index_Data (2) := Character'Pos ('I');
         Index_Data (3) := Character'Pos ('R');
         Index_Data (4) := Character'Pos ('C');
         Store_U32 (2, Index_Data, 5);
         Store_U32 (Entry_Count, Index_Data, 9);
         if Entry_Data'Length > 0 then
            Index_Data
              (Entry_First
               .. Entry_First + Entry_Data'Length - 1) := Entry_Data;
         end if;

         Digest_Value :=
           CryptoLib.Hashes.SHA1
             (Index_Data
                (Index_Data'First
                 .. Index_Data'Last
                    - Stream_Element_Offset (Object_ID_SHA1_Raw_Length)));
         declare
            Cursor : Stream_Element_Offset := Index_Data'Last
              - Stream_Element_Offset (Object_ID_SHA1_Raw_Length) + 1;
         begin
            for Digest_Index in Digest_Value'Range loop
               Index_Data (Cursor) := Digest_Value (Digest_Index);
               Cursor := Cursor + 1;
            end loop;
         end;

         Ada.Directories.Create_Path
           (Ada.Directories.Containing_Directory (Path));
         Stream_IO.Create (File, Stream_IO.Out_File, Path);
         Stream_IO.Write (File, Index_Data);
         Stream_IO.Close (File);
      end;
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Write_Failed;
   end Write_Index;

   function Parse_Index_Entry
     (Entry_Data  : Stream_Element_Array;
      Entry_Offset : Natural;
      File_Mode   : out Natural;
      Path        : out Stream_Element_Array;
      Path_Last   : out Stream_Element_Offset;
      Object_ID   : out Stream_Element_Array;
      Object_Last : out Stream_Element_Offset;
      File_Size   : out Natural;
      Next_Offset : out Natural)
      return Status
   is
      Fixed_Length : constant Natural := 62;
      Flags        : Natural := 0;
      Path_Length  : Natural := 0;
      Entry_Length : Natural := 0;
      Base         : Stream_Element_Offset;

      function Valid_Index_Mode (Mode : Natural) return Boolean is
      begin
         return
           Mode = 8#100644#
           or else Mode = 8#100755#
           or else Mode = 8#120000#
           or else Mode = 8#160000#;
      end Valid_Index_Mode;

      function U16_At
        (Data  : Stream_Element_Array;
         First : Stream_Element_Offset)
         return Natural
      is
      begin
         return Natural (Data (First)) * 256 + Natural (Data (First + 1));
      end U16_At;
   begin
      File_Mode := 0;
      Path_Last := Path'First - 1;
      Object_Last := Object_ID'First - 1;
      File_Size := 0;
      Next_Offset := 0;

      if Entry_Data'Length > Stream_Element_Offset (Natural'Last) then
         return Unsupported_Feature;
      elsif Object_ID'Length
        < Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
      then
         return Read_Failed;
      elsif Entry_Offset + Fixed_Length > Natural (Entry_Data'Length) then
         return Invalid_Command;
      end if;

      Base := Entry_Data'First + Stream_Element_Offset (Entry_Offset);
      File_Mode := U32_At (Entry_Data, Base + 24);
      File_Size := U32_At (Entry_Data, Base + 36);
      Flags := U16_At (Entry_Data, Base + 60);
      Path_Length := Flags mod 16#1000#;
      if not Valid_Index_Mode (File_Mode)
        or else Path_Length = 0
        or else Path_Length = 16#0FFF#
        or else (Flags / 16#1000#) mod 4 /= 0
        or else Flags >= 16#4000#
      then
         File_Mode := 0;
         File_Size := 0;
         return Invalid_Command;
      elsif Path'Length < Stream_Element_Offset (Path_Length) then
         File_Mode := 0;
         File_Size := 0;
         return Read_Failed;
      elsif Entry_Offset + Fixed_Length + Path_Length
        >= Natural (Entry_Data'Length)
      then
         File_Mode := 0;
         File_Size := 0;
         return Invalid_Command;
      end if;

      Entry_Length := Fixed_Length + Path_Length + 1;
      if Entry_Length mod 8 /= 0 then
         Entry_Length := Entry_Length + (8 - Entry_Length mod 8);
      end if;
      if Entry_Offset + Entry_Length > Natural (Entry_Data'Length) then
         File_Mode := 0;
         File_Size := 0;
         return Invalid_Command;
      end if;

      if Entry_Data (Base + Stream_Element_Offset (Fixed_Length + Path_Length))
        /= 0
      then
         File_Mode := 0;
         File_Size := 0;
         return Invalid_Command;
      end if;
      for Pad in Fixed_Length + Path_Length + 1 .. Entry_Length - 1 loop
         if Entry_Data (Base + Stream_Element_Offset (Pad)) /= 0 then
            File_Mode := 0;
            File_Size := 0;
            return Invalid_Command;
         end if;
      end loop;

      for Index in 0 .. Path_Length - 1 loop
         declare
            Value : constant Stream_Element :=
              Entry_Data
                (Base + Stream_Element_Offset (Fixed_Length + Index));
         begin
            if Value = 0
              or else Value = Character'Pos (Character'Val (10))
              or else Value = Character'Pos (Character'Val (13))
            then
               File_Mode := 0;
               File_Size := 0;
               return Invalid_Command;
            end if;
            Path (Path'First + Stream_Element_Offset (Index)) := Value;
         end;
      end loop;
      Path_Last := Path'First + Stream_Element_Offset (Path_Length) - 1;
      Object_ID
        (Object_ID'First
         .. Object_ID'First
            + Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
            - 1) :=
          Entry_Data (Base + 40 .. Base + 59);
      Object_Last :=
        Object_ID'First + Stream_Element_Offset (Object_ID_SHA1_Raw_Length) - 1;
      Next_Offset := Entry_Offset + Entry_Length;
      return Ok;
   exception
      when Constraint_Error =>
         File_Mode := 0;
         Path_Last := Path'First - 1;
         Object_Last := Object_ID'First - 1;
         File_Size := 0;
         Next_Offset := 0;
         return Invalid_Command;
      when others =>
         File_Mode := 0;
         Path_Last := Path'First - 1;
         Object_Last := Object_ID'First - 1;
         File_Size := 0;
         Next_Offset := 0;
         return Internal_Error;
   end Parse_Index_Entry;

   function Read_Index_Entry
     (Repository_Root : String;
      Entry_Index     : Natural;
      File_Mode       : out Natural;
      Path            : out Stream_Element_Array;
      Path_Last       : out Stream_Element_Offset;
      Object_ID       : out Stream_Element_Array;
      Object_Last     : out Stream_Element_Offset;
      File_Size       : out Natural)
      return Status
   is
      Path_Value  : constant String := Index_File_Path (Repository_Root);
      File        : Stream_IO.File_Type;
      File_Length : Stream_IO.Count;
      Last_Read   : Stream_Element_Offset;
      Version     : Natural := 0;
      Entry_Count : Natural := 0;
      Offset      : Natural := 0;
      Next        : Natural := 0;
      Status_Value : Status;
   begin
      File_Mode := 0;
      Path_Last := Path'First - 1;
      Object_Last := Object_ID'First - 1;
      File_Size := 0;

      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Stream_IO.Open (File, Stream_IO.In_File, Path_Value);
      File_Length := Stream_IO.Size (File);
      if File_Length < Stream_IO.Count (12 + Object_ID_SHA1_Raw_Length)
        or else File_Length > Maximum_Index_File_Length
      then
         Stream_IO.Close (File);
         return Invalid_Command;
      end if;

      declare
         Data : Stream_Element_Array (1 .. Stream_Element_Offset (File_Length));
      begin
         Stream_IO.Read (File, Data, Last_Read);
         Stream_IO.Close (File);
         if Last_Read /= Data'Last then
            return Read_Failed;
         elsif Data (1) /= Character'Pos ('D')
           or else Data (2) /= Character'Pos ('I')
           or else Data (3) /= Character'Pos ('R')
           or else Data (4) /= Character'Pos ('C')
         then
            return Invalid_Command;
         end if;

         Version := U32_At (Data, 5);
         Entry_Count := U32_At (Data, 9);
         if Version < 2 or else Version > 4 then
            return Unsupported_Feature;
         elsif Entry_Index >= Entry_Count then
            return Invalid_Command;
         elsif not SHA1_Digest_Matches
           (CryptoLib.Hashes.SHA1
              (Data
                 (Data'First
                  .. Data'Last
                     - Stream_Element_Offset (Object_ID_SHA1_Raw_Length))),
            Data
              (Data'Last - Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
               + 1
               .. Data'Last))
         then
            return Invalid_Command;
         end if;

         declare
            Entries : constant Stream_Element_Array :=
              Data
                (13
                 .. Data'Last
                    - Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
            Skip_Mode : Natural := 0;
            Skip_Path : Stream_Element_Array
              (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
            Skip_Path_Last : Stream_Element_Offset;
            Skip_ID : Stream_Element_Array
              (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
            Skip_ID_Last : Stream_Element_Offset;
            Skip_Size : Natural := 0;
         begin
            for Index in 0 .. Entry_Count - 1 loop
               if Index = Entry_Index then
                  Status_Value :=
                    Parse_Index_Entry
                      (Entries,
                       Offset,
                       File_Mode,
                       Path,
                       Path_Last,
                       Object_ID,
                       Object_Last,
                       File_Size,
                       Next);
               else
                  Status_Value :=
                    Parse_Index_Entry
                      (Entries,
                       Offset,
                       Skip_Mode,
                       Skip_Path,
                       Skip_Path_Last,
                       Skip_ID,
                       Skip_ID_Last,
                       Skip_Size,
                       Next);
               end if;

               if Status_Value /= Ok then
                  File_Mode := 0;
                  Path_Last := Path'First - 1;
                  Object_Last := Object_ID'First - 1;
                  File_Size := 0;
                  return Status_Value;
               elsif Next <= Offset or else Next > Natural (Entries'Length) then
                  File_Mode := 0;
                  Path_Last := Path'First - 1;
                  Object_Last := Object_ID'First - 1;
                  File_Size := 0;
                  return Invalid_Command;
               elsif Index = Entry_Index then
                  return Ok;
               end if;
               Offset := Next;
            end loop;
         end;
      end;

      return Invalid_Command;
   exception
      when Constraint_Error =>
         File_Mode := 0;
         Path_Last := Path'First - 1;
         Object_Last := Object_ID'First - 1;
         File_Size := 0;
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Invalid_Command;
      when others =>
         File_Mode := 0;
         Path_Last := Path'First - 1;
         Object_Last := Object_ID'First - 1;
         File_Size := 0;
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Read_Failed;
   end Read_Index_Entry;

   function Find_Index_Entry
     (Repository_Root : String;
      Path            : Stream_Element_Array;
      File_Mode       : out Natural;
      Object_ID       : out Stream_Element_Array;
      Object_Last     : out Stream_Element_Offset;
      File_Size       : out Natural;
      Found           : out Boolean)
      return Status
   is
      Version     : Natural := 0;
      Entry_Count : Natural := 0;
      Path_Buffer : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Path_Last   : Stream_Element_Offset;
      Status_Value : Status;
   begin
      File_Mode := 0;
      Object_Last := Object_ID'First - 1;
      File_Size := 0;
      Found := False;

      if Path'Length = 0
        or else Path'Length > Stream_Element_Offset (Maximum_Ref_Name_Length)
      then
         return Invalid_Command;
      end if;
      for Index in Path'Range loop
         if Path (Index) = 0
           or else Path (Index) = Character'Pos (Character'Val (10))
           or else Path (Index) = Character'Pos (Character'Val (13))
         then
            return Invalid_Command;
         end if;
      end loop;

      Status_Value :=
        Read_Index_Header (Repository_Root, Version, Entry_Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      for Entry_Index in 0 .. Entry_Count - 1 loop
         Status_Value :=
           Read_Index_Entry
             (Repository_Root,
              Entry_Index,
              File_Mode,
              Path_Buffer,
              Path_Last,
              Object_ID,
              Object_Last,
              File_Size);
         if Status_Value /= Ok then
            File_Mode := 0;
            Object_Last := Object_ID'First - 1;
            File_Size := 0;
            Found := False;
            return Status_Value;
         elsif Path_Last - Path_Buffer'First + 1 = Path'Length
           and then Path_Buffer (Path_Buffer'First .. Path_Last) = Path
         then
            Found := True;
            return Ok;
         end if;
      end loop;

      File_Mode := 0;
      Object_Last := Object_ID'First - 1;
      File_Size := 0;
      Found := False;
      return Ok;
   exception
      when Constraint_Error =>
         File_Mode := 0;
         Object_Last := Object_ID'First - 1;
         File_Size := 0;
         Found := False;
         return Invalid_Command;
      when others =>
         File_Mode := 0;
         Object_Last := Object_ID'First - 1;
         File_Size := 0;
         Found := False;
         return Internal_Error;
   end Find_Index_Entry;

   function Read_Index_Path_Object
     (Repository_Root : String;
      Path            : Stream_Element_Array;
      Kind            : out Pack_Object_Kind;
      Data            : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
      File_Mode : Natural := 0;
      Raw_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last : Stream_Element_Offset;
      Hex_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Hex_Last : Stream_Element_Offset;
      Empty_Pack_Checksum : Stream_Element_Array (1 .. 0);
      Pack_Data : Stream_Element_Array (1 .. 0);
      Index_Data : Stream_Element_Array (1 .. 0);
      File_Size : Natural := 0;
      Status_Value : Status;
   begin
      Kind := Pack_Blob;
      Last := Data'First - 1;
      Found := False;

      Status_Value :=
        Find_Index_Entry
          (Repository_Root,
           Path,
           File_Mode,
           Raw_ID,
           Raw_Last,
           File_Size,
           Found);
      if Status_Value /= Ok or else not Found then
         return Status_Value;
      elsif Raw_Last /= Raw_ID'Last then
         Found := False;
         return Invalid_Command;
      end if;

      Status_Value := Encode_Object_ID_Hex (Raw_ID, Hex_ID, Hex_Last);
      if Status_Value /= Ok then
         Found := False;
         return Status_Value;
      elsif Hex_Last /= Hex_ID'Last then
         Found := False;
         return Invalid_Command;
      end if;

      Status_Value :=
        Read_Stored_Object
          (Repository_Root,
           Hex_ID,
           Empty_Pack_Checksum,
           Pack_Data,
           Index_Data,
           Kind,
           Data,
           Last);
      if Status_Value /= Ok then
         Kind := Pack_Blob;
         Last := Data'First - 1;
         Found := False;
         return Status_Value;
      end if;

      Found := True;
      return Ok;
   exception
      when Constraint_Error =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         Found := False;
         return Invalid_Command;
      when others =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         Found := False;
         return Internal_Error;
   end Read_Index_Path_Object;

   function List_Index_Paths
     (Repository_Root : String;
      Paths           : out Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Path_Count      : out Natural)
      return Status
   is
      Version     : Natural := 0;
      Entry_Count : Natural := 0;
      File_Mode   : Natural := 0;
      Object_ID   : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Object_Last : Stream_Element_Offset;
      File_Size   : Natural := 0;
      Path_Buffer : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Path_Last   : Stream_Element_Offset;
      Cursor      : Stream_Element_Offset := Paths'First;
      Status_Value : Status;
   begin
      Path_Count := 0;
      if Path_Lasts'Length = 0 then
         return Read_Failed;
      end if;

      Status_Value :=
        Read_Index_Header (Repository_Root, Version, Entry_Count);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Entry_Count > Path_Lasts'Length then
         return Read_Failed;
      end if;

      for Entry_Index in 0 .. Entry_Count - 1 loop
         Status_Value :=
           Read_Index_Entry
             (Repository_Root,
              Entry_Index,
              File_Mode,
              Path_Buffer,
              Path_Last,
              Object_ID,
              Object_Last,
              File_Size);
         if Status_Value /= Ok then
            Path_Count := 0;
            return Status_Value;
         elsif Path_Last < Path_Buffer'First then
            Path_Count := 0;
            return Invalid_Command;
         elsif Cursor + (Path_Last - Path_Buffer'First) > Paths'Last then
            Path_Count := 0;
            return Read_Failed;
         end if;

         Paths
           (Cursor
            .. Cursor + (Path_Last - Path_Buffer'First)) :=
             Path_Buffer (Path_Buffer'First .. Path_Last);
         Cursor := Cursor + (Path_Last - Path_Buffer'First) + 1;
         Path_Count := Path_Count + 1;
         Path_Lasts (Path_Lasts'First + Path_Count - 1) := Cursor - 1;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         Path_Count := 0;
         return Invalid_Command;
      when others =>
         Path_Count := 0;
         return Internal_Error;
   end List_Index_Paths;

   function Write_Worktree_File
     (Repository_Root : String;
      Path            : String;
      Data            : Stream_Element_Array)
      return Status
   is
      Full_Path : constant String := Worktree_Path (Repository_Root, Path);
      File      : Stream_IO.File_Type;
   begin
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Worktree_Path (Path)
      then
         return Invalid_Command;
      end if;

      Ada.Directories.Create_Path
        (Ada.Directories.Containing_Directory (Full_Path));
      Stream_IO.Create (File, Stream_IO.Out_File, Full_Path);
      if Data'Length > 0 then
         Stream_IO.Write (File, Data);
      end if;
      Stream_IO.Close (File);
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Write_Failed;
   end Write_Worktree_File;

   function Read_Worktree_File
     (Repository_Root : String;
      Path            : String;
      Data            : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
      Full_Path : constant String := Worktree_Path (Repository_Root, Path);
      File      : Stream_IO.File_Type;
      File_Size : Stream_IO.Count;
   begin
      Last := Data'First - 1;
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Worktree_Path (Path)
      then
         return Invalid_Command;
      end if;

      Stream_IO.Open (File, Stream_IO.In_File, Full_Path);
      File_Size := Stream_IO.Size (File);
      if File_Size > Stream_IO.Count (Data'Length) then
         Stream_IO.Close (File);
         return Read_Failed;
      elsif File_Size = 0 then
         Stream_IO.Close (File);
         return Ok;
      end if;

      Stream_IO.Read
        (File,
         Data (Data'First .. Data'First + Stream_Element_Offset (File_Size) - 1),
         Last);
      Stream_IO.Close (File);
      if Last /= Data'First + Stream_Element_Offset (File_Size) - 1 then
         Last := Data'First - 1;
         return Read_Failed;
      end if;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Data'First - 1;
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Invalid_Command;
      when others =>
         Last := Data'First - 1;
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Read_Failed;
   end Read_Worktree_File;

   function Worktree_File_Exists
     (Repository_Root : String;
      Path            : String;
      Found           : out Boolean)
      return Status
   is
   begin
      Found := False;
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Worktree_Path (Path)
      then
         return Invalid_Command;
      end if;

      Found := Ada.Directories.Exists (Worktree_Path (Repository_Root, Path));
      return Ok;
   exception
      when Constraint_Error =>
         Found := False;
         return Invalid_Command;
      when others =>
         Found := False;
         return Read_Failed;
   end Worktree_File_Exists;

   function Delete_Worktree_File
     (Repository_Root : String;
      Path            : String;
      Removed         : out Boolean)
      return Status
   is
      Full_Path : constant String := Worktree_Path (Repository_Root, Path);
   begin
      Removed := False;
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Worktree_Path (Path)
      then
         return Invalid_Command;
      end if;

      if not Ada.Directories.Exists (Full_Path) then
         return Ok;
      end if;

      Ada.Directories.Delete_File (Full_Path);
      Removed := True;
      return Ok;
   exception
      when Constraint_Error =>
         Removed := False;
         return Invalid_Command;
      when others =>
         Removed := False;
         return Write_Failed;
   end Delete_Worktree_File;

   function Checkout_Index_Path
     (Repository_Root : String;
      Path            : Stream_Element_Array;
      Written         : out Boolean)
      return Status
   is
      Kind : Pack_Object_Kind := Pack_Blob;
      Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Last : Stream_Element_Offset;
      Found : Boolean := False;
      Status_Value : Status;
   begin
      Written := False;
      if Path'Length = 0
        or else Path'Length > Stream_Element_Offset (Maximum_Ref_Name_Length)
      then
         return Invalid_Command;
      end if;

      Status_Value :=
        Read_Index_Path_Object
          (Repository_Root, Path, Kind, Data, Last, Found);
      if Status_Value /= Ok or else not Found then
         return Status_Value;
      elsif Kind /= Pack_Blob then
         return Unsupported_Feature;
      elsif Last < Data'First then
         return Invalid_Command;
      end if;

      declare
         Path_Text : String (1 .. Natural (Path'Length));
      begin
         for Index in Path_Text'Range loop
            Path_Text (Index) :=
              Character'Val
                (Path (Path'First + Stream_Element_Offset (Index - 1)));
         end loop;
         Status_Value :=
           Write_Worktree_File
             (Repository_Root,
              Path_Text,
              Data (Data'First .. Last));
      end;

      if Status_Value = Ok then
         Written := True;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Written := False;
         return Invalid_Command;
      when others =>
         Written := False;
         return Internal_Error;
   end Checkout_Index_Path;

   function Checkout_Index_All
     (Repository_Root : String;
      Written_Count   : out Natural)
      return Status
   is
      Version     : Natural := 0;
      Entry_Count : Natural := 0;
      File_Mode   : Natural := 0;
      Path_Buffer : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Path_Last   : Stream_Element_Offset;
      Object_ID   : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Object_Last : Stream_Element_Offset;
      File_Size   : Natural := 0;
      Written     : Boolean := False;
      Status_Value : Status;
   begin
      Written_Count := 0;
      Status_Value :=
        Read_Index_Header (Repository_Root, Version, Entry_Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      for Entry_Index in 0 .. Entry_Count - 1 loop
         Status_Value :=
           Read_Index_Entry
             (Repository_Root,
              Entry_Index,
              File_Mode,
              Path_Buffer,
              Path_Last,
              Object_ID,
              Object_Last,
              File_Size);
         if Status_Value /= Ok then
            Written_Count := 0;
            return Status_Value;
         elsif Path_Last < Path_Buffer'First then
            Written_Count := 0;
            return Invalid_Command;
         end if;

         Status_Value :=
           Checkout_Index_Path
             (Repository_Root,
              Path_Buffer (Path_Buffer'First .. Path_Last),
              Written);
         if Status_Value /= Ok then
            Written_Count := 0;
            return Status_Value;
         elsif Written then
            Written_Count := Written_Count + 1;
         end if;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         Written_Count := 0;
         return Invalid_Command;
      when others =>
         Written_Count := 0;
         return Internal_Error;
   end Checkout_Index_All;

   function Compare_Index_Path_To_Worktree
     (Repository_Root : String;
      Path            : Stream_Element_Array;
      Path_Status     : out Worktree_Path_Status)
      return Status
   is
      Kind : Pack_Object_Kind := Pack_Blob;
      Index_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Index_Last : Stream_Element_Offset;
      Worktree_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Worktree_Last : Stream_Element_Offset;
      Found : Boolean := False;
      Status_Value : Status;
   begin
      Path_Status := Worktree_Path_Missing;
      if Path'Length = 0
        or else Path'Length > Stream_Element_Offset (Maximum_Ref_Name_Length)
      then
         return Invalid_Command;
      end if;

      Status_Value :=
        Read_Index_Path_Object
          (Repository_Root, Path, Kind, Index_Data, Index_Last, Found);
      if Status_Value /= Ok then
         return Status_Value;
      elsif not Found then
         return Ok;
      elsif Kind /= Pack_Blob then
         return Unsupported_Feature;
      end if;

      declare
         Path_Text : String (1 .. Natural (Path'Length));
      begin
         for Index in Path_Text'Range loop
            Path_Text (Index) :=
              Character'Val
                (Path (Path'First + Stream_Element_Offset (Index - 1)));
         end loop;

         Status_Value :=
           Read_Worktree_File
             (Repository_Root, Path_Text, Worktree_Data, Worktree_Last);
      end;

      if Status_Value = Read_Failed then
         Path_Status := Worktree_Path_Missing;
         return Ok;
      elsif Status_Value /= Ok then
         return Status_Value;
      elsif Index_Last < Index_Data'First
        or else Worktree_Last < Worktree_Data'First
        or else Index_Last - Index_Data'First
          /= Worktree_Last - Worktree_Data'First
      then
         Path_Status := Worktree_Path_Modified;
      elsif Index_Data (Index_Data'First .. Index_Last)
        = Worktree_Data (Worktree_Data'First .. Worktree_Last)
      then
         Path_Status := Worktree_Path_Unchanged;
      else
         Path_Status := Worktree_Path_Modified;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Path_Status := Worktree_Path_Missing;
         return Invalid_Command;
      when others =>
         Path_Status := Worktree_Path_Missing;
         return Internal_Error;
   end Compare_Index_Path_To_Worktree;

   function Summarize_Index_Worktree
     (Repository_Root  : String;
      Missing_Count    : out Natural;
      Unchanged_Count  : out Natural;
      Modified_Count   : out Natural)
      return Status
   is
      Version     : Natural := 0;
      Entry_Count : Natural := 0;
      File_Mode   : Natural := 0;
      Path_Buffer : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Path_Last   : Stream_Element_Offset;
      Object_ID   : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Object_Last : Stream_Element_Offset;
      File_Size   : Natural := 0;
      Path_State  : Worktree_Path_Status := Worktree_Path_Missing;
      Status_Value : Status;
   begin
      Missing_Count := 0;
      Unchanged_Count := 0;
      Modified_Count := 0;

      Status_Value :=
        Read_Index_Header (Repository_Root, Version, Entry_Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      for Entry_Index in 0 .. Entry_Count - 1 loop
         Status_Value :=
           Read_Index_Entry
             (Repository_Root,
              Entry_Index,
              File_Mode,
              Path_Buffer,
              Path_Last,
              Object_ID,
              Object_Last,
              File_Size);
         if Status_Value /= Ok then
            Missing_Count := 0;
            Unchanged_Count := 0;
            Modified_Count := 0;
            return Status_Value;
         elsif Path_Last < Path_Buffer'First then
            Missing_Count := 0;
            Unchanged_Count := 0;
            Modified_Count := 0;
            return Invalid_Command;
         end if;

         Status_Value :=
           Compare_Index_Path_To_Worktree
             (Repository_Root,
              Path_Buffer (Path_Buffer'First .. Path_Last),
              Path_State);
         if Status_Value /= Ok then
            Missing_Count := 0;
            Unchanged_Count := 0;
            Modified_Count := 0;
            return Status_Value;
         end if;

         case Path_State is
            when Worktree_Path_Missing =>
               Missing_Count := Missing_Count + 1;
            when Worktree_Path_Unchanged =>
               Unchanged_Count := Unchanged_Count + 1;
            when Worktree_Path_Modified =>
               Modified_Count := Modified_Count + 1;
         end case;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         Missing_Count := 0;
         Unchanged_Count := 0;
         Modified_Count := 0;
         return Invalid_Command;
      when others =>
         Missing_Count := 0;
         Unchanged_Count := 0;
         Modified_Count := 0;
      return Internal_Error;
   end Summarize_Index_Worktree;

   function Classify_Worktree_Path
     (Repository_Root : String;
      Path            : String;
      Path_Status     : out Porcelain_Path_Status)
      return Status
   is
      Path_Bytes : Stream_Element_Array
        (1 .. Stream_Element_Offset (Path'Length));
      File_Mode  : Natural := 0;
      Object_ID  : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Object_Last : Stream_Element_Offset;
      File_Size  : Natural := 0;
      Found_In_Index : Boolean := False;
      Found_In_Worktree : Boolean := False;
      Index_State : Worktree_Path_Status := Worktree_Path_Missing;
      Status_Value : Status;
   begin
      Path_Status := Porcelain_Path_Absent;
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Worktree_Path (Path)
      then
         return Invalid_Command;
      end if;

      for Index in Path'Range loop
         Path_Bytes
           (Path_Bytes'First + Stream_Element_Offset (Index - Path'First)) :=
             Character'Pos (Path (Index));
      end loop;

      Status_Value :=
        Find_Index_Entry
          (Repository_Root,
           Path_Bytes,
           File_Mode,
           Object_ID,
           Object_Last,
           File_Size,
           Found_In_Index);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Found_In_Index then
         Status_Value :=
           Compare_Index_Path_To_Worktree
             (Repository_Root, Path_Bytes, Index_State);
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         case Index_State is
            when Worktree_Path_Missing =>
               Path_Status := Porcelain_Path_Tracked_Missing;
            when Worktree_Path_Unchanged =>
               Path_Status := Porcelain_Path_Tracked_Unchanged;
            when Worktree_Path_Modified =>
               Path_Status := Porcelain_Path_Tracked_Modified;
         end case;
         return Ok;
      end if;

      Status_Value :=
        Worktree_File_Exists (Repository_Root, Path, Found_In_Worktree);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Found_In_Worktree then
         Path_Status := Porcelain_Path_Untracked;
      else
         Path_Status := Porcelain_Path_Absent;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Path_Status := Porcelain_Path_Absent;
         return Invalid_Command;
      when others =>
         Path_Status := Porcelain_Path_Absent;
         return Internal_Error;
   end Classify_Worktree_Path;

   function Summarize_Worktree_Paths
     (Repository_Root  : String;
      Paths            : Stream_Element_Array;
      Path_Lasts       : Index_Path_Last_Array;
      Path_Count       : Natural;
      Absent_Count     : out Natural;
      Untracked_Count  : out Natural;
      Missing_Count    : out Natural;
      Unchanged_Count  : out Natural;
      Modified_Count   : out Natural)
      return Status
   is
      Cursor      : Stream_Element_Offset := Paths'First;
      Path_State  : Porcelain_Path_Status := Porcelain_Path_Absent;
      Status_Value : Status;
   begin
      Absent_Count := 0;
      Untracked_Count := 0;
      Missing_Count := 0;
      Unchanged_Count := 0;
      Modified_Count := 0;

      if not Valid_Repository_Root (Repository_Root)
        or else Path_Count > Path_Lasts'Length
      then
         return Invalid_Command;
      end if;

      for Index in 1 .. Path_Count loop
         declare
            Last : constant Stream_Element_Offset :=
              Path_Lasts (Path_Lasts'First + Index - 1);
         begin
            if Last < Cursor or else Last > Paths'Last then
               Absent_Count := 0;
               Untracked_Count := 0;
               Missing_Count := 0;
               Unchanged_Count := 0;
               Modified_Count := 0;
               return Invalid_Command;
            end if;

            declare
               Path_Text : String (1 .. Natural (Last - Cursor + 1));
            begin
               for Path_Index in Path_Text'Range loop
                  Path_Text (Path_Index) :=
                    Character'Val
                      (Paths
                         (Cursor
                          + Stream_Element_Offset (Path_Index - 1)));
               end loop;

               Status_Value :=
                 Classify_Worktree_Path
                   (Repository_Root, Path_Text, Path_State);
            end;
         end;

         if Status_Value /= Ok then
            Absent_Count := 0;
            Untracked_Count := 0;
            Missing_Count := 0;
            Unchanged_Count := 0;
            Modified_Count := 0;
            return Status_Value;
         end if;

         case Path_State is
            when Porcelain_Path_Absent =>
               Absent_Count := Absent_Count + 1;
            when Porcelain_Path_Untracked =>
               Untracked_Count := Untracked_Count + 1;
            when Porcelain_Path_Tracked_Missing =>
               Missing_Count := Missing_Count + 1;
            when Porcelain_Path_Tracked_Unchanged =>
               Unchanged_Count := Unchanged_Count + 1;
            when Porcelain_Path_Tracked_Modified =>
               Modified_Count := Modified_Count + 1;
         end case;

         Cursor := Path_Lasts (Path_Lasts'First + Index - 1) + 1;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         Absent_Count := 0;
         Untracked_Count := 0;
         Missing_Count := 0;
         Unchanged_Count := 0;
         Modified_Count := 0;
         return Invalid_Command;
      when others =>
         Absent_Count := 0;
         Untracked_Count := 0;
         Missing_Count := 0;
         Unchanged_Count := 0;
         Modified_Count := 0;
         return Internal_Error;
   end Summarize_Worktree_Paths;

   function List_Worktree_Files
     (Repository_Root : String;
      Paths           : out Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Path_Count      : out Natural)
      return Status
   is
      use type Ada.Directories.File_Kind;
      Cursor : Stream_Element_Offset := Paths'First;

      procedure Append_Path
        (Path_Text : String;
         Result    : out Status)
      is
      begin
         Result := Ok;
         if not Valid_Worktree_Path (Path_Text) then
            Result := Invalid_Command;
            return;
         elsif Path_Count >= Path_Lasts'Length
           or else Cursor + Stream_Element_Offset (Path_Text'Length) - 1
             > Paths'Last
         then
            Result := Read_Failed;
            return;
         end if;

         for Ch of Path_Text loop
            Paths (Cursor) := Character'Pos (Ch);
            Cursor := Cursor + 1;
         end loop;
         Path_Count := Path_Count + 1;
         Path_Lasts (Path_Lasts'First + Path_Count - 1) := Cursor - 1;
      exception
         when Constraint_Error =>
            Result := Invalid_Command;
      end Append_Path;

      procedure Walk
        (Full_Dir : String;
         Prefix   : String;
         Depth    : Natural;
         Result   : out Status)
      is
         Search      : Ada.Directories.Search_Type;
         Search_Open : Boolean := False;
      begin
         Result := Ok;
         if Depth > Maximum_Ref_Resolution_Depth then
            Result := Unsupported_Feature;
            return;
         end if;

         Ada.Directories.Start_Search
           (Search    => Search,
            Directory => Full_Dir,
            Pattern   => "*",
            Filter    =>
              [Ada.Directories.Ordinary_File => True,
               Ada.Directories.Directory => True,
               others => False]);
         Search_Open := True;

         while Ada.Directories.More_Entries (Search) loop
            declare
               Entry_Item : Ada.Directories.Directory_Entry_Type;
            begin
               Ada.Directories.Get_Next_Entry (Search, Entry_Item);
               declare
                  Name : constant String :=
                    Ada.Directories.Simple_Name (Entry_Item);
                  Relative : constant String :=
                    (if Prefix'Length = 0 then Name else Prefix & "/" & Name);
               begin
                  if Name = "." or else Name = ".." then
                     null;
                  elsif Prefix'Length = 0 and then Name = ".git" then
                     null;
                  elsif Ada.Directories.Kind (Entry_Item)
                    = Ada.Directories.Directory
                  then
                     if Valid_Worktree_Path (Relative) then
                        Walk
                          (Ada.Directories.Full_Name (Entry_Item),
                           Relative,
                           Depth + 1,
                           Result);
                        if Result /= Ok then
                           Ada.Directories.End_Search (Search);
                           Search_Open := False;
                           return;
                        end if;
                     end if;
                  elsif Ada.Directories.Kind (Entry_Item)
                    = Ada.Directories.Ordinary_File
                  then
                     Append_Path (Relative, Result);
                     if Result /= Ok then
                        Ada.Directories.End_Search (Search);
                        Search_Open := False;
                        return;
                     end if;
                  end if;
               end;
            end;
         end loop;

         Ada.Directories.End_Search (Search);
         Search_Open := False;
      exception
         when Constraint_Error =>
            if Search_Open then
               Ada.Directories.End_Search (Search);
            end if;
            Result := Invalid_Command;
         when others =>
            if Search_Open then
               Ada.Directories.End_Search (Search);
            end if;
            Result := Read_Failed;
      end Walk;

      Status_Value : Status := Ok;
   begin
      Path_Count := 0;
      if Paths'Length > 0 then
         Paths := [others => 0];
      end if;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      elsif not Ada.Directories.Exists (Repository_Root) then
         return Read_Failed;
      elsif Ada.Directories.Kind (Repository_Root) /= Ada.Directories.Directory
      then
         return Invalid_Command;
      end if;

      Walk (Repository_Root, "", 0, Status_Value);
      if Status_Value /= Ok then
         Path_Count := 0;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Path_Count := 0;
         return Invalid_Command;
      when others =>
         Path_Count := 0;
         return Read_Failed;
   end List_Worktree_Files;

   function Worktree_Path_Ignored
     (Repository_Root : String;
      Path            : String;
      Ignored         : out Boolean)
      return Status
   is
      File_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Config_File_Length));
      File_Last : Stream_Element_Offset;
      Config_Value : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Config_Last : Stream_Element_Offset;
      Config_Found : Boolean := False;
      Status_Value : Status;

      function Base_Name (Text : String) return String is
         First : Positive := Text'First;
      begin
         for Index in reverse Text'Range loop
            if Text (Index) = '/' then
               First := Index + 1;
               exit;
            end if;
         end loop;
         return Text (First .. Text'Last);
      end Base_Name;

      function Wildcard_Matches (Pattern, Text : String) return Boolean is
         Star : Natural := 0;
      begin
         for Index in Pattern'Range loop
            if Pattern (Index) = '*' then
               if Star /= 0 then
                  return False;
               end if;
               Star := Index;
            end if;
         end loop;

         if Star = 0 then
            return Pattern = Text;
         end if;

         declare
            Prefix : constant String :=
              (if Star = Pattern'First then ""
               else Pattern (Pattern'First .. Star - 1));
            Suffix : constant String :=
              (if Star = Pattern'Last then ""
               else Pattern (Star + 1 .. Pattern'Last));
         begin
            if Text'Length < Prefix'Length + Suffix'Length then
               return False;
            end if;
            return
              (Prefix'Length = 0
               or else Text
                 (Text'First .. Text'First + Prefix'Length - 1) = Prefix)
              and then
              (Suffix'Length = 0
               or else Text
                 (Text'Last - Suffix'Length + 1 .. Text'Last) = Suffix);
         end;
      exception
         when others =>
            return False;
      end Wildcard_Matches;

      function Pattern_Matches (Pattern, Path_Text : String) return Boolean is
         First : Positive := Pattern'First;
         Last  : Natural := Pattern'Last;
         Has_Slash : Boolean := False;
      begin
         while First <= Last and then Pattern (First) = ' ' loop
            First := First + 1;
         end loop;
         while Last >= First and then Pattern (Last) = ' ' loop
            Last := Last - 1;
         end loop;
         if Last < First
           or else Pattern (First) = '#'
           or else Pattern (First) = '!'
         then
            return False;
         end if;
         if Pattern (First) = '/' then
            First := First + 1;
         end if;
         if Last < First then
            return False;
         end if;

         for Index in First .. Last loop
            if Pattern (Index) = '/' then
               Has_Slash := True;
               exit;
            end if;
         end loop;

         if Pattern (Last) = '/' then
            declare
               Prefix : constant String := Pattern (First .. Last - 1);
            begin
               return
                 Prefix'Length > 0
                 and then Path_Text'Length > Prefix'Length
                 and then Path_Text
                   (Path_Text'First
                    .. Path_Text'First + Prefix'Length - 1) = Prefix
                 and then Path_Text (Path_Text'First + Prefix'Length) = '/';
            end;
         elsif Has_Slash then
            return Wildcard_Matches (Pattern (First .. Last), Path_Text);
         else
            return Wildcard_Matches (Pattern (First .. Last), Base_Name (Path_Text));
         end if;
      exception
         when others =>
            return False;
      end Pattern_Matches;

      function Data_Matches
        (Data : Stream_Element_Array;
         Last : Stream_Element_Offset) return Boolean
      is
         Cursor : Stream_Element_Offset := Data'First;
      begin
         if Last < Data'First then
            return False;
         end if;
         while Cursor <= Last loop
            declare
               Line_First : constant Stream_Element_Offset := Cursor;
               Line_Last  : Stream_Element_Offset := Cursor - 1;
            begin
               while Cursor <= Last
                 and then Data (Cursor) /= Character'Pos (Character'Val (10))
               loop
                  if Data (Cursor) = Character'Pos (Character'Val (0))
                    or else Data (Cursor) = Character'Pos (Character'Val (13))
                  then
                     return False;
                  end if;
                  Line_Last := Cursor;
                  Cursor := Cursor + 1;
               end loop;

               if Line_Last >= Line_First then
                  declare
                     Line_Text : String
                       (1 .. Natural (Line_Last - Line_First + 1));
                  begin
                     for Index in Line_Text'Range loop
                        Line_Text (Index) :=
                          Character'Val
                            (Data
                               (Line_First
                                + Stream_Element_Offset (Index - 1)));
                     end loop;
                     if Pattern_Matches (Line_Text, Path) then
                        return True;
                     end if;
                  end;
               end if;

               Cursor := Cursor + 1;
            end;
         end loop;
         return False;
      end Data_Matches;

      function Read_Ordinary_File
        (Full_Path : String;
         Data      : out Stream_Element_Array;
         Last      : out Stream_Element_Offset) return Status
      is
         use type Ada.Directories.File_Kind;
         File : Stream_IO.File_Type;
         Size : Stream_IO.Count;
      begin
         Last := Data'First - 1;
         if not Ada.Directories.Exists (Full_Path) then
            return Read_Failed;
         elsif Ada.Directories.Kind (Full_Path) /= Ada.Directories.Ordinary_File
         then
            return Invalid_Command;
         end if;

         Stream_IO.Open (File, Stream_IO.In_File, Full_Path);
         Size := Stream_IO.Size (File);
         if Size > Stream_IO.Count (Data'Length) then
            Stream_IO.Close (File);
            return Read_Failed;
         elsif Size = 0 then
            Stream_IO.Close (File);
            return Ok;
         end if;
         Stream_IO.Read
           (File,
            Data
              (Data'First
               .. Data'First + Stream_Element_Offset (Size) - 1),
            Last);
         Stream_IO.Close (File);
         if Last /= Data'First + Stream_Element_Offset (Size) - 1 then
            Last := Data'First - 1;
            return Read_Failed;
         end if;
         return Ok;
      exception
         when Constraint_Error =>
            Last := Data'First - 1;
            if Stream_IO.Is_Open (File) then
               Stream_IO.Close (File);
            end if;
            return Invalid_Command;
         when others =>
            Last := Data'First - 1;
            if Stream_IO.Is_Open (File) then
               Stream_IO.Close (File);
            end if;
            return Read_Failed;
      end Read_Ordinary_File;
   begin
      Ignored := False;
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Worktree_Path (Path)
      then
         return Invalid_Command;
      end if;

      Status_Value :=
        Read_Ordinary_File
          (Worktree_Path (Repository_Root, ".gitignore"),
           File_Data,
           File_Last);
      if Status_Value = Ok and then Data_Matches (File_Data, File_Last) then
         Ignored := True;
         return Ok;
      elsif Status_Value /= Ok and then Status_Value /= Read_Failed then
         return Status_Value;
      end if;

      Status_Value :=
        Read_Ordinary_File
          (Git_Path (Repository_Root, "info/exclude"),
           File_Data,
           File_Last);
      if Status_Value = Ok and then Data_Matches (File_Data, File_Last) then
         Ignored := True;
         return Ok;
      elsif Status_Value /= Ok and then Status_Value /= Read_Failed then
         return Status_Value;
      end if;

      Status_Value :=
        Read_Config_Value
          (Repository_Root,
           "core",
           "excludesFile",
           Config_Value,
           Config_Last,
           Config_Found);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Config_Found and then Config_Last >= Config_Value'First then
         declare
            Excludes_Path : String
              (1 .. Natural (Config_Last - Config_Value'First + 1));
         begin
            for Index in Excludes_Path'Range loop
               Excludes_Path (Index) :=
                 Character'Val
                   (Config_Value
                      (Config_Value'First
                       + Stream_Element_Offset (Index - 1)));
            end loop;
            Status_Value :=
              Read_Ordinary_File (Excludes_Path, File_Data, File_Last);
            if Status_Value = Ok and then Data_Matches (File_Data, File_Last) then
               Ignored := True;
               return Ok;
            elsif Status_Value /= Ok and then Status_Value /= Read_Failed then
               return Status_Value;
            end if;
         end;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Ignored := False;
         return Invalid_Command;
      when others =>
         Ignored := False;
         return Internal_Error;
   end Worktree_Path_Ignored;

   function Summarize_Worktree_Status
     (Repository_Root  : String;
      Untracked_Count  : out Natural;
      Missing_Count    : out Natural;
      Unchanged_Count  : out Natural;
      Modified_Count   : out Natural)
      return Status
   is
      Paths : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Path_Lasts : Index_Path_Last_Array (1 .. 1024);
      Path_Count : Natural := 0;
      Cursor : Stream_Element_Offset := Paths'First;
      File_Mode : Natural := 0;
      Object_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Object_Last : Stream_Element_Offset;
      File_Size : Natural := 0;
      Found_In_Index : Boolean := False;
      Status_Value : Status;
   begin
      Untracked_Count := 0;
      Missing_Count := 0;
      Unchanged_Count := 0;
      Modified_Count := 0;

      Status_Value :=
        Summarize_Index_Worktree
          (Repository_Root, Missing_Count, Unchanged_Count, Modified_Count);
      if Status_Value /= Ok then
         Untracked_Count := 0;
         Missing_Count := 0;
         Unchanged_Count := 0;
         Modified_Count := 0;
         return Status_Value;
      end if;

      Status_Value :=
        List_Worktree_Files
          (Repository_Root, Paths, Path_Lasts, Path_Count);
      if Status_Value /= Ok then
         Untracked_Count := 0;
         Missing_Count := 0;
         Unchanged_Count := 0;
         Modified_Count := 0;
         return Status_Value;
      end if;

      for Index in 1 .. Path_Count loop
         declare
            Last : constant Stream_Element_Offset :=
              Path_Lasts (Path_Lasts'First + Index - 1);
         begin
            if Last < Cursor or else Last > Paths'Last then
               Untracked_Count := 0;
               Missing_Count := 0;
               Unchanged_Count := 0;
               Modified_Count := 0;
               return Invalid_Command;
            end if;

            Status_Value :=
              Find_Index_Entry
                (Repository_Root,
                 Paths (Cursor .. Last),
                 File_Mode,
                 Object_ID,
                 Object_Last,
                 File_Size,
                 Found_In_Index);
            if Status_Value /= Ok then
               Untracked_Count := 0;
               Missing_Count := 0;
               Unchanged_Count := 0;
               Modified_Count := 0;
               return Status_Value;
            elsif not Found_In_Index then
               Untracked_Count := Untracked_Count + 1;
            end if;
            Cursor := Last + 1;
         end;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         Untracked_Count := 0;
         Missing_Count := 0;
         Unchanged_Count := 0;
         Modified_Count := 0;
         return Invalid_Command;
      when others =>
         Untracked_Count := 0;
         Missing_Count := 0;
         Unchanged_Count := 0;
         Modified_Count := 0;
         return Internal_Error;
   end Summarize_Worktree_Status;

   function Summarize_Worktree_Status_Matching
     (Repository_Root  : String;
      Pathspec         : String;
      Untracked_Count  : out Natural;
      Missing_Count    : out Natural;
      Unchanged_Count  : out Natural;
      Modified_Count   : out Natural)
      return Status
   is
      Version : Natural := 0;
      Entry_Count : Natural := 0;
      File_Mode : Natural := 0;
      Path_Buffer : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Path_Last : Stream_Element_Offset;
      Object_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Object_Last : Stream_Element_Offset;
      File_Size : Natural := 0;
      Path_State : Worktree_Path_Status := Worktree_Path_Missing;
      Paths : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Path_Lasts : Index_Path_Last_Array (1 .. 1024);
      Path_Count : Natural := 0;
      Cursor : Stream_Element_Offset := Paths'First;
      Found_In_Index : Boolean := False;
      Matches : Boolean := False;
      Status_Value : Status;

      function Path_String
        (Source : Stream_Element_Array;
         Last   : Stream_Element_Offset)
         return String
      is
         Result : String (1 .. Natural (Last - Source'First + 1));
      begin
         for Index in Result'Range loop
            Result (Index) :=
              Character'Val
                (Source (Source'First + Stream_Element_Offset (Index - 1)));
         end loop;
         return Result;
      end Path_String;
   begin
      Untracked_Count := 0;
      Missing_Count := 0;
      Unchanged_Count := 0;
      Modified_Count := 0;

      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value := Read_Index_Header (Repository_Root, Version, Entry_Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      for Entry_Index in 0 .. Entry_Count - 1 loop
         Status_Value :=
           Read_Index_Entry
             (Repository_Root,
              Entry_Index,
              File_Mode,
              Path_Buffer,
              Path_Last,
              Object_ID,
              Object_Last,
              File_Size);
         if Status_Value /= Ok then
            Untracked_Count := 0;
            Missing_Count := 0;
            Unchanged_Count := 0;
            Modified_Count := 0;
            return Status_Value;
         elsif Path_Last < Path_Buffer'First then
            Untracked_Count := 0;
            Missing_Count := 0;
            Unchanged_Count := 0;
            Modified_Count := 0;
            return Invalid_Command;
         end if;

         declare
            Path_Text : constant String :=
              Path_String (Path_Buffer, Path_Last);
         begin
            Status_Value := Pathspec_Matches (Path_Text, Pathspec, Matches);
         end;
         if Status_Value /= Ok then
            Untracked_Count := 0;
            Missing_Count := 0;
            Unchanged_Count := 0;
            Modified_Count := 0;
            return Status_Value;
         elsif Matches then
            Status_Value :=
              Compare_Index_Path_To_Worktree
                (Repository_Root,
                 Path_Buffer (Path_Buffer'First .. Path_Last),
                 Path_State);
            if Status_Value /= Ok then
               Untracked_Count := 0;
               Missing_Count := 0;
               Unchanged_Count := 0;
               Modified_Count := 0;
               return Status_Value;
            end if;

            case Path_State is
               when Worktree_Path_Missing =>
                  Missing_Count := Missing_Count + 1;
               when Worktree_Path_Unchanged =>
                  Unchanged_Count := Unchanged_Count + 1;
               when Worktree_Path_Modified =>
                  Modified_Count := Modified_Count + 1;
            end case;
         end if;
      end loop;

      Status_Value :=
        List_Worktree_Files
          (Repository_Root, Paths, Path_Lasts, Path_Count);
      if Status_Value /= Ok then
         Untracked_Count := 0;
         Missing_Count := 0;
         Unchanged_Count := 0;
         Modified_Count := 0;
         return Status_Value;
      end if;

      for Index in 1 .. Path_Count loop
         declare
            Last : constant Stream_Element_Offset :=
              Path_Lasts (Path_Lasts'First + Index - 1);
         begin
            if Last < Cursor or else Last > Paths'Last then
               Untracked_Count := 0;
               Missing_Count := 0;
               Unchanged_Count := 0;
               Modified_Count := 0;
               return Invalid_Command;
            end if;

            declare
               Path_Text : constant String :=
                 Path_String (Paths (Cursor .. Last), Last);
            begin
               Status_Value := Pathspec_Matches (Path_Text, Pathspec, Matches);
            end;
            if Status_Value /= Ok then
               Untracked_Count := 0;
               Missing_Count := 0;
               Unchanged_Count := 0;
               Modified_Count := 0;
               return Status_Value;
            elsif Matches then
               Status_Value :=
                 Find_Index_Entry
                   (Repository_Root,
                    Paths (Cursor .. Last),
                    File_Mode,
                    Object_ID,
                    Object_Last,
                    File_Size,
                    Found_In_Index);
               if Status_Value /= Ok then
                  Untracked_Count := 0;
                  Missing_Count := 0;
                  Unchanged_Count := 0;
                  Modified_Count := 0;
                  return Status_Value;
               elsif not Found_In_Index then
                  Untracked_Count := Untracked_Count + 1;
               end if;
            end if;
            Cursor := Last + 1;
         end;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         Untracked_Count := 0;
         Missing_Count := 0;
         Unchanged_Count := 0;
         Modified_Count := 0;
         return Invalid_Command;
      when others =>
         Untracked_Count := 0;
         Missing_Count := 0;
         Unchanged_Count := 0;
         Modified_Count := 0;
         return Internal_Error;
   end Summarize_Worktree_Status_Matching;

   function Summarize_Worktree_Status_With_Ignored
     (Repository_Root  : String;
      Untracked_Count  : out Natural;
      Ignored_Count    : out Natural;
      Missing_Count    : out Natural;
      Unchanged_Count  : out Natural;
      Modified_Count   : out Natural)
      return Status
   is
      Paths : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Path_Lasts : Index_Path_Last_Array (1 .. 1024);
      Path_Count : Natural := 0;
      Cursor : Stream_Element_Offset := Paths'First;
      File_Mode : Natural := 0;
      Object_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Object_Last : Stream_Element_Offset;
      File_Size : Natural := 0;
      Found_In_Index : Boolean := False;
      Is_Ignored : Boolean := False;
      Status_Value : Status;
   begin
      Untracked_Count := 0;
      Ignored_Count := 0;
      Missing_Count := 0;
      Unchanged_Count := 0;
      Modified_Count := 0;

      Status_Value :=
        Summarize_Index_Worktree
          (Repository_Root, Missing_Count, Unchanged_Count, Modified_Count);
      if Status_Value /= Ok then
         Untracked_Count := 0;
         Ignored_Count := 0;
         Missing_Count := 0;
         Unchanged_Count := 0;
         Modified_Count := 0;
         return Status_Value;
      end if;

      Status_Value :=
        List_Worktree_Files
          (Repository_Root, Paths, Path_Lasts, Path_Count);
      if Status_Value /= Ok then
         Untracked_Count := 0;
         Ignored_Count := 0;
         Missing_Count := 0;
         Unchanged_Count := 0;
         Modified_Count := 0;
         return Status_Value;
      end if;

      for Index in 1 .. Path_Count loop
         declare
            Last : constant Stream_Element_Offset :=
              Path_Lasts (Path_Lasts'First + Index - 1);
         begin
            if Last < Cursor or else Last > Paths'Last then
               Untracked_Count := 0;
               Ignored_Count := 0;
               Missing_Count := 0;
               Unchanged_Count := 0;
               Modified_Count := 0;
               return Invalid_Command;
            end if;

            Status_Value :=
              Find_Index_Entry
                (Repository_Root,
                 Paths (Cursor .. Last),
                 File_Mode,
                 Object_ID,
                 Object_Last,
                 File_Size,
                 Found_In_Index);
            if Status_Value /= Ok then
               Untracked_Count := 0;
               Ignored_Count := 0;
               Missing_Count := 0;
               Unchanged_Count := 0;
               Modified_Count := 0;
               return Status_Value;
            elsif not Found_In_Index then
               declare
                  Path_Text : String (1 .. Natural (Last - Cursor + 1));
               begin
                  for Path_Index in Path_Text'Range loop
                     Path_Text (Path_Index) :=
                       Character'Val
                         (Paths
                            (Cursor
                             + Stream_Element_Offset (Path_Index - 1)));
                  end loop;
                  Status_Value :=
                    Worktree_Path_Ignored
                      (Repository_Root, Path_Text, Is_Ignored);
               end;
               if Status_Value /= Ok then
                  Untracked_Count := 0;
                  Ignored_Count := 0;
                  Missing_Count := 0;
                  Unchanged_Count := 0;
                  Modified_Count := 0;
                  return Status_Value;
               elsif Is_Ignored then
                  Ignored_Count := Ignored_Count + 1;
               else
                  Untracked_Count := Untracked_Count + 1;
               end if;
            end if;
            Cursor := Last + 1;
         end;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         Untracked_Count := 0;
         Ignored_Count := 0;
         Missing_Count := 0;
         Unchanged_Count := 0;
         Modified_Count := 0;
         return Invalid_Command;
      when others =>
         Untracked_Count := 0;
         Ignored_Count := 0;
         Missing_Count := 0;
         Unchanged_Count := 0;
         Modified_Count := 0;
         return Internal_Error;
   end Summarize_Worktree_Status_With_Ignored;

   function Evaluate_Porcelain_Status
     (Repository_Root  : String;
      Pathspec         : String;
      Include_Ignored  : Boolean;
      Summary          : out Porcelain_Status_Summary)
      return Status
   is
      Status_Value : Status;
      Paths        : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Path_Lasts   : Index_Path_Last_Array (1 .. 1024);
      Path_Count   : Natural := 0;

      procedure Finalize_Summary is
      begin
         Summary.Has_Untracked := Summary.Untracked_Count > 0;
         Summary.Has_Ignored := Summary.Ignored_Count > 0;
         Summary.Has_Tracked_Changes :=
           Summary.Missing_Count > 0 or else Summary.Modified_Count > 0;
         Summary.Is_Clean :=
           not Summary.Has_Untracked and then not Summary.Has_Tracked_Changes;
         Summary.Pathspec_Applied :=
           Pathspec'Length > 0 and then Pathspec /= ".";
         Summary.Include_Ignored := Include_Ignored;
      end Finalize_Summary;

      function Count_Matching_Ignored return Status is
         Cursor : Stream_Element_Offset := Paths'First;
         Ignored : Boolean := False;
         Matches : Boolean := False;
      begin
         for Index in 1 .. Path_Count loop
            declare
               Last : constant Stream_Element_Offset :=
                 Path_Lasts (Path_Lasts'First + Index - 1);
            begin
               if Last < Cursor or else Last > Paths'Last then
                  return Invalid_Command;
               end if;

               declare
                  Path_Text : String (1 .. Natural (Last - Cursor + 1));
               begin
                  for Path_Index in Path_Text'Range loop
                     Path_Text (Path_Index) :=
                       Character'Val
                         (Paths
                            (Cursor
                             + Stream_Element_Offset (Path_Index - 1)));
                  end loop;

                  Status_Value :=
                    Pathspec_Matches (Path_Text, Pathspec, Matches);
                  if Status_Value /= Ok then
                     return Status_Value;
                  elsif Matches then
                     Status_Value :=
                       Worktree_Path_Ignored
                         (Repository_Root, Path_Text, Ignored);
                     if Status_Value /= Ok then
                        return Status_Value;
                     elsif Ignored then
                        Summary.Ignored_Count := Summary.Ignored_Count + 1;
                     end if;
                  end if;
               end;
               Cursor := Last + 1;
            end;
         end loop;
         return Ok;
      exception
         when Constraint_Error =>
            return Invalid_Command;
         when others =>
            return Internal_Error;
      end Count_Matching_Ignored;
   begin
      Summary := (others => <>);
      if Pathspec'Length = 0 or else Pathspec = "." then
         if Include_Ignored then
            Status_Value :=
              Summarize_Worktree_Status_With_Ignored
                (Repository_Root,
                 Summary.Untracked_Count,
                 Summary.Ignored_Count,
                 Summary.Missing_Count,
                 Summary.Unchanged_Count,
                 Summary.Modified_Count);
         else
            Status_Value :=
              Summarize_Worktree_Status
                (Repository_Root,
                 Summary.Untracked_Count,
                 Summary.Missing_Count,
                 Summary.Unchanged_Count,
                 Summary.Modified_Count);
         end if;
      else
         Status_Value :=
           Summarize_Worktree_Status_Matching
             (Repository_Root,
              Pathspec,
              Summary.Untracked_Count,
              Summary.Missing_Count,
              Summary.Unchanged_Count,
              Summary.Modified_Count);
         if Status_Value = Ok and then Include_Ignored then
            Status_Value :=
              List_Worktree_Files
                (Repository_Root, Paths, Path_Lasts, Path_Count);
            if Status_Value = Ok then
               Status_Value := Count_Matching_Ignored;
            end if;
         end if;
      end if;

      if Status_Value /= Ok then
         Summary := (others => <>);
         return Status_Value;
      end if;

      Finalize_Summary;
      return Ok;
   exception
      when Constraint_Error =>
         Summary := (others => <>);
         return Invalid_Command;
      when others =>
         Summary := (others => <>);
         return Internal_Error;
   end Evaluate_Porcelain_Status;

   function Read_Porcelain_Index_Worktree_Model
     (Repository_Root  : String;
      Pathspec         : String;
      Include_Ignored  : Boolean;
      Model            : out Porcelain_Index_Worktree_Model)
      return Status
   is
      Paths      : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Path_Lasts : Index_Path_Last_Array (1 .. 1024);
      Head_Target : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Head_Last : Stream_Element_Offset;
      Head_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Head_ID_Last : Stream_Element_Offset;
      Branch_Name : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Branch_Last : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Model := (others => <>);
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value :=
        List_Index_Paths
          (Repository_Root, Paths, Path_Lasts, Model.Index_Path_Count);
      if Status_Value /= Ok then
         Model := (others => <>);
         return Status_Value;
      end if;

      Status_Value :=
        List_Worktree_Files
          (Repository_Root, Paths, Path_Lasts, Model.Worktree_File_Count);
      if Status_Value /= Ok then
         Model := (others => <>);
         return Status_Value;
      end if;

      Status_Value :=
        Read_HEAD_Target
          (Repository_Root, Head_Target, Head_Last, Model.HEAD_Attached);
      if Status_Value /= Ok and then Status_Value /= No_Such_File then
         Model := (others => <>);
         return Status_Value;
      end if;

      Status_Value :=
        Resolve_HEAD (Repository_Root, Head_ID, Head_ID_Last);
      if Status_Value = Ok
        and then Head_ID_Last = Head_ID'Last
      then
         Model.HEAD_Resolved := True;
      elsif Status_Value /= No_Such_File
        and then Status_Value /= Read_Failed
      then
         Model := (others => <>);
         return Status_Value;
      end if;

      Status_Value :=
        Read_Current_Branch
          (Repository_Root,
           Branch_Name,
           Branch_Last,
           Model.Current_Branch_Found);
      if Status_Value /= Ok then
         Model := (others => <>);
         return Status_Value;
      end if;

      Status_Value :=
        Evaluate_Porcelain_Status
          (Repository_Root, Pathspec, Include_Ignored, Model.Status);
      if Status_Value /= Ok then
         Model := (others => <>);
         return Status_Value;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Model := (others => <>);
         return Invalid_Command;
      when others =>
         Model := (others => <>);
         return Internal_Error;
   end Read_Porcelain_Index_Worktree_Model;

   function Detect_Worktree_Rename
     (Repository_Root : String;
      Old_Path        : out Stream_Element_Array;
      Old_Last        : out Stream_Element_Offset;
      New_Path        : out Stream_Element_Array;
      New_Last        : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
      Version : Natural := 0;
      Entry_Count : Natural := 0;
      File_Mode : Natural := 0;
      Indexed_Path : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Indexed_Path_Last : Stream_Element_Offset;
      Indexed_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Indexed_ID_Last : Stream_Element_Offset;
      Indexed_Size : Natural := 0;
      Path_State : Worktree_Path_Status := Worktree_Path_Missing;
      Paths : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Path_Lasts : Index_Path_Last_Array (1 .. 1024);
      Path_Count : Natural := 0;
      Cursor : Stream_Element_Offset := Paths'First;
      Found_In_Index : Boolean := False;
      Ignored : Boolean := False;
      File_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      File_Last : Stream_Element_Offset;
      Candidate_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Candidate_ID_Last : Stream_Element_Offset;
      Status_Value : Status;

      procedure Reset_Outputs is
      begin
         Old_Last := Old_Path'First - 1;
         New_Last := New_Path'First - 1;
         Found := False;
      end Reset_Outputs;

      function Path_String
        (Data : Stream_Element_Array;
         Last : Stream_Element_Offset) return String
      is
         Result : String (1 .. Natural (Last - Data'First + 1));
      begin
         for Index in Result'Range loop
            Result (Index) :=
              Character'Val
                (Data (Data'First + Stream_Element_Offset (Index - 1)));
         end loop;
         return Result;
      end Path_String;

      procedure Copy_Path
        (Source : Stream_Element_Array;
         Last   : Stream_Element_Offset;
         Target : in out Stream_Element_Array;
         Target_Last : out Stream_Element_Offset;
         Result : out Status)
      is
         Length : constant Stream_Element_Offset := Last - Source'First + 1;
      begin
         Result := Ok;
         Target_Last := Target'First - 1;
         if Last < Source'First then
            Result := Invalid_Command;
         elsif Length > Target'Length then
            Result := Read_Failed;
         else
            Target (Target'First .. Target'First + Length - 1) :=
              Source (Source'First .. Last);
            Target_Last := Target'First + Length - 1;
         end if;
      end Copy_Path;
   begin
      Reset_Outputs;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value := Read_Index_Header (Repository_Root, Version, Entry_Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := List_Worktree_Files (Repository_Root, Paths, Path_Lasts, Path_Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      for Entry_Index in 0 .. Entry_Count - 1 loop
         Status_Value :=
           Read_Index_Entry
             (Repository_Root,
              Entry_Index,
              File_Mode,
              Indexed_Path,
              Indexed_Path_Last,
              Indexed_ID,
              Indexed_ID_Last,
              Indexed_Size);
         if Status_Value /= Ok then
            Reset_Outputs;
            return Status_Value;
         elsif Indexed_ID_Last /= Indexed_ID'Last then
            Reset_Outputs;
            return Invalid_Command;
         end if;

         Status_Value :=
           Compare_Index_Path_To_Worktree
             (Repository_Root,
              Indexed_Path (Indexed_Path'First .. Indexed_Path_Last),
              Path_State);
         if Status_Value /= Ok then
            Reset_Outputs;
            return Status_Value;
         elsif Path_State = Worktree_Path_Missing then
            Cursor := Paths'First;
            for Path_Index in 1 .. Path_Count loop
               declare
                  Candidate_Last : constant Stream_Element_Offset :=
                    Path_Lasts (Path_Lasts'First + Path_Index - 1);
               begin
                  if Candidate_Last < Cursor or else Candidate_Last > Paths'Last then
                     Reset_Outputs;
                     return Invalid_Command;
                  end if;

                  Status_Value :=
                    Find_Index_Entry
                      (Repository_Root,
                       Paths (Cursor .. Candidate_Last),
                       File_Mode,
                       Candidate_ID,
                       Candidate_ID_Last,
                       Indexed_Size,
                       Found_In_Index);
                  if Status_Value /= Ok then
                     Reset_Outputs;
                     return Status_Value;
                  elsif not Found_In_Index then
                     declare
                        Candidate_Text : constant String :=
                          Path_String (Paths (Cursor .. Candidate_Last),
                                       Candidate_Last);
                     begin
                        Status_Value :=
                          Worktree_Path_Ignored
                            (Repository_Root, Candidate_Text, Ignored);
                        if Status_Value /= Ok then
                           Reset_Outputs;
                           return Status_Value;
                        elsif not Ignored then
                           Status_Value :=
                             Read_Worktree_File
                               (Repository_Root,
                                Candidate_Text,
                                File_Data,
                                File_Last);
                           if Status_Value /= Ok then
                              Reset_Outputs;
                              return Status_Value;
                           end if;
                           Status_Value :=
                             Compute_Object_ID
                               (Pack_Blob,
                                File_Data (File_Data'First .. File_Last),
                                Candidate_ID,
                                Candidate_ID_Last);
                           if Status_Value /= Ok then
                              Reset_Outputs;
                              return Status_Value;
                           elsif Candidate_ID_Last = Candidate_ID'Last
                             and then Candidate_ID = Indexed_ID
                           then
                              Copy_Path
                                (Indexed_Path,
                                 Indexed_Path_Last,
                                 Old_Path,
                                 Old_Last,
                                 Status_Value);
                              if Status_Value /= Ok then
                                 Reset_Outputs;
                                 return Status_Value;
                              end if;
                              Copy_Path
                                (Paths (Cursor .. Candidate_Last),
                                 Candidate_Last,
                                 New_Path,
                                 New_Last,
                                 Status_Value);
                              if Status_Value /= Ok then
                                 Reset_Outputs;
                                 return Status_Value;
                              end if;
                              Found := True;
                              return Ok;
                           end if;
                        end if;
                     end;
                  end if;

                  Cursor := Candidate_Last + 1;
               end;
            end loop;
         end if;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         Reset_Outputs;
         return Invalid_Command;
      when others =>
         Reset_Outputs;
         return Internal_Error;
   end Detect_Worktree_Rename;

   function Detect_Worktree_Copy
     (Repository_Root : String;
      Source_Path     : out Stream_Element_Array;
      Source_Last     : out Stream_Element_Offset;
      Copy_Path       : out Stream_Element_Array;
      Copy_Last       : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
      Version : Natural := 0;
      Entry_Count : Natural := 0;
      File_Mode : Natural := 0;
      Indexed_Path : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Indexed_Path_Last : Stream_Element_Offset;
      Indexed_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Indexed_ID_Last : Stream_Element_Offset;
      Indexed_Size : Natural := 0;
      Path_State : Worktree_Path_Status := Worktree_Path_Missing;
      Paths : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Path_Lasts : Index_Path_Last_Array (1 .. 1024);
      Path_Count : Natural := 0;
      Cursor : Stream_Element_Offset := Paths'First;
      Found_In_Index : Boolean := False;
      Ignored : Boolean := False;
      File_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      File_Last : Stream_Element_Offset;
      Candidate_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Candidate_ID_Last : Stream_Element_Offset;
      Status_Value : Status;

      procedure Reset_Outputs is
      begin
         Source_Last := Source_Path'First - 1;
         Copy_Last := Copy_Path'First - 1;
         Found := False;
      end Reset_Outputs;

      function Path_String
        (Data : Stream_Element_Array;
         Last : Stream_Element_Offset) return String
      is
         Result : String (1 .. Natural (Last - Data'First + 1));
      begin
         for Index in Result'Range loop
            Result (Index) :=
              Character'Val
                (Data (Data'First + Stream_Element_Offset (Index - 1)));
         end loop;
         return Result;
      end Path_String;

      procedure Copy_Name
        (Source : Stream_Element_Array;
         Last   : Stream_Element_Offset;
         Target : in out Stream_Element_Array;
         Target_Last : out Stream_Element_Offset;
         Result : out Status)
      is
         Length : constant Stream_Element_Offset := Last - Source'First + 1;
      begin
         Result := Ok;
         Target_Last := Target'First - 1;
         if Last < Source'First then
            Result := Invalid_Command;
         elsif Length > Target'Length then
            Result := Read_Failed;
         else
            Target (Target'First .. Target'First + Length - 1) :=
              Source (Source'First .. Last);
            Target_Last := Target'First + Length - 1;
         end if;
      end Copy_Name;
   begin
      Reset_Outputs;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value := Read_Index_Header (Repository_Root, Version, Entry_Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := List_Worktree_Files (Repository_Root, Paths, Path_Lasts, Path_Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      for Entry_Index in 0 .. Entry_Count - 1 loop
         Status_Value :=
           Read_Index_Entry
             (Repository_Root,
              Entry_Index,
              File_Mode,
              Indexed_Path,
              Indexed_Path_Last,
              Indexed_ID,
              Indexed_ID_Last,
              Indexed_Size);
         if Status_Value /= Ok then
            Reset_Outputs;
            return Status_Value;
         elsif Indexed_ID_Last /= Indexed_ID'Last then
            Reset_Outputs;
            return Invalid_Command;
         end if;

         Status_Value :=
           Compare_Index_Path_To_Worktree
             (Repository_Root,
              Indexed_Path (Indexed_Path'First .. Indexed_Path_Last),
              Path_State);
         if Status_Value /= Ok then
            Reset_Outputs;
            return Status_Value;
         elsif Path_State /= Worktree_Path_Missing then
            Cursor := Paths'First;
            for Path_Index in 1 .. Path_Count loop
               declare
                  Candidate_Last : constant Stream_Element_Offset :=
                    Path_Lasts (Path_Lasts'First + Path_Index - 1);
               begin
                  if Candidate_Last < Cursor or else Candidate_Last > Paths'Last then
                     Reset_Outputs;
                     return Invalid_Command;
                  end if;

                  Status_Value :=
                    Find_Index_Entry
                      (Repository_Root,
                       Paths (Cursor .. Candidate_Last),
                       File_Mode,
                       Candidate_ID,
                       Candidate_ID_Last,
                       Indexed_Size,
                       Found_In_Index);
                  if Status_Value /= Ok then
                     Reset_Outputs;
                     return Status_Value;
                  elsif not Found_In_Index then
                     declare
                        Candidate_Text : constant String :=
                          Path_String
                            (Paths (Cursor .. Candidate_Last),
                             Candidate_Last);
                     begin
                        Status_Value :=
                          Worktree_Path_Ignored
                            (Repository_Root, Candidate_Text, Ignored);
                        if Status_Value /= Ok then
                           Reset_Outputs;
                           return Status_Value;
                        elsif not Ignored then
                           Status_Value :=
                             Read_Worktree_File
                               (Repository_Root,
                                Candidate_Text,
                                File_Data,
                                File_Last);
                           if Status_Value /= Ok then
                              Reset_Outputs;
                              return Status_Value;
                           end if;
                           Status_Value :=
                             Compute_Object_ID
                               (Pack_Blob,
                                File_Data (File_Data'First .. File_Last),
                                Candidate_ID,
                                Candidate_ID_Last);
                           if Status_Value /= Ok then
                              Reset_Outputs;
                              return Status_Value;
                           elsif Candidate_ID_Last = Candidate_ID'Last
                             and then Candidate_ID = Indexed_ID
                           then
                              Copy_Name
                                (Indexed_Path,
                                 Indexed_Path_Last,
                                 Source_Path,
                                 Source_Last,
                                 Status_Value);
                              if Status_Value /= Ok then
                                 Reset_Outputs;
                                 return Status_Value;
                              end if;
                              Copy_Name
                                (Paths (Cursor .. Candidate_Last),
                                 Candidate_Last,
                                 Copy_Path,
                                 Copy_Last,
                                 Status_Value);
                              if Status_Value /= Ok then
                                 Reset_Outputs;
                                 return Status_Value;
                              end if;
                              Found := True;
                              return Ok;
                           end if;
                        end if;
                     end;
                  end if;

                  Cursor := Candidate_Last + 1;
               end;
            end loop;
         end if;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         Reset_Outputs;
         return Invalid_Command;
      when others =>
         Reset_Outputs;
         return Internal_Error;
   end Detect_Worktree_Copy;

   function Clean_Worktree_Not_In_Index
     (Repository_Root : String;
      Removed_Count   : out Natural)
      return Status
   is
      subtype Path_Slot is Positive range 1 .. 1024;
      type Delete_Mark_Array is array (Path_Slot range <>) of Boolean;

      Paths : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Path_Lasts : Index_Path_Last_Array (1 .. 1024);
      Path_Count : Natural := 0;
      Delete_Marks : Delete_Mark_Array (1 .. 1024) := [others => False];
      Cursor : Stream_Element_Offset;
      Mode : Natural := 0;
      Object_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Object_Last : Stream_Element_Offset;
      File_Size : Natural := 0;
      Found : Boolean := False;
      Ignored : Boolean := False;
      Removed : Boolean := False;
      Status_Value : Status;

      function Path_String
        (First : Stream_Element_Offset;
         Last  : Stream_Element_Offset)
         return String
      is
         Result : String (1 .. Natural (Last - First + 1));
      begin
         for Index in Result'Range loop
            Result (Index) :=
              Character'Val
                (Paths (First + Stream_Element_Offset (Index - 1)));
         end loop;
         return Result;
      end Path_String;
   begin
      Removed_Count := 0;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value := List_Worktree_Files (Repository_Root, Paths, Path_Lasts, Path_Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Cursor := Paths'First;
      for Index in 1 .. Path_Count loop
         if Index > Path_Lasts'Length
           or else Cursor > Path_Lasts (Index)
           or else Path_Lasts (Index) > Paths'Last
         then
            Removed_Count := 0;
            return Invalid_Command;
         end if;

         declare
            Path_Text : constant String := Path_String (Cursor, Path_Lasts (Index));
         begin
            Status_Value := Worktree_Path_Ignored (Repository_Root, Path_Text, Ignored);
            if Status_Value /= Ok then
               Removed_Count := 0;
               return Status_Value;
            end if;

            Status_Value :=
              Find_Index_Entry
                (Repository_Root,
                 Paths (Cursor .. Path_Lasts (Index)),
                 Mode,
                 Object_ID,
                 Object_Last,
                 File_Size,
                 Found);
            if Status_Value /= Ok then
               Removed_Count := 0;
               return Status_Value;
            elsif not Found and then not Ignored then
               Delete_Marks (Index) := True;
            end if;
         end;

         Cursor := Path_Lasts (Index) + 1;
      end loop;

      Cursor := Paths'First;
      for Index in 1 .. Path_Count loop
         if Delete_Marks (Index) then
            declare
               Path_Text : constant String := Path_String (Cursor, Path_Lasts (Index));
            begin
               Status_Value :=
                 Delete_Worktree_File (Repository_Root, Path_Text, Removed);
               if Status_Value /= Ok then
                  Removed_Count := 0;
                  return Status_Value;
               elsif Removed then
                  Removed_Count := Removed_Count + 1;
               end if;
            end;
         end if;

         Cursor := Path_Lasts (Index) + 1;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         Removed_Count := 0;
         return Invalid_Command;
      when others =>
         Removed_Count := 0;
         return Internal_Error;
   end Clean_Worktree_Not_In_Index;

   function Stage_Worktree_File
     (Repository_Root : String;
      Path            : String;
      Object_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
      File_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      File_Last : Stream_Element_Offset;
      Raw_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last : Stream_Element_Offset;
      Entry_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length + 72));
      Entry_Last : Stream_Element_Offset;
      New_Index_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      New_Index_Last : Stream_Element_Offset := New_Index_Data'First - 1;
      New_Entry_Count : Natural := 0;
      Version : Natural := 0;
      Existing_Entry_Count : Natural := 0;
      Existing_Mode : Natural := 0;
      Existing_Path : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Existing_Path_Last : Stream_Element_Offset;
      Existing_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Existing_ID_Last : Stream_Element_Offset;
      Existing_Size : Natural := 0;
      Status_Value : Status;

      function Same_Path
        (Path_Data : Stream_Element_Array;
         Path_Last : Stream_Element_Offset)
         return Boolean
      is
      begin
         if Path_Last < Path_Data'First
           or else Path_Last - Path_Data'First + 1
             /= Stream_Element_Offset (Path'Length)
         then
            return False;
         end if;

         for Index in Path'Range loop
            if Path_Data
              (Path_Data'First + Stream_Element_Offset (Index - Path'First))
              /= Character'Pos (Path (Index))
            then
               return False;
            end if;
         end loop;
         return True;
      end Same_Path;

      procedure Append_Entry
        (Mode      : Natural;
         Path_Data : Stream_Element_Array;
         Path_Last : Stream_Element_Offset;
         ID        : Stream_Element_Array;
         Size      : Natural;
         Result    : out Status)
      is
      begin
         Result := Ok;
         if Path_Last < Path_Data'First then
            Result := Invalid_Command;
            return;
         end if;

         declare
            Path_Text : String
              (1 .. Natural (Path_Last - Path_Data'First + 1));
         begin
            for Index in Path_Text'Range loop
               Path_Text (Index) :=
                 Character'Val
                   (Path_Data
                      (Path_Data'First
                       + Stream_Element_Offset (Index - 1)));
            end loop;

            Result :=
              Build_Index_Entry
                (Mode, Path_Text, ID, Size, Entry_Data, Entry_Last);
         end;

         if Result /= Ok then
            return;
         elsif New_Index_Last + (Entry_Last - Entry_Data'First) + 1
           > New_Index_Data'Last
         then
            Result := Read_Failed;
            return;
         end if;

         New_Index_Data
           (New_Index_Last + 1
            .. New_Index_Last + (Entry_Last - Entry_Data'First) + 1) :=
              Entry_Data (Entry_Data'First .. Entry_Last);
         New_Index_Last :=
           New_Index_Last + (Entry_Last - Entry_Data'First) + 1;
         New_Entry_Count := New_Entry_Count + 1;
      end Append_Entry;
   begin
      Last := Object_ID_Hex'First - 1;
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Worktree_Path (Path)
      then
         return Invalid_Command;
      end if;

      Status_Value :=
        Read_Worktree_File (Repository_Root, Path, File_Data, File_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Store_Loose_Object
          (Repository_Root,
           Pack_Blob,
           File_Data (File_Data'First .. File_Last),
           Object_ID_Hex,
           Last);
      if Status_Value /= Ok then
         Last := Object_ID_Hex'First - 1;
         return Status_Value;
      end if;

      Status_Value :=
        Parse_Object_ID_Hex
          (Object_ID_Hex
             (Object_ID_Hex'First
              .. Object_ID_Hex'First
                 + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                 - 1),
           Raw_ID,
           Raw_Last);
      if Status_Value /= Ok then
         Last := Object_ID_Hex'First - 1;
         return Status_Value;
      elsif Raw_Last /= Raw_ID'Last then
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      end if;

      Status_Value :=
        Read_Index_Header (Repository_Root, Version, Existing_Entry_Count);
      if Status_Value /= Ok then
         Last := Object_ID_Hex'First - 1;
         return Status_Value;
      end if;

      for Entry_Index in 0 .. Existing_Entry_Count - 1 loop
         Status_Value :=
           Read_Index_Entry
             (Repository_Root,
              Entry_Index,
              Existing_Mode,
              Existing_Path,
              Existing_Path_Last,
              Existing_ID,
              Existing_ID_Last,
              Existing_Size);
         if Status_Value /= Ok then
            Last := Object_ID_Hex'First - 1;
            return Status_Value;
         elsif Existing_ID_Last /= Existing_ID'Last then
            Last := Object_ID_Hex'First - 1;
            return Invalid_Command;
         elsif not Same_Path (Existing_Path, Existing_Path_Last) then
            Append_Entry
              (Existing_Mode,
               Existing_Path,
               Existing_Path_Last,
               Existing_ID,
               Existing_Size,
               Status_Value);
            if Status_Value /= Ok then
               Last := Object_ID_Hex'First - 1;
               return Status_Value;
            end if;
         end if;
      end loop;

      declare
         Path_Data : Stream_Element_Array
           (1 .. Stream_Element_Offset (Path'Length));
      begin
         for Index in Path'Range loop
            Path_Data
              (Path_Data'First + Stream_Element_Offset (Index - Path'First)) :=
                Character'Pos (Path (Index));
         end loop;
         Append_Entry
           (8#100644#,
            Path_Data,
            Path_Data'Last,
            Raw_ID,
            Natural (File_Last - File_Data'First + 1),
            Status_Value);
      end;
      if Status_Value /= Ok then
         Last := Object_ID_Hex'First - 1;
         return Status_Value;
      end if;

      Status_Value :=
        Write_Index
          (Repository_Root,
           New_Index_Data (New_Index_Data'First .. New_Index_Last),
           New_Entry_Count);
      if Status_Value /= Ok then
         Last := Object_ID_Hex'First - 1;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Last := Object_ID_Hex'First - 1;
         return Internal_Error;
   end Stage_Worktree_File;

   function Remove_Index_Path
     (Repository_Root : String;
      Path            : String;
      Removed         : out Boolean)
      return Status
   is
      New_Index_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      New_Index_Last : Stream_Element_Offset := New_Index_Data'First - 1;
      New_Entry_Count : Natural := 0;
      Version : Natural := 0;
      Existing_Entry_Count : Natural := 0;
      Existing_Mode : Natural := 0;
      Existing_Path : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Existing_Path_Last : Stream_Element_Offset;
      Existing_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Existing_ID_Last : Stream_Element_Offset;
      Existing_Size : Natural := 0;
      Entry_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length + 72));
      Entry_Last : Stream_Element_Offset;
      Status_Value : Status;

      function Same_Path
        (Path_Data : Stream_Element_Array;
         Path_Last : Stream_Element_Offset)
         return Boolean
      is
      begin
         if Path_Last < Path_Data'First
           or else Path_Last - Path_Data'First + 1
             /= Stream_Element_Offset (Path'Length)
         then
            return False;
         end if;

         for Index in Path'Range loop
            if Path_Data
              (Path_Data'First + Stream_Element_Offset (Index - Path'First))
              /= Character'Pos (Path (Index))
            then
               return False;
            end if;
         end loop;
         return True;
      end Same_Path;

      procedure Append_Existing (Result : out Status) is
      begin
         Result := Ok;
         if Existing_Path_Last < Existing_Path'First
           or else Existing_ID_Last /= Existing_ID'Last
         then
            Result := Invalid_Command;
            return;
         end if;

         declare
            Path_Text : String
              (1 .. Natural (Existing_Path_Last - Existing_Path'First + 1));
         begin
            for Index in Path_Text'Range loop
               Path_Text (Index) :=
                 Character'Val
                   (Existing_Path
                      (Existing_Path'First
                       + Stream_Element_Offset (Index - 1)));
            end loop;

            Result :=
              Build_Index_Entry
                (Existing_Mode,
                 Path_Text,
                 Existing_ID,
                 Existing_Size,
                 Entry_Data,
                 Entry_Last);
         end;

         if Result /= Ok then
            return;
         elsif New_Index_Last + (Entry_Last - Entry_Data'First) + 1
           > New_Index_Data'Last
         then
            Result := Read_Failed;
            return;
         end if;

         New_Index_Data
           (New_Index_Last + 1
            .. New_Index_Last + (Entry_Last - Entry_Data'First) + 1) :=
              Entry_Data (Entry_Data'First .. Entry_Last);
         New_Index_Last :=
           New_Index_Last + (Entry_Last - Entry_Data'First) + 1;
         New_Entry_Count := New_Entry_Count + 1;
      end Append_Existing;
   begin
      Removed := False;
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Worktree_Path (Path)
      then
         return Invalid_Command;
      end if;

      Status_Value :=
        Read_Index_Header (Repository_Root, Version, Existing_Entry_Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      for Entry_Index in 0 .. Existing_Entry_Count - 1 loop
         Status_Value :=
           Read_Index_Entry
             (Repository_Root,
              Entry_Index,
              Existing_Mode,
              Existing_Path,
              Existing_Path_Last,
              Existing_ID,
              Existing_ID_Last,
              Existing_Size);
         if Status_Value /= Ok then
            Removed := False;
            return Status_Value;
         elsif Same_Path (Existing_Path, Existing_Path_Last) then
            Removed := True;
         else
            Append_Existing (Status_Value);
            if Status_Value /= Ok then
               Removed := False;
               return Status_Value;
            end if;
         end if;
      end loop;

      if not Removed then
         return Ok;
      end if;

      if New_Entry_Count = 0 then
         return Write_Empty_Index (Repository_Root);
      end if;

      Status_Value :=
        Write_Index
          (Repository_Root,
           New_Index_Data (New_Index_Data'First .. New_Index_Last),
           New_Entry_Count);
      if Status_Value /= Ok then
         Removed := False;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Removed := False;
         return Invalid_Command;
      when others =>
         Removed := False;
         return Internal_Error;
   end Remove_Index_Path;

   function Reset_Index_To_Commit_Root
     (Repository_Root : String;
      Commit_ID_Hex   : Stream_Element_Array;
      Entry_Count     : out Natural)
      return Status
   is
      Pack_Checksums_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length * 16));
      Pack_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Index_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Pack_Checksum_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Pack_Checksum_Last : Stream_Element_Offset;
      Commit_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Commit_Last : Stream_Element_Offset;
      Root_Tree_ID_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Root_Tree_ID_Last : Stream_Element_Offset;
      Tree_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Tree_Last : Stream_Element_Offset;
      Tree_Entry_Count : Natural := 0;
      New_Index_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      New_Index_Last : Stream_Element_Offset := New_Index_Data'First - 1;
      New_Entry_Count : Natural := 0;
      Status_Value : Status;

      procedure Append_Tree
        (Current_Tree      : Stream_Element_Array;
         Current_Tree_Last : Stream_Element_Offset;
         Current_Count     : Natural;
         Prefix            : String;
         Depth             : Natural;
         Result            : out Status)
      is
         Entry_Offset : Natural := 0;
         File_Mode : Natural := 0;
         Name : Stream_Element_Array
           (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
         Name_Last : Stream_Element_Offset;
         Raw_ID : Stream_Element_Array
           (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
         Raw_ID_Last : Stream_Element_Offset;
         Object_ID_Hex : Stream_Element_Array
           (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
         Object_ID_Last : Stream_Element_Offset;
         Next_Offset : Natural := 0;
         Object_Kind : Pack_Object_Kind := Pack_Blob;
         Object_Data : Stream_Element_Array
           (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
         Object_Last : Stream_Element_Offset;
         Entry_Data : Stream_Element_Array
           (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length + 72));
         Entry_Last : Stream_Element_Offset;
      begin
         Result := Ok;
         if Depth > Maximum_Ref_Resolution_Depth then
            Result := Unsupported_Feature;
            return;
         end if;

         for Tree_Index in 1 .. Current_Count loop
            Result :=
              Parse_Tree_Entry
                (Current_Tree (Current_Tree'First .. Current_Tree_Last),
                 Entry_Offset,
                 File_Mode,
                 Name,
                 Name_Last,
                 Raw_ID,
                 Raw_ID_Last,
                 Next_Offset);
            if Result /= Ok then
               return;
            elsif Raw_ID_Last /= Raw_ID'Last
              or else Name_Last < Name'First
            then
               Result := Invalid_Command;
               return;
            end if;

            Result := Encode_Object_ID_Hex (Raw_ID, Object_ID_Hex, Object_ID_Last);
            if Result /= Ok then
               return;
            end if;

            Result :=
              Read_Loose_Object_Validated
                (Repository_Root,
                 Object_ID_Hex (Object_ID_Hex'First .. Object_ID_Last),
                 Object_Kind,
                 Object_Data,
                 Object_Last);
            if Result /= Ok then
               return;
            end if;

            declare
               Name_Text : String (1 .. Natural (Name_Last - Name'First + 1));
            begin
               for Index in Name_Text'Range loop
                  Name_Text (Index) :=
                    Character'Val
                      (Name (Name'First + Stream_Element_Offset (Index - 1)));
               end loop;

               declare
                  Path_Text : constant String :=
                    (if Prefix'Length = 0 then Name_Text
                     else Prefix & "/" & Name_Text);
                  Object_Size : Natural := 0;
                  Child_Count : Natural := 0;
               begin
                  if File_Mode = 8#040000# then
                     if Object_Kind /= Pack_Tree
                       or else Object_Last < Object_Data'First
                     then
                        Result := Unsupported_Feature;
                        return;
                     end if;
                     Result :=
                       Validate_Tree_Object
                         (Object_Data (Object_Data'First .. Object_Last),
                          Child_Count);
                     if Result /= Ok then
                        return;
                     end if;
                     Append_Tree
                       (Object_Data,
                        Object_Last,
                        Child_Count,
                        Path_Text,
                        Depth + 1,
                        Result);
                     if Result /= Ok then
                        return;
                     end if;
                  elsif Object_Kind = Pack_Blob then
                     if Object_Last >= Object_Data'First then
                        Object_Size :=
                          Natural (Object_Last - Object_Data'First + 1);
                     end if;

                     Result :=
                       Build_Index_Entry
                         (File_Mode,
                          Path_Text,
                          Raw_ID,
                          Object_Size,
                          Entry_Data,
                          Entry_Last);
                     if Result /= Ok then
                        return;
                     elsif New_Index_Last + (Entry_Last - Entry_Data'First) + 1
                       > New_Index_Data'Last
                     then
                        Result := Read_Failed;
                        return;
                     end if;

                     New_Index_Data
                       (New_Index_Last + 1
                        .. New_Index_Last + (Entry_Last - Entry_Data'First) + 1) :=
                          Entry_Data (Entry_Data'First .. Entry_Last);
                     New_Index_Last :=
                       New_Index_Last + (Entry_Last - Entry_Data'First) + 1;
                     New_Entry_Count := New_Entry_Count + 1;
                  else
                     Result := Unsupported_Feature;
                     return;
                  end if;
               end;
            end;

            Entry_Offset := Next_Offset;
         end loop;
      exception
         when Constraint_Error =>
            Result := Invalid_Command;
         when others =>
            Result := Internal_Error;
      end Append_Tree;
   begin
      Entry_Count := 0;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value :=
        Read_Commit_Tree_Object
          (Repository_Root,
           Commit_ID_Hex,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Commit_Data,
           Commit_Last,
           Root_Tree_ID_Hex,
           Root_Tree_ID_Last,
           Tree_Data,
           Tree_Last,
           Tree_Entry_Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Tree_Entry_Count = 0 then
         Status_Value := Write_Empty_Index (Repository_Root);
         if Status_Value = Ok then
            Entry_Count := 0;
         end if;
         return Status_Value;
      end if;

      Append_Tree
        (Tree_Data,
         Tree_Last,
         Tree_Entry_Count,
         "",
         0,
         Status_Value);
      if Status_Value /= Ok then
         Entry_Count := 0;
         return Status_Value;
      end if;

      Status_Value :=
        Write_Index
          (Repository_Root,
           New_Index_Data (New_Index_Data'First .. New_Index_Last),
           New_Entry_Count);
      if Status_Value = Ok then
         Entry_Count := New_Entry_Count;
      else
         Entry_Count := 0;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Entry_Count := 0;
         return Invalid_Command;
      when others =>
         Entry_Count := 0;
         return Internal_Error;
   end Reset_Index_To_Commit_Root;

   function Checkout_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Written_Count   : out Natural)
      return Status
   is
      Branch_ID_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Branch_ID_Last : Stream_Element_Offset;
      Reset_Count : Natural := 0;
      Status_Value : Status;
   begin
      Written_Count := 0;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value :=
        Resolve_Branch
          (Repository_Root, Branch_Name, Branch_ID_Hex, Branch_ID_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Branch_ID_Last /= Branch_ID_Hex'Last then
         return Invalid_Command;
      end if;

      Status_Value :=
        Reset_Index_To_Commit_Root
          (Repository_Root, Branch_ID_Hex, Reset_Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value := Attach_HEAD_To_Branch (Repository_Root, Branch_Name);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return Checkout_Index_All (Repository_Root, Written_Count);
   exception
      when Constraint_Error =>
         Written_Count := 0;
         return Invalid_Command;
      when others =>
         Written_Count := 0;
         return Internal_Error;
   end Checkout_Branch;

   function Is_Ancestor_First_Parent
     (Repository_Root      : String;
      Ancestor_Commit_Hex  : Stream_Element_Array;
      Descendant_Commit_Hex : Stream_Element_Array;
      Is_Ancestor          : out Boolean)
      return Status
   is
      Current_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Current_Last : Stream_Element_Offset := Current_ID'First - 1;
      Commit_Kind : Pack_Object_Kind := Pack_Blob;
      Commit_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Commit_Last : Stream_Element_Offset;
      Parent_Count : Natural := 0;
      Parent_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Parent_Last : Stream_Element_Offset;
      Status_Value : Status;

      function Same_ID
        (Left  : Stream_Element_Array;
         Right : Stream_Element_Array) return Boolean
      is
      begin
         if Left'Length /=
           Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
           or else Right'Length /=
             Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
         then
            return False;
         end if;

         for Index in 0 .. Object_ID_SHA1_Hex_Length - 1 loop
            if Left (Left'First + Stream_Element_Offset (Index))
              /= Right (Right'First + Stream_Element_Offset (Index))
            then
               return False;
            end if;
         end loop;
         return True;
      end Same_ID;
   begin
      Is_Ancestor := False;
      if not Valid_Repository_Root (Repository_Root)
        or else Ancestor_Commit_Hex'Length /=
          Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
        or else Descendant_Commit_Hex'Length /=
          Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Invalid_Command;
      end if;

      Current_ID := Descendant_Commit_Hex;
      Current_Last := Current_ID'Last;
      for Depth in 0 .. Maximum_Ref_Resolution_Depth loop
         if Same_ID (Ancestor_Commit_Hex, Current_ID) then
            Is_Ancestor := True;
            return Ok;
         end if;

         Status_Value :=
           Read_Loose_Object_Validated
             (Repository_Root,
              Current_ID (Current_ID'First .. Current_Last),
              Commit_Kind,
              Commit_Data,
              Commit_Last);
         if Status_Value /= Ok then
            Is_Ancestor := False;
            return Status_Value;
         elsif Commit_Kind /= Pack_Commit then
            Is_Ancestor := False;
            return Invalid_Command;
         end if;

         Status_Value :=
           Validate_Commit_Object
             (Commit_Data (Commit_Data'First .. Commit_Last),
              Parent_Count);
         if Status_Value /= Ok then
            Is_Ancestor := False;
            return Status_Value;
         elsif Parent_Count = 0 then
            Is_Ancestor := False;
            return Ok;
         end if;

         Status_Value :=
           Parse_Commit_Parent_ID
             (Commit_Data (Commit_Data'First .. Commit_Last),
              1,
              Parent_ID,
              Parent_Last);
         if Status_Value /= Ok then
            Is_Ancestor := False;
            return Status_Value;
         elsif Parent_Last /= Parent_ID'Last then
            Is_Ancestor := False;
            return Invalid_Command;
         end if;

         Current_ID := Parent_ID;
         Current_Last := Current_ID'Last;
      end loop;

      Is_Ancestor := False;
      return Unsupported_Feature;
   exception
      when Constraint_Error =>
         Is_Ancestor := False;
         return Invalid_Command;
      when others =>
         Is_Ancestor := False;
         return Internal_Error;
   end Is_Ancestor_First_Parent;

   function Fast_Forward_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      New_Commit_Hex  : Stream_Element_Array;
      Updated         : out Boolean)
      return Status
   is
      Current_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Current_Last : Stream_Element_Offset;
      Ancestor : Boolean := False;
      Status_Value : Status;
   begin
      Updated := False;
      if not Valid_Repository_Root (Repository_Root)
        or else New_Commit_Hex'Length /=
          Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Invalid_Command;
      end if;

      Status_Value :=
        Resolve_Branch
          (Repository_Root, Branch_Name, Current_ID, Current_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Current_Last /= Current_ID'Last then
         return Invalid_Command;
      elsif Current_ID = New_Commit_Hex then
         return Ok;
      end if;

      Status_Value :=
        Is_Ancestor_First_Parent
          (Repository_Root,
           Current_ID,
           New_Commit_Hex,
           Ancestor);
      if Status_Value /= Ok then
         return Status_Value;
      elsif not Ancestor then
         return Unsupported_Feature;
      end if;

      Status_Value :=
        Write_Branch (Repository_Root, Branch_Name, New_Commit_Hex);
      if Status_Value = Ok then
         Updated := True;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Updated := False;
         return Invalid_Command;
      when others =>
         Updated := False;
         return Internal_Error;
   end Fast_Forward_Branch;

   function Apply_Push_Branch_Update
     (Repository_Root        : String;
      Branch_Name            : String;
      Expected_Old_Hex       : Stream_Element_Array;
      New_Commit_Hex         : Stream_Element_Array;
      Allow_Non_Fast_Forward : Boolean;
      Updated                : out Boolean)
      return Status
   is
      Current_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Current_Last : Stream_Element_Offset;
      Ancestor : Boolean := False;
      Status_Value : Status;
   begin
      Updated := False;
      if not Valid_Repository_Root (Repository_Root)
        or else Expected_Old_Hex'Length /=
          Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
        or else New_Commit_Hex'Length /=
          Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Invalid_Command;
      end if;

      Status_Value :=
        Resolve_Branch
          (Repository_Root, Branch_Name, Current_ID, Current_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Current_Last /= Current_ID'Last
        or else Current_ID /= Expected_Old_Hex
      then
         return Invalid_Command;
      elsif Current_ID = New_Commit_Hex then
         return Ok;
      end if;

      if not Allow_Non_Fast_Forward then
         Status_Value :=
           Is_Ancestor_First_Parent
             (Repository_Root,
              Current_ID,
              New_Commit_Hex,
              Ancestor);
         if Status_Value /= Ok then
            return Status_Value;
         elsif not Ancestor then
            return Unsupported_Feature;
         end if;
      end if;

      Status_Value :=
        Write_Branch (Repository_Root, Branch_Name, New_Commit_Hex);
      if Status_Value = Ok then
         Updated := True;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Updated := False;
         return Invalid_Command;
      when others =>
         Updated := False;
         return Internal_Error;
   end Apply_Push_Branch_Update;

   function Commit_Index_To_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Author_Line     : String;
      Committer_Line  : String;
      Message         : String;
      Commit_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
      Version     : Natural := 0;
      Entry_Count : Natural := 0;
      File_Mode   : Natural := 0;
      Path_Buffer : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Path_Last   : Stream_Element_Offset;
      Object_ID   : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Object_Last : Stream_Element_Offset;
      File_Size   : Natural := 0;
      Entry_Data  : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length + 32));
      Entry_Last  : Stream_Element_Offset;
      Tree_Data   : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Tree_Last   : Stream_Element_Offset := Tree_Data'First - 1;
      Tree_ID_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Tree_ID_Last : Stream_Element_Offset;
      Commit_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Commit_Last : Stream_Element_Offset;
      Parent_ID_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length)) :=
          [others => Character'Pos ('0')];
      Parent_Last : Stream_Element_Offset := Parent_ID_Hex'First - 1;
      Has_Parent  : Boolean := False;
      Cursor      : Stream_Element_Offset := Tree_Data'First;
      Status_Value : Status;
   begin
      Last := Commit_ID_Hex'First - 1;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value := Read_Index_Header (Repository_Root, Version, Entry_Count);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Entry_Count = 0 then
         return Invalid_Command;
      end if;

      for Entry_Index in 0 .. Entry_Count - 1 loop
         Status_Value :=
           Read_Index_Entry
             (Repository_Root,
              Entry_Index,
              File_Mode,
              Path_Buffer,
              Path_Last,
              Object_ID,
              Object_Last,
              File_Size);
         if Status_Value /= Ok then
            Last := Commit_ID_Hex'First - 1;
            return Status_Value;
         elsif Path_Last < Path_Buffer'First
           or else Object_Last /= Object_ID'Last
         then
            Last := Commit_ID_Hex'First - 1;
            return Invalid_Command;
         end if;

         for Index in Path_Buffer'First .. Path_Last loop
            if Path_Buffer (Index) = Character'Pos ('/') then
               Last := Commit_ID_Hex'First - 1;
               return Unsupported_Feature;
            end if;
         end loop;

         declare
            Path_Text : String
              (1 .. Natural (Path_Last - Path_Buffer'First + 1));
         begin
            for Index in Path_Text'Range loop
               Path_Text (Index) :=
                 Character'Val
                   (Path_Buffer
                      (Path_Buffer'First
                       + Stream_Element_Offset (Index - 1)));
            end loop;

            Status_Value :=
              Build_Tree_Entry
                (File_Mode,
                 Path_Text,
                 Object_ID,
                 Entry_Data,
                 Entry_Last);
         end;
         if Status_Value /= Ok then
            Last := Commit_ID_Hex'First - 1;
            return Status_Value;
         elsif Cursor + (Entry_Last - Entry_Data'First) > Tree_Data'Last then
            Last := Commit_ID_Hex'First - 1;
            return Read_Failed;
         end if;

         Tree_Data (Cursor .. Cursor + (Entry_Last - Entry_Data'First)) :=
           Entry_Data (Entry_Data'First .. Entry_Last);
         Cursor := Cursor + (Entry_Last - Entry_Data'First) + 1;
         Tree_Last := Cursor - 1;
      end loop;

      Status_Value :=
        Store_Loose_Object
          (Repository_Root,
           Pack_Tree,
           Tree_Data (Tree_Data'First .. Tree_Last),
           Tree_ID_Hex,
           Tree_ID_Last);
      if Status_Value /= Ok then
         Last := Commit_ID_Hex'First - 1;
         return Status_Value;
      end if;

      Status_Value :=
        Read_Branch
          (Repository_Root, Branch_Name, Parent_ID_Hex, Parent_Last);
      if Status_Value = Ok then
         if Parent_Last /= Parent_ID_Hex'Last then
            Last := Commit_ID_Hex'First - 1;
            return Invalid_Command;
         end if;
         Has_Parent := True;
      elsif Status_Value = Read_Failed then
         Has_Parent := False;
      else
         Last := Commit_ID_Hex'First - 1;
         return Status_Value;
      end if;

      Status_Value :=
        Build_Commit_Object
          (Tree_ID_Hex,
           Has_Parent,
           Parent_ID_Hex,
           Author_Line,
           Committer_Line,
           Message,
           Commit_Data,
           Commit_Last);
      if Status_Value /= Ok then
         Last := Commit_ID_Hex'First - 1;
         return Status_Value;
      end if;

      Status_Value :=
        Store_Loose_Object
          (Repository_Root,
           Pack_Commit,
           Commit_Data (Commit_Data'First .. Commit_Last),
           Commit_ID_Hex,
           Last);
      if Status_Value /= Ok then
         Last := Commit_ID_Hex'First - 1;
         return Status_Value;
      end if;

      Status_Value :=
        Write_Branch
          (Repository_Root,
           Branch_Name,
           Commit_ID_Hex
             (Commit_ID_Hex'First
              .. Commit_ID_Hex'First
                 + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                 - 1));
      if Status_Value /= Ok then
         Last := Commit_ID_Hex'First - 1;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Last := Commit_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Last := Commit_ID_Hex'First - 1;
         return Internal_Error;
   end Commit_Index_To_Branch;

   function Stage_And_Commit_Worktree_File
     (Repository_Root : String;
      Branch_Name     : String;
      Path            : String;
      Author_Line     : String;
      Committer_Line  : String;
      Message         : String;
      Commit_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
      Staged_Object_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Staged_Object_Last : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Last := Commit_ID_Hex'First - 1;

      Status_Value :=
        Stage_Worktree_File
          (Repository_Root, Path, Staged_Object_Hex, Staged_Object_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return Commit_Index_To_Branch
        (Repository_Root,
         Branch_Name,
         Author_Line,
         Committer_Line,
         Message,
         Commit_ID_Hex,
         Last);
   exception
      when Constraint_Error =>
         Last := Commit_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Last := Commit_ID_Hex'First - 1;
         return Internal_Error;
   end Stage_And_Commit_Worktree_File;

   function Loose_Object_Path
     (Repository_Root : String;
      Object_ID_Hex   : Stream_Element_Array)
      return String
   is
      Prefix : String (1 .. 2);
      Suffix : String (1 .. Object_ID_SHA1_Hex_Length - 2);
   begin
      for Index in Prefix'Range loop
         Prefix (Index) :=
           Character'Val
             (Object_ID_Hex
                (Object_ID_Hex'First + Stream_Element_Offset (Index - 1)));
      end loop;
      for Index in Suffix'Range loop
         Suffix (Index) :=
           Character'Val
             (Object_ID_Hex
                (Object_ID_Hex'First + 1 + Stream_Element_Offset (Index)));
      end loop;
      return Ada.Directories.Compose
        (Git_Path (Repository_Root, "objects/" & Prefix), Suffix);
   end Loose_Object_Path;

   function Pack_File_Path
     (Repository_Root   : String;
      Pack_Checksum_Hex : Stream_Element_Array)
      return String
   is
      Name : String (1 .. Object_ID_SHA1_Hex_Length);
   begin
      for Index in Name'Range loop
         Name (Index) :=
           Character'Val
             (Pack_Checksum_Hex
                (Pack_Checksum_Hex'First
                 + Stream_Element_Offset (Index - 1)));
      end loop;
      return Ada.Directories.Compose
        (Git_Path (Repository_Root, "objects/pack"),
         "pack-" & Name & ".pack");
   end Pack_File_Path;

   function Pack_Index_Path
     (Repository_Root   : String;
      Pack_Checksum_Hex : Stream_Element_Array)
      return String
   is
      Name : String (1 .. Object_ID_SHA1_Hex_Length);
   begin
      for Index in Name'Range loop
         Name (Index) :=
           Character'Val
             (Pack_Checksum_Hex
                (Pack_Checksum_Hex'First
                 + Stream_Element_Offset (Index - 1)));
      end loop;
      return Ada.Directories.Compose
        (Git_Path (Repository_Root, "objects/pack"),
         "pack-" & Name & ".idx");
   end Pack_Index_Path;

   function Compress_Zlib
     (Data       : Stream_Element_Array;
      Compressed : out Stream_Element_Array;
      Last       : out Stream_Element_Offset)
      return Status
   is
      Filter  : Zlib.Compression_Filter_Type;
      In_Last : Stream_Element_Offset := Data'First - 1;
      First_Input : Stream_Element_Offset := Data'First;
      Out_Data : Stream_Element_Array (1 .. 4096);
      Out_Last : Stream_Element_Offset := Out_Data'First - 1;
      Cursor   : Stream_Element_Offset := Compressed'First;

      function Append_Output return Status is
         Count : Stream_Element_Offset;
      begin
         if Out_Last < Out_Data'First then
            return Ok;
         end if;
         Count := Out_Last - Out_Data'First + 1;
         if Cursor > Compressed'Last
           or else Count > Compressed'Last - Cursor + 1
         then
            return Write_Failed;
         end if;
         Compressed (Cursor .. Cursor + Count - 1) :=
           Out_Data (Out_Data'First .. Out_Last);
         Cursor := Cursor + Count;
         Last := Cursor - 1;
         return Ok;
      end Append_Output;
   begin
      Last := Compressed'First - 1;
      Zlib.Deflate_Init
        (Filter,
         Header => Zlib.Zlib_Header,
         Mode   => Zlib.Auto);

      if Data'Length > 0 then
         while First_Input <= Data'Last loop
            Zlib.Compress
              (Filter,
               Data (First_Input .. Data'Last),
               In_Last,
               Out_Data,
               Out_Last,
               Zlib.No_Flush);
            if Append_Output /= Ok then
               Last := Compressed'First - 1;
               return Write_Failed;
            end if;
            if In_Last >= First_Input then
               First_Input := In_Last + 1;
            elsif Out_Last < Out_Data'First then
               Last := Compressed'First - 1;
               return Write_Failed;
            end if;
         end loop;
      end if;

      loop
         Zlib.Compress_Flush (Filter, Out_Data, Out_Last, Zlib.Finish);
         exit when Out_Last < Out_Data'First;
         if Append_Output /= Ok then
            Last := Compressed'First - 1;
            return Write_Failed;
         end if;
      end loop;

      return Ok;
   exception
      when Zlib.Zlib_Error | Zlib.Status_Error =>
         Last := Compressed'First - 1;
         return Write_Failed;
      when others =>
         Last := Compressed'First - 1;
         return Internal_Error;
   end Compress_Zlib;

   function Inflate_Zlib_Bounded
     (Compressed : Stream_Element_Array;
      Inflated   : out Stream_Element_Array;
      Last       : out Stream_Element_Offset)
      return Status
   is
      Filter  : Zlib.Filter_Type;
      In_Last : Stream_Element_Offset := Compressed'First - 1;
   begin
      Last := Inflated'First - 1;
      Zlib.Inflate_Init (Filter, Header => Zlib.Zlib_Header);
      Zlib.Translate
        (Filter, Compressed, In_Last, Inflated, Last, Zlib.Finish);
      if not Zlib.Stream_End (Filter) or else In_Last < Compressed'Last then
         Zlib.Close (Filter, Ignore_Error => True);
         Last := Inflated'First - 1;
         return Read_Failed;
      end if;
      Zlib.Close (Filter, Ignore_Error => True);
      return Ok;
   exception
      when Zlib.Zlib_Error | Zlib.Status_Error =>
         if Zlib.Is_Open (Filter) then
            Zlib.Close (Filter, Ignore_Error => True);
         end if;
         Last := Inflated'First - 1;
         return Read_Failed;
      when others =>
         if Zlib.Is_Open (Filter) then
            Zlib.Close (Filter, Ignore_Error => True);
         end if;
         Last := Inflated'First - 1;
         return Internal_Error;
   end Inflate_Zlib_Bounded;

   function Store_Loose_Object
     (Repository_Root : String;
      Kind            : Pack_Object_Kind;
      Data            : Stream_Element_Array;
      Object_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
      Name : constant String := Kind_Name (Kind);

      function Decimal_Length (Value : Natural) return Natural is
         Work  : Natural := Value;
         Count : Natural := 1;
      begin
         while Work >= 10 loop
            Work := Work / 10;
            Count := Count + 1;
         end loop;
         return Count;
      end Decimal_Length;

      Raw_ID       : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last     : Stream_Element_Offset;
      Size_Digits  : Natural;
      Header_Size  : Natural;
      Total_Size   : Natural;
      Status_Value : Status;
   begin
      Last := Object_ID_Hex'First - 1;
      if not Valid_Repository_Root (Repository_Root)
        or else Name'Length = 0
      then
         return Invalid_Command;
      elsif Object_ID_Hex'Length
        < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Read_Failed;
      elsif Data'Length > Stream_Element_Offset (Natural'Last) then
         return Unsupported_Feature;
      end if;

      Status_Value := Compute_Object_ID (Kind, Data, Raw_ID, Raw_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Encode_Object_ID_Hex (Raw_ID, Object_ID_Hex, Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Size_Digits := Decimal_Length (Natural (Data'Length));
      Header_Size := Name'Length + 1 + Size_Digits + 1;
      Total_Size := Header_Size + Natural (Data'Length);

      declare
         Preimage   : Stream_Element_Array (1 .. Stream_Element_Offset (Total_Size));
         Comp_Size  : constant Natural := Total_Size + Total_Size / 100 + 1024;
         Compressed : Stream_Element_Array (1 .. Stream_Element_Offset (Comp_Size));
         Comp_Last  : Stream_Element_Offset;
         Cursor     : Stream_Element_Offset := Preimage'First;
         Work_Size  : Natural := Natural (Data'Length);
         Dir_Path   : constant String :=
           Git_Path
             (Repository_Root,
              "objects/"
              & Character'Val (Object_ID_Hex (Object_ID_Hex'First))
              & Character'Val (Object_ID_Hex (Object_ID_Hex'First + 1)));
         File_Path  : constant String :=
           Loose_Object_Path (Repository_Root, Object_ID_Hex);
         File       : Stream_IO.File_Type;
      begin
         for Ch of Name loop
            Preimage (Cursor) := Stream_Element (Character'Pos (Ch));
            Cursor := Cursor + 1;
         end loop;
         Preimage (Cursor) := Stream_Element (Character'Pos (' '));
         Cursor := Cursor + 1;
         for Position in reverse 0 .. Size_Digits - 1 loop
            declare
               Divisor : Natural := 1;
            begin
               for Step in 1 .. Position loop
                  Divisor := Divisor * 10;
               end loop;
               Preimage (Cursor) :=
                 Stream_Element (Character'Pos ('0') + Work_Size / Divisor);
               Work_Size := Work_Size mod Divisor;
               Cursor := Cursor + 1;
            end;
         end loop;
         Preimage (Cursor) := 0;
         Cursor := Cursor + 1;
         if Data'Length > 0 then
            Preimage (Cursor .. Preimage'Last) := Data;
         end if;

         Status_Value := Compress_Zlib (Preimage, Compressed, Comp_Last);
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         Ada.Directories.Create_Path (Dir_Path);
         Stream_IO.Create (File, Stream_IO.Out_File, File_Path);
         Stream_IO.Write (File, Compressed (Compressed'First .. Comp_Last));
         Stream_IO.Close (File);
      exception
         when others =>
            if Stream_IO.Is_Open (File) then
               Stream_IO.Close (File);
            end if;
            return Write_Failed;
      end;

      return Ok;
   exception
      when Constraint_Error =>
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Last := Object_ID_Hex'First - 1;
         return Internal_Error;
   end Store_Loose_Object;

   function Store_Loose_Object_Validated
     (Repository_Root : String;
      Kind            : Pack_Object_Kind;
      Data            : Stream_Element_Array;
      Object_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
      Status_Value : Status;
   begin
      Last := Object_ID_Hex'First - 1;
      Status_Value := Validate_Object_Data (Kind, Data);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return
        Store_Loose_Object
          (Repository_Root, Kind, Data, Object_ID_Hex, Last);
   exception
      when Constraint_Error =>
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Last := Object_ID_Hex'First - 1;
         return Internal_Error;
   end Store_Loose_Object_Validated;

   function Delete_Loose_Object
     (Repository_Root : String;
      Object_ID_Hex   : Stream_Element_Array)
      return Status
   is
      use type Ada.Directories.File_Kind;
      Raw_ID   : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last : Stream_Element_Offset;
      Status_Value : Status;
      Path : constant String := Loose_Object_Path (Repository_Root, Object_ID_Hex);
   begin
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value := Parse_Object_ID_Hex (Object_ID_Hex, Raw_ID, Raw_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Raw_Last /= Raw_ID'Last then
         return Invalid_Command;
      elsif not Ada.Directories.Exists (Path) then
         return Read_Failed;
      elsif Ada.Directories.Kind (Path) /= Ada.Directories.Ordinary_File then
         return Invalid_Command;
      end if;

      Ada.Directories.Delete_File (Path);
      return Ok;
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Delete_Loose_Object;

   function Read_Loose_Object
     (Repository_Root : String;
      Object_ID_Hex   : Stream_Element_Array;
      Kind            : out Pack_Object_Kind;
      Data            : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
      Raw_ID     : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last   : Stream_Element_Offset;
      File       : Stream_IO.File_Type;
      File_Size  : Stream_IO.Count;
      Status_Value : Status;
   begin
      Kind := Pack_Blob;
      Last := Data'First - 1;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;
      Status_Value := Parse_Object_ID_Hex (Object_ID_Hex, Raw_ID, Raw_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Stream_IO.Open
        (File, Stream_IO.In_File, Loose_Object_Path (Repository_Root, Object_ID_Hex));
      File_Size := Stream_IO.Size (File);
      if File_Size = 0
        or else File_Size > Stream_IO.Count (Natural'Last)
      then
         Stream_IO.Close (File);
         return Read_Failed;
      end if;

      declare
         Compressed : Stream_Element_Array
           (1 .. Stream_Element_Offset (File_Size));
         Comp_Last : Stream_Element_Offset;
         Inflated : Stream_Element_Array
           (1 .. Data'Length + Stream_Element_Offset (128));
         Inflated_Last : Stream_Element_Offset;
         Header_Last : Stream_Element_Offset := Inflated'First - 1;
         Size_Start  : Stream_Element_Offset;
         Declared_Size : Natural := 0;
      begin
         Stream_IO.Read (File, Compressed, Comp_Last);
         Stream_IO.Close (File);
         if Comp_Last /= Compressed'Last then
            return Read_Failed;
         end if;

         Status_Value :=
           Inflate_Zlib_Bounded (Compressed, Inflated, Inflated_Last);
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         while Header_Last < Inflated_Last
           and then Inflated (Header_Last + 1) /= Stream_Element (Character'Pos (' '))
         loop
            Header_Last := Header_Last + 1;
         end loop;
         if Header_Last < Inflated'First
           or else Header_Last >= Inflated_Last
         then
            return Invalid_Command;
         end if;

         declare
            Name : String
              (1 .. Natural (Header_Last - Inflated'First + 1));
         begin
            for Index in Name'Range loop
               Name (Index) :=
                 Character'Val
                   (Inflated
                      (Inflated'First + Stream_Element_Offset (Index - 1)));
            end loop;
            if not Kind_From_Name (Name, Kind) then
               return Invalid_Command;
            end if;
         end;

         Size_Start := Header_Last + 2;
         if Size_Start > Inflated_Last then
            return Invalid_Command;
         end if;
         declare
            Cursor : Stream_Element_Offset := Size_Start;
         begin
            while Cursor <= Inflated_Last
              and then Inflated (Cursor) /= 0
            loop
               if Inflated (Cursor) < Character'Pos ('0')
                 or else Inflated (Cursor) > Character'Pos ('9')
               then
                  return Invalid_Command;
               end if;
               if Declared_Size > (Natural'Last - 9) / 10 then
                  return Unsupported_Feature;
               end if;
               Declared_Size :=
                 Declared_Size * 10
                 + Natural (Inflated (Cursor) - Character'Pos ('0'));
               Cursor := Cursor + 1;
            end loop;
            if Cursor > Inflated_Last
              or else Inflated (Cursor) /= 0
              or else Declared_Size > Natural (Data'Length)
              or else Stream_Element_Offset (Declared_Size)
                /= Inflated_Last - Cursor
            then
               return Read_Failed;
            end if;
            if Declared_Size > 0 then
               Data
                 (Data'First
                  .. Data'First + Stream_Element_Offset (Declared_Size) - 1) :=
                    Inflated
                      (Cursor + 1
                       .. Cursor + Stream_Element_Offset (Declared_Size));
            end if;
            Last :=
              Data'First + Stream_Element_Offset (Declared_Size) - 1;
         end;
      end;

      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Read_Failed;
   end Read_Loose_Object;

   function Read_Loose_Object_Validated
     (Repository_Root : String;
      Object_ID_Hex   : Stream_Element_Array;
      Kind            : out Pack_Object_Kind;
      Data            : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
      Status_Value : Status;
   begin
      Status_Value :=
        Read_Loose_Object (Repository_Root, Object_ID_Hex, Kind, Data, Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Last < Data'First then
         if Kind = Pack_Blob then
            return Ok;
         end if;
         return Invalid_Command;
      end if;

      Status_Value :=
        Validate_Object_Data (Kind, Data (Data'First .. Last));
      if Status_Value /= Ok then
         Last := Data'First - 1;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Invalid_Command;
      when others =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Read_Failed;
   end Read_Loose_Object_Validated;

   function Store_Pack_File
     (Repository_Root    : String;
      Pack_Data          : Stream_Element_Array;
      Pack_Checksum_Hex  : out Stream_Element_Array;
      Last               : out Stream_Element_Offset)
      return Status
   is
      Raw_Checksum : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Trailer_First : Stream_Element_Offset;
      Status_Value : Status;
      File         : Stream_IO.File_Type;
   begin
      Last := Pack_Checksum_Hex'First - 1;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      elsif Pack_Checksum_Hex'Length
        < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Read_Failed;
      end if;

      Status_Value := Verify_Pack_Trailer_Checksum (Pack_Data);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Trailer_First :=
        Pack_Data'Last - Stream_Element_Offset (Object_ID_SHA1_Raw_Length) + 1;
      Raw_Checksum := Pack_Data (Trailer_First .. Pack_Data'Last);
      Status_Value :=
        Encode_Object_ID_Hex (Raw_Checksum, Pack_Checksum_Hex, Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Ada.Directories.Create_Path (Git_Path (Repository_Root, "objects/pack"));
      Stream_IO.Create
        (File,
         Stream_IO.Out_File,
         Pack_File_Path
           (Repository_Root,
            Pack_Checksum_Hex
              (Pack_Checksum_Hex'First
               .. Pack_Checksum_Hex'First
                  + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                  - 1)));
      Stream_IO.Write (File, Pack_Data);
      Stream_IO.Close (File);
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Last := Pack_Checksum_Hex'First - 1;
         return Write_Failed;
   end Store_Pack_File;

   function Read_Pack_File
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Stream_Element_Array;
      Pack_Data          : out Stream_Element_Array;
      Last               : out Stream_Element_Offset)
      return Status
   is
      Raw_ID   : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last : Stream_Element_Offset;
      File     : Stream_IO.File_Type;
      File_Size : Stream_IO.Count;
      Status_Value : Status;
   begin
      Last := Pack_Data'First - 1;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;
      Status_Value := Parse_Object_ID_Hex (Pack_Checksum_Hex, Raw_ID, Raw_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Stream_IO.Open
        (File,
         Stream_IO.In_File,
         Pack_File_Path (Repository_Root, Pack_Checksum_Hex));
      File_Size := Stream_IO.Size (File);
      if File_Size = 0
        or else File_Size > Stream_IO.Count (Pack_Data'Length)
      then
         Stream_IO.Close (File);
         return Read_Failed;
      end if;

      declare
         Data_Last : Stream_Element_Offset;
      begin
         Stream_IO.Read
           (File,
            Pack_Data
              (Pack_Data'First
               .. Pack_Data'First + Stream_Element_Offset (File_Size) - 1),
            Data_Last);
         Stream_IO.Close (File);
         if Data_Last /=
           Pack_Data'First + Stream_Element_Offset (File_Size) - 1
         then
            return Read_Failed;
         end if;
         Last := Data_Last;
      end;

      Status_Value :=
        Verify_Pack_Trailer_Checksum (Pack_Data (Pack_Data'First .. Last));
      if Status_Value /= Ok then
         Last := Pack_Data'First - 1;
         return Status_Value;
      end if;
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Last := Pack_Data'First - 1;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Last := Pack_Data'First - 1;
         return Read_Failed;
   end Read_Pack_File;

   function Delete_Pack_File
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Stream_Element_Array)
      return Status
   is
      use type Ada.Directories.File_Kind;
      Raw_ID   : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last : Stream_Element_Offset;
      Status_Value : Status;
      Path : constant String := Pack_File_Path (Repository_Root, Pack_Checksum_Hex);
   begin
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value := Parse_Object_ID_Hex (Pack_Checksum_Hex, Raw_ID, Raw_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Raw_Last /= Raw_ID'Last then
         return Invalid_Command;
      elsif not Ada.Directories.Exists (Path) then
         return Read_Failed;
      elsif Ada.Directories.Kind (Path) /= Ada.Directories.Ordinary_File then
         return Invalid_Command;
      end if;

      Ada.Directories.Delete_File (Path);
      return Ok;
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Delete_Pack_File;

   function Store_Pack_Index
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Stream_Element_Array;
      Index_Data         : Stream_Element_Array)
      return Status
   is
      Raw_ID   : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last : Stream_Element_Offset;
      Status_Value : Status;
      File     : Stream_IO.File_Type;
   begin
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value := Parse_Object_ID_Hex (Pack_Checksum_Hex, Raw_ID, Raw_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Raw_Last /= Raw_ID'Last then
         return Invalid_Command;
      end if;

      Status_Value := Verify_Pack_Index_Checksum (Index_Data);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Verify_Pack_Index_Pack_Checksum (Index_Data, Raw_ID);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Ada.Directories.Create_Path (Git_Path (Repository_Root, "objects/pack"));
      Stream_IO.Create
        (File,
         Stream_IO.Out_File,
         Pack_Index_Path (Repository_Root, Pack_Checksum_Hex));
      Stream_IO.Write (File, Index_Data);
      Stream_IO.Close (File);
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Write_Failed;
   end Store_Pack_Index;

   function Read_Pack_Index
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Stream_Element_Array;
      Index_Data         : out Stream_Element_Array;
      Last               : out Stream_Element_Offset)
      return Status
   is
      Raw_ID   : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last : Stream_Element_Offset;
      File     : Stream_IO.File_Type;
      File_Size : Stream_IO.Count;
      Status_Value : Status;
   begin
      Last := Index_Data'First - 1;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value := Parse_Object_ID_Hex (Pack_Checksum_Hex, Raw_ID, Raw_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Raw_Last /= Raw_ID'Last then
         return Invalid_Command;
      end if;

      Stream_IO.Open
        (File,
         Stream_IO.In_File,
         Pack_Index_Path (Repository_Root, Pack_Checksum_Hex));
      File_Size := Stream_IO.Size (File);
      if File_Size = 0
        or else File_Size > Stream_IO.Count (Index_Data'Length)
      then
         Stream_IO.Close (File);
         return Read_Failed;
      end if;

      declare
         Data_Last : Stream_Element_Offset;
      begin
         Stream_IO.Read
           (File,
            Index_Data
              (Index_Data'First
               .. Index_Data'First + Stream_Element_Offset (File_Size) - 1),
            Data_Last);
         Stream_IO.Close (File);
         if Data_Last /=
           Index_Data'First + Stream_Element_Offset (File_Size) - 1
         then
            return Read_Failed;
         end if;
         Last := Data_Last;
      end;

      Status_Value :=
        Verify_Pack_Index_Checksum (Index_Data (Index_Data'First .. Last));
      if Status_Value /= Ok then
         Last := Index_Data'First - 1;
         return Status_Value;
      end if;
      Status_Value :=
        Verify_Pack_Index_Pack_Checksum
          (Index_Data (Index_Data'First .. Last), Raw_ID);
      if Status_Value /= Ok then
         Last := Index_Data'First - 1;
         return Status_Value;
      end if;
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Last := Index_Data'First - 1;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Last := Index_Data'First - 1;
         return Read_Failed;
   end Read_Pack_Index;

   function Delete_Pack_Index
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Stream_Element_Array)
      return Status
   is
      use type Ada.Directories.File_Kind;
      Raw_ID   : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last : Stream_Element_Offset;
      Status_Value : Status;
      Path : constant String := Pack_Index_Path (Repository_Root, Pack_Checksum_Hex);
   begin
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value := Parse_Object_ID_Hex (Pack_Checksum_Hex, Raw_ID, Raw_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Raw_Last /= Raw_ID'Last then
         return Invalid_Command;
      elsif not Ada.Directories.Exists (Path) then
         return Read_Failed;
      elsif Ada.Directories.Kind (Path) /= Ada.Directories.Ordinary_File then
         return Invalid_Command;
      end if;

      Ada.Directories.Delete_File (Path);
      return Ok;
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Delete_Pack_Index;

   function Delete_Stored_Pack
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Stream_Element_Array;
      Deleted_Pack_File  : out Boolean;
      Deleted_Pack_Index : out Boolean)
      return Status
   is
      use type Ada.Directories.File_Kind;
      Raw_ID   : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last : Stream_Element_Offset;
      Status_Value : Status;
      Pack_Path  : constant String := Pack_File_Path (Repository_Root, Pack_Checksum_Hex);
      Index_Path : constant String := Pack_Index_Path (Repository_Root, Pack_Checksum_Hex);
      Has_Pack  : Boolean := False;
      Has_Index : Boolean := False;
   begin
      Deleted_Pack_File := False;
      Deleted_Pack_Index := False;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value := Parse_Object_ID_Hex (Pack_Checksum_Hex, Raw_ID, Raw_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Raw_Last /= Raw_ID'Last then
         return Invalid_Command;
      end if;

      Has_Pack := Ada.Directories.Exists (Pack_Path);
      Has_Index := Ada.Directories.Exists (Index_Path);
      if Has_Pack
        and then Ada.Directories.Kind (Pack_Path) /= Ada.Directories.Ordinary_File
      then
         return Invalid_Command;
      elsif Has_Index
        and then Ada.Directories.Kind (Index_Path) /= Ada.Directories.Ordinary_File
      then
         return Invalid_Command;
      elsif not Has_Pack and then not Has_Index then
         return Read_Failed;
      end if;

      if Has_Pack then
         Ada.Directories.Delete_File (Pack_Path);
         Deleted_Pack_File := True;
      end if;
      if Has_Index then
         Ada.Directories.Delete_File (Index_Path);
         Deleted_Pack_Index := True;
      end if;
      return Ok;
   exception
      when Constraint_Error =>
         Deleted_Pack_File := False;
         Deleted_Pack_Index := False;
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Delete_Stored_Pack;

   function Read_Packed_Object
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Stream_Element_Array;
      Object_ID_Hex      : Stream_Element_Array;
      Pack_Data          : out Stream_Element_Array;
      Index_Data         : out Stream_Element_Array;
      Kind               : out Pack_Object_Kind;
      Data               : out Stream_Element_Array;
      Last               : out Stream_Element_Offset)
      return Status
   is
      Pack_Last       : Stream_Element_Offset;
      Index_Last      : Stream_Element_Offset;
      Object_Index    : Natural := 0;
      Pack_Offset     : Natural := 0;
      Size            : Natural := 0;
      Header_Size     : Natural := 0;
      Payload_Offset  : Natural := 0;
      Next_Offset     : Natural := 0;
      Requested_ID    : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Requested_Last  : Stream_Element_Offset;
      Computed_ID     : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Computed_Last   : Stream_Element_Offset;
      Status_Value    : Status;

      function Same_Raw_ID (Left, Right : Stream_Element_Array) return Boolean is
      begin
         if Left'Length /= Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
           or else Right'Length /= Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
         then
            return False;
         end if;
         for Offset in 0 .. Object_ID_SHA1_Raw_Length - 1 loop
            if Left (Left'First + Stream_Element_Offset (Offset))
              /= Right (Right'First + Stream_Element_Offset (Offset))
            then
               return False;
            end if;
         end loop;
         return True;
      end Same_Raw_ID;
   begin
      Kind := Pack_Blob;
      Last := Data'First - 1;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value :=
        Parse_Object_ID_Hex (Object_ID_Hex, Requested_ID, Requested_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Requested_Last /= Requested_ID'Last then
         return Invalid_Command;
      end if;

      Status_Value :=
        Read_Pack_File
          (Repository_Root, Pack_Checksum_Hex, Pack_Data, Pack_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Read_Pack_Index
          (Repository_Root, Pack_Checksum_Hex, Index_Data, Index_Last);
      if Status_Value /= Ok then
         Last := Data'First - 1;
         return Status_Value;
      end if;

      Status_Value :=
        Find_Pack_Index_Object_Hex
          (Index_Data (Index_Data'First .. Index_Last),
           Object_ID_Hex,
           Object_Index,
           Pack_Offset);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Inflate_Pack_Object_At_Offset
          (Pack_Data (Pack_Data'First .. Pack_Last),
           Pack_Offset,
           Kind,
           Size,
           Header_Size,
           Payload_Offset,
           Data,
           Last,
           Next_Offset);
      if Status_Value /= Ok then
         Last := Data'First - 1;
         return Status_Value;
      elsif Header_Size = 0
        or else Payload_Offset <= Pack_Offset
        or else Next_Offset <= Pack_Offset
        or else Size > Natural (Data'Length)
      then
         Last := Data'First - 1;
         return Invalid_Command;
      elsif Kind in Pack_OFS_Delta | Pack_REF_Delta then
         Last := Data'First - 1;
         return Unsupported_Feature;
      end if;

      Status_Value :=
        Compute_Object_ID
          (Kind,
           Data (Data'First .. Last),
           Computed_ID,
           Computed_Last);
      if Status_Value /= Ok then
         Last := Data'First - 1;
         return Status_Value;
      elsif Computed_Last /= Computed_ID'Last
        or else not Same_Raw_ID (Requested_ID, Computed_ID)
      then
         Last := Data'First - 1;
         return Invalid_Command;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Invalid_Command;
      when others =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Read_Failed;
   end Read_Packed_Object;

   function Read_Packed_Object_Validated
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Stream_Element_Array;
      Object_ID_Hex      : Stream_Element_Array;
      Pack_Data          : out Stream_Element_Array;
      Index_Data         : out Stream_Element_Array;
      Kind               : out Pack_Object_Kind;
      Data               : out Stream_Element_Array;
      Last               : out Stream_Element_Offset)
      return Status
   is
      Status_Value : Status;
   begin
      Status_Value :=
        Read_Packed_Object
          (Repository_Root,
           Pack_Checksum_Hex,
           Object_ID_Hex,
           Pack_Data,
           Index_Data,
           Kind,
           Data,
           Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Last < Data'First then
         if Kind = Pack_Blob then
            return Ok;
         end if;
         return Invalid_Command;
      end if;

      Status_Value :=
        Validate_Object_Data (Kind, Data (Data'First .. Last));
      if Status_Value /= Ok then
         Last := Data'First - 1;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Invalid_Command;
      when others =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Read_Failed;
   end Read_Packed_Object_Validated;

   function Read_Packed_Object_Resolved
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Stream_Element_Array;
      Object_ID_Hex      : Stream_Element_Array;
      Pack_Data          : out Stream_Element_Array;
      Index_Data         : out Stream_Element_Array;
      Base_Data          : out Stream_Element_Array;
      Delta_Data         : out Stream_Element_Array;
      Workspace          : out Stream_Element_Array;
      Kind               : out Pack_Object_Kind;
      Data               : out Stream_Element_Array;
      Last               : out Stream_Element_Offset)
      return Status
   is
      Pack_Last       : Stream_Element_Offset;
      Index_Last      : Stream_Element_Offset;
      Object_Index    : Natural := 0;
      Pack_Offset     : Natural := 0;
      Size            : Natural := 0;
      Header_Size     : Natural := 0;
      Payload_Offset  : Natural := 0;
      Next_Offset     : Natural := 0;
      Count_Value     : Natural := 0;
      Trailer_Value   : Natural := 0;
      Large_Count     : Natural := 0;
      Layout          : Pack_Index_Layout;
      Requested_ID    : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Requested_Last  : Stream_Element_Offset;
      Computed_ID     : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Computed_Last   : Stream_Element_Offset;
      Status_Value    : Status;

      function Same_Raw_ID (Left, Right : Stream_Element_Array) return Boolean is
      begin
         if Left'Length /= Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
           or else Right'Length /= Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
         then
            return False;
         end if;
         for Offset in 0 .. Object_ID_SHA1_Raw_Length - 1 loop
            if Left (Left'First + Stream_Element_Offset (Offset))
              /= Right (Right'First + Stream_Element_Offset (Offset))
            then
               return False;
            end if;
         end loop;
         return True;
      end Same_Raw_ID;

      function Index_At (Offset : Natural) return Stream_Element_Offset is
      begin
         return Index_Data'First + Stream_Element_Offset (Offset);
      end Index_At;

      function Resolve_Index_Offset
        (Index       : Natural;
         Found_Offset : out Natural)
         return Status
      is
         Large_Index : Natural := 0;
         Uses_Large  : Boolean := False;
      begin
         Found_Offset := 0;
         Status_Value :=
           Parse_Pack_Index_Offset
             (Index_Data (Index_At (Layout.Offsets_Offset) .. Index_Last),
              Index,
              Found_Offset,
              Large_Index,
              Uses_Large);
         if Status_Value /= Ok then
            return Status_Value;
         elsif Uses_Large then
            return
              Parse_Pack_Index_Large_Offset
                (Index_Data (Index_At (Layout.Large_Offsets_Offset) .. Index_Last),
                 Large_Index,
                 Found_Offset);
         end if;
         return Ok;
      end Resolve_Index_Offset;

      function Find_Index_By_Offset
        (Target_Offset : Natural;
         Target_Index  : out Natural)
         return Status
      is
      begin
         Target_Index := 0;
         if Count_Value > 0 then
            for Index in 0 .. Count_Value - 1 loop
               declare
                  Candidate : Natural := 0;
               begin
                  Status_Value := Resolve_Index_Offset (Index, Candidate);
                  if Status_Value /= Ok then
                     return Status_Value;
                  elsif Candidate = Target_Offset then
                     Target_Index := Index;
                     return Ok;
                  end if;
               end;
            end loop;
         end if;
         return Invalid_Command;
      end Find_Index_By_Offset;

      function Object_Kind_At
        (Index       : Natural;
         Found_Kind  : out Pack_Object_Kind;
         Found_Offset : out Natural;
         Found_Header : out Natural)
         return Status
      is
         Ignored_Size : Natural := 0;
      begin
         Status_Value := Resolve_Index_Offset (Index, Found_Offset);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         return
           Parse_Pack_Object_Header
             (Pack_Data
                (Pack_Data'First + Stream_Element_Offset (Found_Offset)
                 .. Pack_Last),
              Found_Kind,
              Ignored_Size,
              Found_Header);
      end Object_Kind_At;

      function Resolve_Delta_Base_Index
        (Delta_Offset : Natural;
         Delta_Header : Natural;
         Delta_Kind   : Pack_Object_Kind;
         Base_Index   : out Natural)
         return Status
      is
         Base_First : constant Stream_Element_Offset :=
           Pack_Data'First + Stream_Element_Offset (Delta_Offset + Delta_Header);
      begin
         Base_Index := 0;
         if Base_First > Pack_Last then
            return Read_Failed;
         end if;
         case Delta_Kind is
            when Pack_REF_Delta =>
               declare
                  Base_ID : Stream_Element_Array
                    (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
                  Base_Last : Stream_Element_Offset;
                  Consumed  : Natural := 0;
                  Ignored_Offset : Natural := 0;
               begin
                  Status_Value :=
                    Parse_Pack_REF_Delta_Base
                      (Pack_Data (Base_First .. Pack_Last),
                       Base_ID,
                       Base_Last,
                       Consumed);
                  if Status_Value /= Ok then
                     return Status_Value;
                  elsif Base_Last /= Base_ID'Last then
                     return Invalid_Command;
                  end if;
                  return
                    Find_Pack_Index_Object
                      (Index_Data (Index_Data'First .. Index_Last),
                       Base_ID,
                       Base_Index,
                       Ignored_Offset);
               end;
            when Pack_OFS_Delta =>
               declare
                  Negative_Offset : Natural := 0;
                  Consumed        : Natural := 0;
               begin
                  Status_Value :=
                    Parse_Pack_OFS_Delta_Base
                      (Pack_Data (Base_First .. Pack_Last),
                       Negative_Offset,
                       Consumed);
                  if Status_Value /= Ok then
                     return Status_Value;
                  elsif Negative_Offset = 0
                    or else Negative_Offset > Delta_Offset
                  then
                     return Invalid_Command;
                  end if;
                  return
                    Find_Index_By_Offset
                      (Delta_Offset - Negative_Offset, Base_Index);
               end;
            when others =>
               return Invalid_Command;
         end case;
      end Resolve_Delta_Base_Index;

      procedure Copy_Result
        (Source      : Stream_Element_Array;
         Source_Last : Stream_Element_Offset)
      is
         Length : constant Stream_Element_Offset :=
           (if Source_Last < Source'First then 0
            else Source_Last - Source'First + 1);
      begin
         if Length = 0 then
            Last := Data'First - 1;
         else
            Data (Data'First .. Data'First + Length - 1) :=
              Source (Source'First .. Source_Last);
            Last := Data'First + Length - 1;
         end if;
      end Copy_Result;
   begin
      Kind := Pack_Blob;
      Last := Data'First - 1;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value :=
        Parse_Object_ID_Hex (Object_ID_Hex, Requested_ID, Requested_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Requested_Last /= Requested_ID'Last then
         return Invalid_Command;
      end if;

      Status_Value :=
        Read_Pack_File
          (Repository_Root, Pack_Checksum_Hex, Pack_Data, Pack_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Read_Pack_Index
          (Repository_Root, Pack_Checksum_Hex, Index_Data, Index_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Validate_Pack_Object_Sequence
          (Pack_Data (Pack_Data'First .. Pack_Last),
           Delta_Data,
           Count_Value,
           Trailer_Value);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Count_Value > Maximum_Pack_Delta_Chain_Length then
         return Unsupported_Feature;
      end if;
      Status_Value :=
        Validate_Pack_Index
          (Index_Data (Index_Data'First .. Index_Last),
           Count_Value,
           Large_Count,
           Layout);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Find_Pack_Index_Object_Hex
          (Index_Data (Index_Data'First .. Index_Last),
           Object_ID_Hex,
           Object_Index,
           Pack_Offset);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      declare
         subtype Chain_Index is Positive range 1 .. Maximum_Pack_Delta_Chain_Length;
         type Chain_Array is array (Chain_Index range <>) of Natural;
         Chain        : Chain_Array (1 .. Maximum_Pack_Delta_Chain_Length);
         Chain_Length : Natural := 0;
         Current      : Natural := Object_Index;
      begin
         loop
            Status_Value :=
              Object_Kind_At (Current, Kind, Pack_Offset, Header_Size);
            if Status_Value /= Ok then
               return Status_Value;
            end if;
            exit when Kind not in Pack_REF_Delta | Pack_OFS_Delta;
            if Chain_Length = Maximum_Pack_Delta_Chain_Length then
               return Unsupported_Feature;
            end if;
            Chain_Length := Chain_Length + 1;
            Chain (Chain_Length) := Current;
            Status_Value :=
              Resolve_Delta_Base_Index
                (Pack_Offset, Header_Size, Kind, Current);
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         end loop;

         Status_Value := Resolve_Index_Offset (Current, Pack_Offset);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         Status_Value :=
           Inflate_Pack_Object_At_Offset
             (Pack_Data (Pack_Data'First .. Pack_Last),
              Pack_Offset,
              Kind,
              Size,
              Header_Size,
              Payload_Offset,
              Base_Data,
              Last,
              Next_Offset);
         if Status_Value /= Ok then
            Last := Data'First - 1;
            return Status_Value;
         elsif Kind not in Pack_Commit | Pack_Tree | Pack_Blob | Pack_Tag
           or else Header_Size = 0
           or else Payload_Offset <= Pack_Offset
           or else Next_Offset <= Pack_Offset
           or else Size > Natural (Base_Data'Length)
         then
            Last := Data'First - 1;
            return Invalid_Command;
         end if;

         if Chain_Length = 0 then
            if Last >= Base_Data'First
              and then Stream_Element_Offset (Data'Length)
                < Last - Base_Data'First + 1
            then
               Last := Data'First - 1;
               return Read_Failed;
            end if;
            Copy_Result (Base_Data, Last);
         else
            declare
               Current_Last   : Stream_Element_Offset := Last;
               Current_Buffer : Natural := 0;
            begin
               for Chain_Position in reverse 1 .. Chain_Length loop
                  declare
                     Delta_Kind           : Pack_Object_Kind := Pack_Blob;
                     Delta_Size           : Natural := 0;
                     Delta_Header_Size    : Natural := 0;
                     Delta_Payload_Offset : Natural := 0;
                     Delta_Last           : Stream_Element_Offset;
                     Delta_Next_Offset    : Natural := 0;
                  begin
                     Status_Value :=
                       Resolve_Index_Offset
                         (Chain (Chain_Position), Pack_Offset);
                     if Status_Value /= Ok then
                        Last := Data'First - 1;
                        return Status_Value;
                     end if;
                     Status_Value :=
                       Inflate_Pack_Object_At_Offset
                         (Pack_Data (Pack_Data'First .. Pack_Last),
                          Pack_Offset,
                          Delta_Kind,
                          Delta_Size,
                          Delta_Header_Size,
                          Delta_Payload_Offset,
                          Delta_Data,
                          Delta_Last,
                          Delta_Next_Offset);
                     if Status_Value /= Ok then
                        Last := Data'First - 1;
                        return Status_Value;
                     elsif Delta_Kind not in Pack_REF_Delta | Pack_OFS_Delta then
                        Last := Data'First - 1;
                        return Invalid_Command;
                     end if;

                     case Current_Buffer is
                        when 0 =>
                           Status_Value :=
                             Apply_Pack_Delta
                               (Base_Data (Base_Data'First .. Current_Last),
                                Delta_Data (Delta_Data'First .. Delta_Last),
                                Data,
                                Current_Last);
                           Current_Buffer := 1;
                        when 1 =>
                           Status_Value :=
                             Apply_Pack_Delta
                               (Data (Data'First .. Current_Last),
                                Delta_Data (Delta_Data'First .. Delta_Last),
                                Workspace,
                                Current_Last);
                           Current_Buffer := 2;
                        when others =>
                           Status_Value :=
                             Apply_Pack_Delta
                               (Workspace (Workspace'First .. Current_Last),
                                Delta_Data (Delta_Data'First .. Delta_Last),
                                Data,
                                Current_Last);
                           Current_Buffer := 1;
                     end case;
                     if Status_Value /= Ok then
                        Last := Data'First - 1;
                        return Status_Value;
                     end if;
                  end;
               end loop;

               if Current_Buffer = 2 then
                  if Current_Last >= Workspace'First
                    and then Stream_Element_Offset (Data'Length)
                      < Current_Last - Workspace'First + 1
                  then
                     Last := Data'First - 1;
                     return Read_Failed;
                  end if;
                  Copy_Result (Workspace, Current_Last);
               else
                  Last := Current_Last;
               end if;
            end;
         end if;
      end;

      Status_Value :=
        Compute_Object_ID
          (Kind, Data (Data'First .. Last), Computed_ID, Computed_Last);
      if Status_Value /= Ok then
         Last := Data'First - 1;
         return Status_Value;
      elsif Computed_Last /= Computed_ID'Last
        or else not Same_Raw_ID (Requested_ID, Computed_ID)
      then
         Last := Data'First - 1;
         return Invalid_Command;
      end if;
      return Ok;
   exception
      when Constraint_Error =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Invalid_Command;
      when others =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Read_Failed;
   end Read_Packed_Object_Resolved;

   function Read_Packed_Object_Resolved_Validated
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Stream_Element_Array;
      Object_ID_Hex      : Stream_Element_Array;
      Pack_Data          : out Stream_Element_Array;
      Index_Data         : out Stream_Element_Array;
      Base_Data          : out Stream_Element_Array;
      Delta_Data         : out Stream_Element_Array;
      Workspace          : out Stream_Element_Array;
      Kind               : out Pack_Object_Kind;
      Data               : out Stream_Element_Array;
      Last               : out Stream_Element_Offset)
      return Status
   is
      Status_Value : Status;
   begin
      Status_Value :=
        Read_Packed_Object_Resolved
          (Repository_Root,
           Pack_Checksum_Hex,
           Object_ID_Hex,
           Pack_Data,
           Index_Data,
           Base_Data,
           Delta_Data,
           Workspace,
           Kind,
           Data,
           Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Last < Data'First then
         if Kind = Pack_Blob then
            return Ok;
         end if;
         return Invalid_Command;
      end if;

      Status_Value := Validate_Object_Data (Kind, Data (Data'First .. Last));
      if Status_Value /= Ok then
         Last := Data'First - 1;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Invalid_Command;
      when others =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Read_Failed;
   end Read_Packed_Object_Resolved_Validated;

   function Read_Stored_Object
     (Repository_Root    : String;
      Object_ID_Hex      : Stream_Element_Array;
      Pack_Checksum_Hex  : Stream_Element_Array;
      Pack_Data          : out Stream_Element_Array;
      Index_Data         : out Stream_Element_Array;
      Kind               : out Pack_Object_Kind;
      Data               : out Stream_Element_Array;
      Last               : out Stream_Element_Offset)
      return Status
   is
      Status_Value : Status;
   begin
      Kind := Pack_Blob;
      Last := Data'First - 1;
      Status_Value :=
        Read_Loose_Object
          (Repository_Root, Object_ID_Hex, Kind, Data, Last);
      if Status_Value = Ok then
         return Ok;
      elsif Status_Value /= Read_Failed then
         return Status_Value;
      end if;

      return
        Read_Packed_Object
          (Repository_Root,
           Pack_Checksum_Hex,
           Object_ID_Hex,
           Pack_Data,
           Index_Data,
           Kind,
           Data,
           Last);
   exception
      when Constraint_Error =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Invalid_Command;
      when others =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Read_Failed;
   end Read_Stored_Object;

   function Read_Stored_Object_Resolved
     (Repository_Root    : String;
      Object_ID_Hex      : Stream_Element_Array;
      Pack_Checksum_Hex  : Stream_Element_Array;
      Pack_Data          : out Stream_Element_Array;
      Index_Data         : out Stream_Element_Array;
      Base_Data          : out Stream_Element_Array;
      Delta_Data         : out Stream_Element_Array;
      Workspace          : out Stream_Element_Array;
      Kind               : out Pack_Object_Kind;
      Data               : out Stream_Element_Array;
      Last               : out Stream_Element_Offset)
      return Status
   is
      Status_Value : Status;
   begin
      Kind := Pack_Blob;
      Last := Data'First - 1;
      Status_Value :=
        Read_Loose_Object
          (Repository_Root, Object_ID_Hex, Kind, Data, Last);
      if Status_Value = Ok then
         return Ok;
      elsif Status_Value /= Read_Failed then
         return Status_Value;
      end if;

      return
        Read_Packed_Object_Resolved
          (Repository_Root,
           Pack_Checksum_Hex,
           Object_ID_Hex,
           Pack_Data,
           Index_Data,
           Base_Data,
           Delta_Data,
           Workspace,
           Kind,
           Data,
           Last);
   exception
      when Constraint_Error =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Invalid_Command;
      when others =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Read_Failed;
   end Read_Stored_Object_Resolved;

   function Read_Stored_Object_Resolved_Validated
     (Repository_Root    : String;
      Object_ID_Hex      : Stream_Element_Array;
      Pack_Checksum_Hex  : Stream_Element_Array;
      Pack_Data          : out Stream_Element_Array;
      Index_Data         : out Stream_Element_Array;
      Base_Data          : out Stream_Element_Array;
      Delta_Data         : out Stream_Element_Array;
      Workspace          : out Stream_Element_Array;
      Kind               : out Pack_Object_Kind;
      Data               : out Stream_Element_Array;
      Last               : out Stream_Element_Offset)
      return Status
   is
      Status_Value : Status;
   begin
      Status_Value :=
        Read_Stored_Object_Resolved
          (Repository_Root,
           Object_ID_Hex,
           Pack_Checksum_Hex,
           Pack_Data,
           Index_Data,
           Base_Data,
           Delta_Data,
           Workspace,
           Kind,
           Data,
           Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Last < Data'First then
         if Kind = Pack_Blob then
            return Ok;
         end if;
         return Invalid_Command;
      end if;

      Status_Value := Validate_Object_Data (Kind, Data (Data'First .. Last));
      if Status_Value /= Ok then
         Last := Data'First - 1;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Invalid_Command;
      when others =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Read_Failed;
   end Read_Stored_Object_Resolved_Validated;

   function Read_Stored_Object_Validated
     (Repository_Root    : String;
      Object_ID_Hex      : Stream_Element_Array;
      Pack_Checksum_Hex  : Stream_Element_Array;
      Pack_Data          : out Stream_Element_Array;
      Index_Data         : out Stream_Element_Array;
      Kind               : out Pack_Object_Kind;
      Data               : out Stream_Element_Array;
      Last               : out Stream_Element_Offset)
      return Status
   is
      Status_Value : Status;
   begin
      Status_Value :=
        Read_Stored_Object
          (Repository_Root,
           Object_ID_Hex,
           Pack_Checksum_Hex,
           Pack_Data,
           Index_Data,
           Kind,
           Data,
           Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Last < Data'First then
         if Kind = Pack_Blob then
            return Ok;
         end if;
         return Invalid_Command;
      end if;

      Status_Value :=
        Validate_Object_Data (Kind, Data (Data'First .. Last));
      if Status_Value /= Ok then
         Last := Data'First - 1;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Invalid_Command;
      when others =>
         Kind := Pack_Blob;
         Last := Data'First - 1;
         return Read_Failed;
   end Read_Stored_Object_Validated;

   function Stored_Object_Exists
     (Repository_Root       : String;
      Object_ID_Hex         : Stream_Element_Array;
      Pack_Checksums_Hex    : out Stream_Element_Array;
      Pack_Checksums_Last   : out Stream_Element_Offset;
      Pack_Checksum_Hex     : out Stream_Element_Array;
      Pack_Checksum_Last    : out Stream_Element_Offset;
      Index_Data            : out Stream_Element_Array;
      Found                 : out Boolean)
      return Status
   is
      use type Ada.Directories.File_Kind;
      Raw_ID              :
        Stream_Element_Array
          (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last            : Stream_Element_Offset;
      Index_Last          : Stream_Element_Offset;
      Pack_Count          : Natural := 0;
      Object_Index        : Natural := 0;
      Pack_Offset         : Natural := 0;
      Status_Value        : Status;
      Cursor              : Stream_Element_Offset;
      Current_Checksum    :
        Stream_Element_Array
          (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
   begin
      Found := False;
      Pack_Checksums_Last := Pack_Checksums_Hex'First - 1;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value := Parse_Object_ID_Hex (Object_ID_Hex, Raw_ID, Raw_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Raw_Last /= Raw_ID'Last
        or else Pack_Checksum_Hex'Length
          < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Invalid_Command;
      end if;

      declare
         Path : constant String := Loose_Object_Path (Repository_Root, Object_ID_Hex);
      begin
         if Ada.Directories.Exists (Path) then
            if Ada.Directories.Kind (Path) /= Ada.Directories.Ordinary_File then
               return Invalid_Command;
            end if;
            Found := True;
            return Ok;
         end if;
      end;

      Status_Value :=
        List_Pack_Index_Checksums
          (Repository_Root,
           Pack_Checksums_Hex,
           Pack_Checksums_Last,
           Pack_Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Cursor := Pack_Checksums_Hex'First;
      for Pack_Number in 1 .. Pack_Count loop
         if Cursor > Pack_Checksums_Last
           or else Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
             > Pack_Checksums_Last - Cursor + 1
         then
            Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
            Found := False;
            return Invalid_Command;
         end if;

         Current_Checksum :=
           Pack_Checksums_Hex
             (Cursor
              .. Cursor
                + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                - 1);
         Status_Value :=
           Read_Pack_Index
             (Repository_Root,
              Current_Checksum,
              Index_Data,
              Index_Last);
         if Status_Value /= Ok then
            Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
            Found := False;
            return Status_Value;
         end if;

         Status_Value :=
           Find_Pack_Index_Object_Hex
             (Index_Data (Index_Data'First .. Index_Last),
              Object_ID_Hex,
              Object_Index,
              Pack_Offset);
         if Status_Value = Ok then
            for Offset in 0 .. Object_ID_SHA1_Hex_Length - 1 loop
               Pack_Checksum_Hex
                 (Pack_Checksum_Hex'First + Stream_Element_Offset (Offset)) :=
                   Current_Checksum
                     (Current_Checksum'First + Stream_Element_Offset (Offset));
            end loop;
            Pack_Checksum_Last :=
              Pack_Checksum_Hex'First
              + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
              - 1;
            Found := True;
            return Ok;
         elsif Status_Value /= Invalid_Command then
            Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
            Found := False;
            return Status_Value;
         end if;

         Cursor :=
           Cursor + Stream_Element_Offset (Object_ID_SHA1_Hex_Length);
      end loop;

      Found := False;
      return Ok;
   exception
      when Constraint_Error =>
         Found := False;
         Pack_Checksums_Last := Pack_Checksums_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Pack_Checksums_Last := Pack_Checksums_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Stored_Object_Exists;

   function List_Pack_Index_Checksums
     (Repository_Root    : String;
      Pack_Checksums_Hex : out Stream_Element_Array;
      Last               : out Stream_Element_Offset;
      Count              : out Natural)
      return Status
   is
      use type Ada.Directories.File_Kind;
      Search_Item : Ada.Directories.Search_Type;
      Entry_Item  : Ada.Directories.Directory_Entry_Type;
      Search_Open : Boolean := False;
      Cursor      : Stream_Element_Offset := Pack_Checksums_Hex'First;
      Pack_Dir    : constant String :=
        Git_Path (Repository_Root, "objects/pack");

      function Is_Pack_Index_Name (Name : String) return Boolean is
      begin
         return
           Name'Length = Object_ID_SHA1_Hex_Length + 9
           and then Name (Name'First .. Name'First + 4) = "pack-"
           and then Name (Name'Last - 3 .. Name'Last) = ".idx"
           and then
             Valid_Object_ID
               (Name
                  (Name'First + 5
                   .. Name'First + 5 + Object_ID_SHA1_Hex_Length - 1));
      end Is_Pack_Index_Name;
   begin
      Last := Pack_Checksums_Hex'First - 1;
      Count := 0;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      elsif not Ada.Directories.Exists (Pack_Dir) then
         return Ok;
      elsif Ada.Directories.Kind (Pack_Dir) /= Ada.Directories.Directory then
         return Invalid_Command;
      end if;

      Ada.Directories.Start_Search
        (Search    => Search_Item,
         Directory => Pack_Dir,
         Pattern   => "pack-*.idx",
         Filter    =>
           [Ada.Directories.Ordinary_File => True, others => False]);
      Search_Open := True;

      while Ada.Directories.More_Entries (Search_Item) loop
         Ada.Directories.Get_Next_Entry (Search_Item, Entry_Item);
         declare
            Name : constant String := Ada.Directories.Simple_Name (Entry_Item);
         begin
            if Is_Pack_Index_Name (Name) then
               if Cursor > Pack_Checksums_Hex'Last
                 or else Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                   > Pack_Checksums_Hex'Last - Cursor + 1
               then
                  Ada.Directories.End_Search (Search_Item);
                  Search_Open := False;
                  Last := Pack_Checksums_Hex'First - 1;
                  Count := 0;
                  return Read_Failed;
               end if;

               for Offset in 0 .. Object_ID_SHA1_Hex_Length - 1 loop
                  Pack_Checksums_Hex (Cursor + Stream_Element_Offset (Offset)) :=
                    Stream_Element
                      (Character'Pos
                         (Name (Name'First + 5 + Offset)));
               end loop;
               Cursor := Cursor + Stream_Element_Offset (Object_ID_SHA1_Hex_Length);
               Count := Count + 1;
               Last := Cursor - 1;
            end if;
         end;
      end loop;

      Ada.Directories.End_Search (Search_Item);
      Search_Open := False;
      return Ok;
   exception
      when Constraint_Error =>
         if Search_Open then
            Ada.Directories.End_Search (Search_Item);
         end if;
         Last := Pack_Checksums_Hex'First - 1;
         Count := 0;
         return Invalid_Command;
      when others =>
         if Search_Open then
            Ada.Directories.End_Search (Search_Item);
         end if;
         Last := Pack_Checksums_Hex'First - 1;
         Count := 0;
         return Read_Failed;
   end List_Pack_Index_Checksums;

   function List_Loose_Object_IDs
     (Repository_Root : String;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return Status
   is
      use type Ada.Directories.File_Kind;
      Objects_Dir : constant String := Git_Path (Repository_Root, "objects");
      Dir_Search  : Ada.Directories.Search_Type;
      File_Search : Ada.Directories.Search_Type;
      Dir_Open    : Boolean := False;
      File_Open   : Boolean := False;

      function Is_Hex_Pair (Name : String) return Boolean is
      begin
         return Name'Length = 2
           and then Hex_Value (Stream_Element (Character'Pos (Name (Name'First)))) < 16
           and then Hex_Value (Stream_Element (Character'Pos (Name (Name'Last)))) < 16;
      end Is_Hex_Pair;

      function Is_Hex_Suffix (Name : String) return Boolean is
      begin
         if Name'Length /= Object_ID_SHA1_Hex_Length - 2 then
            return False;
         end if;
         for Ch of Name loop
            if Hex_Value (Stream_Element (Character'Pos (Ch))) >= 16 then
               return False;
            end if;
         end loop;
         return True;
      end Is_Hex_Suffix;

      procedure Append_Object
        (Prefix : String;
         Suffix : String;
         Status_Value : out Status)
      is
         Text : constant String := Prefix & Suffix;
      begin
         Status_Value := Ok;
         if Count >= Object_IDs_Hex'Length then
            Status_Value := Read_Failed;
            return;
         elsif not Valid_Object_ID (Text) then
            Status_Value := Invalid_Command;
            return;
         end if;

         Count := Count + 1;
         declare
            Target_Index : constant Positive := Object_IDs_Hex'First + Count - 1;
         begin
            for Index in 1 .. Object_ID_SHA1_Hex_Length loop
               Object_IDs_Hex (Target_Index) (Index) :=
                 Stream_Element (Character'Pos (Text (Text'First + Index - 1)));
            end loop;
         end;
      exception
         when Constraint_Error =>
            Status_Value := Invalid_Command;
      end Append_Object;

      Status_Value : Status;
   begin
      Count := 0;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      elsif not Ada.Directories.Exists (Objects_Dir) then
         return Ok;
      elsif Ada.Directories.Kind (Objects_Dir) /= Ada.Directories.Directory then
         return Invalid_Command;
      end if;

      Ada.Directories.Start_Search
        (Search    => Dir_Search,
         Directory => Objects_Dir,
         Pattern   => "*",
         Filter    =>
           [Ada.Directories.Directory => True, others => False]);
      Dir_Open := True;

      while Ada.Directories.More_Entries (Dir_Search) loop
         declare
            Dir_Entry : Ada.Directories.Directory_Entry_Type;
         begin
            Ada.Directories.Get_Next_Entry (Dir_Search, Dir_Entry);
            declare
               Prefix : constant String :=
                 Ada.Directories.Simple_Name (Dir_Entry);
            begin
               if Is_Hex_Pair (Prefix) then
                  Ada.Directories.Start_Search
                    (Search    => File_Search,
                     Directory => Ada.Directories.Full_Name (Dir_Entry),
                     Pattern   => "*",
                     Filter    =>
                       [Ada.Directories.Ordinary_File => True,
                        others => False]);
                  File_Open := True;
                  while Ada.Directories.More_Entries (File_Search) loop
                     declare
                        File_Entry : Ada.Directories.Directory_Entry_Type;
                     begin
                        Ada.Directories.Get_Next_Entry
                          (File_Search, File_Entry);
                        declare
                           Suffix : constant String :=
                             Ada.Directories.Simple_Name (File_Entry);
                        begin
                           if Is_Hex_Suffix (Suffix) then
                              Append_Object (Prefix, Suffix, Status_Value);
                              if Status_Value /= Ok then
                                 Ada.Directories.End_Search (File_Search);
                                 File_Open := False;
                                 Ada.Directories.End_Search (Dir_Search);
                                 Dir_Open := False;
                                 Count := 0;
                                 return Status_Value;
                              end if;
                           end if;
                        end;
                     end;
                  end loop;
                  Ada.Directories.End_Search (File_Search);
                  File_Open := False;
               end if;
            end;
         end;
      end loop;

      Ada.Directories.End_Search (Dir_Search);
      Dir_Open := False;
      return Ok;
   exception
      when Constraint_Error =>
         if File_Open then
            Ada.Directories.End_Search (File_Search);
         end if;
         if Dir_Open then
            Ada.Directories.End_Search (Dir_Search);
         end if;
         Count := 0;
         return Invalid_Command;
      when others =>
         if File_Open then
            Ada.Directories.End_Search (File_Search);
         end if;
         if Dir_Open then
            Ada.Directories.End_Search (Dir_Search);
         end if;
         Count := 0;
         return Read_Failed;
   end List_Loose_Object_IDs;

   function List_Packed_Object_IDs
     (Repository_Root    : String;
      Pack_Checksum_Hex  : Stream_Element_Array;
      Index_Data         : out Stream_Element_Array;
      Index_Last         : out Stream_Element_Offset;
      Object_IDs_Hex     : out Object_ID_Hex_Array;
      Count              : out Natural)
      return Status
   is
      Status_Value : Status;
   begin
      Count := 0;
      Index_Last := Index_Data'First - 1;

      Status_Value :=
        Read_Pack_Index
          (Repository_Root,
           Pack_Checksum_Hex,
           Index_Data,
           Index_Last);
      if Status_Value /= Ok then
         Count := 0;
         Index_Last := Index_Data'First - 1;
         return Status_Value;
      end if;

      Status_Value :=
        List_Pack_Index_Object_IDs
          (Index_Data (Index_Data'First .. Index_Last),
           Object_IDs_Hex,
           Count);
      if Status_Value /= Ok then
         Count := 0;
         Index_Last := Index_Data'First - 1;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Count := 0;
         Index_Last := Index_Data'First - 1;
         return Invalid_Command;
      when others =>
         Count := 0;
         Index_Last := Index_Data'First - 1;
         return Read_Failed;
   end List_Packed_Object_IDs;

   function List_Stored_Object_IDs
     (Repository_Root       : String;
      Pack_Checksums_Hex    : out Stream_Element_Array;
      Pack_Checksums_Last   : out Stream_Element_Offset;
      Index_Data            : out Stream_Element_Array;
      Index_Last            : out Stream_Element_Offset;
      Object_IDs_Hex        : out Object_ID_Hex_Array;
      Count                 : out Natural)
      return Status
   is
      Status_Value : Status;
      Pack_Count   : Natural := 0;
      Cursor       : Stream_Element_Offset;
      Pack_IDs     : Natural := 0;
      Pack_Checksum :
        Stream_Element_Array
          (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
   begin
      Count := 0;
      Pack_Checksums_Last := Pack_Checksums_Hex'First - 1;
      Index_Last := Index_Data'First - 1;

      Status_Value :=
        List_Loose_Object_IDs (Repository_Root, Object_IDs_Hex, Count);
      if Status_Value /= Ok then
         Count := 0;
         return Status_Value;
      end if;

      Status_Value :=
        List_Pack_Index_Checksums
          (Repository_Root,
           Pack_Checksums_Hex,
           Pack_Checksums_Last,
           Pack_Count);
      if Status_Value /= Ok then
         Count := 0;
         Pack_Checksums_Last := Pack_Checksums_Hex'First - 1;
         return Status_Value;
      end if;

      Cursor := Pack_Checksums_Hex'First;
      for Pack_Number in 1 .. Pack_Count loop
         if Cursor > Pack_Checksums_Last
           or else Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
             > Pack_Checksums_Last - Cursor + 1
         then
            Count := 0;
            Index_Last := Index_Data'First - 1;
            return Invalid_Command;
         elsif Count >= Object_IDs_Hex'Length then
            Count := 0;
            Index_Last := Index_Data'First - 1;
            return Read_Failed;
         end if;

         Pack_Checksum :=
           Pack_Checksums_Hex
             (Cursor
              .. Cursor
                + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                - 1);
         Status_Value :=
           List_Packed_Object_IDs
             (Repository_Root,
              Pack_Checksum,
              Index_Data,
              Index_Last,
              Object_IDs_Hex (Count + 1 .. Object_IDs_Hex'Last),
              Pack_IDs);
         if Status_Value /= Ok then
            Count := 0;
            Index_Last := Index_Data'First - 1;
            return Status_Value;
         end if;

         Count := Count + Pack_IDs;
         Cursor := Cursor + Stream_Element_Offset (Object_ID_SHA1_Hex_Length);
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         Count := 0;
         Pack_Checksums_Last := Pack_Checksums_Hex'First - 1;
         Index_Last := Index_Data'First - 1;
         return Invalid_Command;
      when others =>
         Count := 0;
         Pack_Checksums_Last := Pack_Checksums_Hex'First - 1;
         Index_Last := Index_Data'First - 1;
         return Read_Failed;
   end List_Stored_Object_IDs;

   function Summarize_Repository_Database
     (Repository_Root : String;
      Summary         : out Repository_Database_Summary)
      return Status
   is
      Pack_Checksums : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length * 64));
      Pack_Checksums_Last : Stream_Element_Offset;
      Index_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Index_Last : Stream_Element_Offset;
      Object_IDs : Object_ID_Hex_Array (1 .. 4096);
      Ref_Names : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length * 256));
      Ref_Name_Lasts : Ref_Name_Last_Array (1 .. 256);
      Ref_IDs : Object_ID_Hex_Array (1 .. 256);
      Head_Target : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Head_Last : Stream_Element_Offset;
      Head_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Head_ID_Last : Stream_Element_Offset;
      Pack_Checksum_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Pack_Checksum_Last : Stream_Element_Offset;
      Ref_ID_Buffer : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Found : Boolean := False;
      Status_Value : Status;
   begin
      Summary := (others => <>);
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Status_Value :=
        List_Refs
          (Repository_Root,
           Ref_Names,
           Ref_Name_Lasts,
           Ref_IDs,
           Summary.Ref_Count);
      if Status_Value /= Ok then
         Summary := (others => <>);
         return Status_Value;
      end if;

      Status_Value :=
        List_Branches
          (Repository_Root,
           Ref_Names,
           Ref_Name_Lasts,
           Ref_IDs,
           Summary.Branch_Count);
      if Status_Value /= Ok then
         Summary := (others => <>);
         return Status_Value;
      end if;

      Status_Value :=
        List_Tag_Refs
          (Repository_Root,
           Ref_Names,
           Ref_Name_Lasts,
           Ref_IDs,
           Summary.Tag_Count);
      if Status_Value /= Ok then
         Summary := (others => <>);
         return Status_Value;
      end if;

      Status_Value :=
        List_Remote_Tracking_Branches
          (Repository_Root,
           Ref_Names,
           Ref_Name_Lasts,
           Ref_IDs,
           Summary.Remote_Tracking_Count);
      if Status_Value /= Ok then
         Summary := (others => <>);
         return Status_Value;
      end if;

      Status_Value :=
        List_Loose_Object_IDs
          (Repository_Root, Object_IDs, Summary.Loose_Object_Count);
      if Status_Value /= Ok then
         Summary := (others => <>);
         return Status_Value;
      end if;

      Status_Value :=
        List_Stored_Object_IDs
          (Repository_Root,
           Pack_Checksums,
           Pack_Checksums_Last,
           Index_Data,
           Index_Last,
           Object_IDs,
           Summary.Stored_Object_Count);
      if Status_Value /= Ok then
         Summary := (others => <>);
         return Status_Value;
      end if;

      Status_Value :=
        List_Pack_Index_Checksums
          (Repository_Root,
           Pack_Checksums,
           Pack_Checksums_Last,
           Summary.Pack_Index_Count);
      if Status_Value /= Ok then
         Summary := (others => <>);
         return Status_Value;
      end if;

      Status_Value :=
        Read_HEAD_Target
          (Repository_Root, Head_Target, Head_Last, Summary.HEAD_Attached);
      if Status_Value /= Ok and then Status_Value /= No_Such_File then
         Summary := (others => <>);
         return Status_Value;
      end if;

      Status_Value := Resolve_HEAD (Repository_Root, Head_ID, Head_ID_Last);
      if Status_Value = Ok and then Head_ID_Last = Head_ID'Last then
         Summary.HEAD_Resolved := True;
      elsif Status_Value /= No_Such_File
        and then Status_Value /= Read_Failed
      then
         Summary := (others => <>);
         return Status_Value;
      end if;

      Status_Value :=
        List_Refs
          (Repository_Root,
           Ref_Names,
           Ref_Name_Lasts,
           Ref_IDs,
           Summary.Ref_Count);
      if Status_Value /= Ok then
         Summary := (others => <>);
         return Status_Value;
      end if;

      for Index in 1 .. Summary.Ref_Count loop
         for Offset in 0 .. Object_ID_SHA1_Hex_Length - 1 loop
            Ref_ID_Buffer
              (Ref_ID_Buffer'First + Stream_Element_Offset (Offset)) :=
              Ref_IDs (Index) (Offset + 1);
         end loop;
         Status_Value :=
           Stored_Object_Exists
             (Repository_Root,
              Ref_ID_Buffer,
              Pack_Checksums,
              Pack_Checksums_Last,
              Pack_Checksum_Hex,
              Pack_Checksum_Last,
              Index_Data,
              Found);
         if Status_Value /= Ok then
            Summary := (others => <>);
            return Status_Value;
         elsif not Found then
            Summary.Missing_Ref_Target_Count :=
              Summary.Missing_Ref_Target_Count + 1;
         end if;
      end loop;

      Summary.Has_Missing_Ref_Targets :=
        Summary.Missing_Ref_Target_Count > 0;
      return Ok;
   exception
      when Constraint_Error =>
         Summary := (others => <>);
         return Invalid_Command;
      when others =>
         Summary := (others => <>);
         return Internal_Error;
   end Summarize_Repository_Database;

   function Read_Any_Stored_Object
     (Repository_Root     : String;
      Object_ID_Hex       : Stream_Element_Array;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Kind                : out Pack_Object_Kind;
      Data                : out Stream_Element_Array;
      Last                : out Stream_Element_Offset)
      return Status
   is
      List_Last    : Stream_Element_Offset;
      List_Count   : Natural := 0;
      Status_Value : Status;
      Candidate_First : Stream_Element_Offset;
   begin
      Kind := Pack_Blob;
      Last := Data'First - 1;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
      if Pack_Checksum_Hex'Length
        < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Read_Failed;
      end if;

      Status_Value :=
        Read_Loose_Object
          (Repository_Root, Object_ID_Hex, Kind, Data, Last);
      if Status_Value = Ok then
         return Ok;
      elsif Status_Value /= Read_Failed then
         return Status_Value;
      end if;

      Status_Value :=
        List_Pack_Index_Checksums
          (Repository_Root, Pack_Checksums_Hex, List_Last, List_Count);
      if Status_Value /= Ok then
         return Status_Value;
      elsif List_Count = 0 then
         return Read_Failed;
      end if;

      Candidate_First := Pack_Checksums_Hex'First;
      for Candidate in 1 .. List_Count loop
         Pack_Checksum_Hex
           (Pack_Checksum_Hex'First
            .. Pack_Checksum_Hex'First
               + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
               - 1) :=
             Pack_Checksums_Hex
               (Candidate_First
                .. Candidate_First
                   + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                   - 1);
         Pack_Checksum_Last :=
           Pack_Checksum_Hex'First
           + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
           - 1;

         Status_Value :=
           Read_Packed_Object
             (Repository_Root,
              Pack_Checksum_Hex
                (Pack_Checksum_Hex'First .. Pack_Checksum_Last),
              Object_ID_Hex,
              Pack_Data,
              Index_Data,
              Kind,
              Data,
              Last);
         if Status_Value = Ok then
            return Ok;
         elsif Status_Value = Unsupported_Feature then
            Last := Data'First - 1;
            return Status_Value;
         end if;

         Candidate_First :=
           Candidate_First + Stream_Element_Offset (Object_ID_SHA1_Hex_Length);
      end loop;

      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
      Last := Data'First - 1;
      return Read_Failed;
   exception
      when Constraint_Error =>
         Kind := Pack_Blob;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         Last := Data'First - 1;
         return Invalid_Command;
      when others =>
         Kind := Pack_Blob;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         Last := Data'First - 1;
         return Read_Failed;
   end Read_Any_Stored_Object;

   function Read_Any_Stored_Object_Resolved
     (Repository_Root     : String;
      Object_ID_Hex       : Stream_Element_Array;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Base_Data           : out Stream_Element_Array;
      Delta_Data          : out Stream_Element_Array;
      Workspace           : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Kind                : out Pack_Object_Kind;
      Data                : out Stream_Element_Array;
      Last                : out Stream_Element_Offset)
      return Status
   is
      List_Last    : Stream_Element_Offset;
      List_Count   : Natural := 0;
      Status_Value : Status;
      Candidate_First : Stream_Element_Offset;
   begin
      Kind := Pack_Blob;
      Last := Data'First - 1;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
      if Pack_Checksum_Hex'Length
        < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Read_Failed;
      end if;

      Status_Value :=
        Read_Loose_Object
          (Repository_Root, Object_ID_Hex, Kind, Data, Last);
      if Status_Value = Ok then
         return Ok;
      elsif Status_Value /= Read_Failed then
         return Status_Value;
      end if;

      Status_Value :=
        List_Pack_Index_Checksums
          (Repository_Root, Pack_Checksums_Hex, List_Last, List_Count);
      if Status_Value /= Ok then
         return Status_Value;
      elsif List_Count = 0 then
         return Read_Failed;
      end if;

      Candidate_First := Pack_Checksums_Hex'First;
      for Candidate in 1 .. List_Count loop
         Pack_Checksum_Hex
           (Pack_Checksum_Hex'First
            .. Pack_Checksum_Hex'First
               + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
               - 1) :=
             Pack_Checksums_Hex
               (Candidate_First
                .. Candidate_First
                   + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                   - 1);
         Pack_Checksum_Last :=
           Pack_Checksum_Hex'First
           + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
           - 1;

         Status_Value :=
           Read_Packed_Object_Resolved
             (Repository_Root,
              Pack_Checksum_Hex
                (Pack_Checksum_Hex'First .. Pack_Checksum_Last),
              Object_ID_Hex,
              Pack_Data,
              Index_Data,
              Base_Data,
              Delta_Data,
              Workspace,
              Kind,
              Data,
              Last);
         if Status_Value = Ok then
            return Ok;
         elsif Status_Value = Unsupported_Feature then
            Last := Data'First - 1;
            return Status_Value;
         end if;

         Candidate_First :=
           Candidate_First + Stream_Element_Offset (Object_ID_SHA1_Hex_Length);
      end loop;

      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
      Last := Data'First - 1;
      return Read_Failed;
   exception
      when Constraint_Error =>
         Kind := Pack_Blob;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         Last := Data'First - 1;
         return Invalid_Command;
      when others =>
         Kind := Pack_Blob;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         Last := Data'First - 1;
         return Read_Failed;
   end Read_Any_Stored_Object_Resolved;

   function Read_Any_Stored_Object_Resolved_Validated
     (Repository_Root     : String;
      Object_ID_Hex       : Stream_Element_Array;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Base_Data           : out Stream_Element_Array;
      Delta_Data          : out Stream_Element_Array;
      Workspace           : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Kind                : out Pack_Object_Kind;
      Data                : out Stream_Element_Array;
      Last                : out Stream_Element_Offset)
      return Status
   is
      Status_Value : Status;
   begin
      Status_Value :=
        Read_Any_Stored_Object_Resolved
          (Repository_Root,
           Object_ID_Hex,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Base_Data,
           Delta_Data,
           Workspace,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Kind,
           Data,
           Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Last < Data'First then
         if Kind = Pack_Blob then
            return Ok;
         end if;
         return Invalid_Command;
      end if;

      Status_Value := Validate_Object_Data (Kind, Data (Data'First .. Last));
      if Status_Value /= Ok then
         Last := Data'First - 1;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Kind := Pack_Blob;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         Last := Data'First - 1;
         return Invalid_Command;
      when others =>
         Kind := Pack_Blob;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         Last := Data'First - 1;
         return Read_Failed;
   end Read_Any_Stored_Object_Resolved_Validated;

   function Read_Any_Stored_Object_Validated
     (Repository_Root     : String;
      Object_ID_Hex       : Stream_Element_Array;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Kind                : out Pack_Object_Kind;
      Data                : out Stream_Element_Array;
      Last                : out Stream_Element_Offset)
      return Status
   is
      Status_Value : Status;
   begin
      Status_Value :=
        Read_Any_Stored_Object
          (Repository_Root,
           Object_ID_Hex,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Kind,
           Data,
           Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Last < Data'First then
         if Kind = Pack_Blob then
            return Ok;
         end if;
         return Invalid_Command;
      end if;

      Status_Value :=
        Validate_Object_Data (Kind, Data (Data'First .. Last));
      if Status_Value /= Ok then
         Last := Data'First - 1;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Kind := Pack_Blob;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         Last := Data'First - 1;
         return Invalid_Command;
      when others =>
         Kind := Pack_Blob;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         Last := Data'First - 1;
         return Read_Failed;
   end Read_Any_Stored_Object_Validated;

   function Read_Tree_Entry_Object
     (Repository_Root     : String;
      Tree_ID_Hex         : Stream_Element_Array;
      Entry_Name          : Stream_Element_Array;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Kind                : out Pack_Object_Kind;
      Data                : out Stream_Element_Array;
      Last                : out Stream_Element_Offset)
      return Status
   is
      Tree_Kind : Pack_Object_Kind := Pack_Blob;
      Entry_ID_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Entry_ID_Last : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Entry_Mode := 0;
      Kind := Pack_Blob;
      Last := Data'First - 1;
      Tree_Last := Tree_Data'First - 1;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      Status_Value :=
        Read_Any_Stored_Object_Validated
          (Repository_Root,
           Tree_ID_Hex,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Tree_Kind,
           Tree_Data,
           Tree_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Tree_Kind /= Pack_Tree or else Tree_Last < Tree_Data'First then
         Tree_Last := Tree_Data'First - 1;
         return Invalid_Command;
      end if;

      Status_Value :=
        Find_Tree_Entry_Hex
          (Tree_Data (Tree_Data'First .. Tree_Last),
           Entry_Name,
           Entry_Mode,
           Entry_ID_Hex,
           Entry_ID_Last);
      if Status_Value /= Ok then
         Entry_Mode := 0;
         Last := Data'First - 1;
         return Status_Value;
      elsif Entry_ID_Last /= Entry_ID_Hex'Last then
         Entry_Mode := 0;
         Last := Data'First - 1;
         return Invalid_Command;
      end if;

      return
        Read_Any_Stored_Object_Validated
          (Repository_Root,
           Entry_ID_Hex,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Kind,
           Data,
           Last);
   exception
      when Constraint_Error =>
         Entry_Mode := 0;
         Kind := Pack_Blob;
         Last := Data'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Entry_Mode := 0;
         Kind := Pack_Blob;
         Last := Data'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Read_Tree_Entry_Object;

   function List_Tree_Entries_Hex
     (Tree_Data      : Stream_Element_Array;
      Names          : out Stream_Element_Array;
      Name_Lasts     : out Tree_Entry_Name_Last_Array;
      Modes          : out Tree_Entry_Mode_Array;
      Object_IDs_Hex : out Object_ID_Hex_Array;
      Count          : out Natural)
      return Status
   is
      Cursor        : Natural := 0;
      Mode_Value    : Natural := 0;
      Name_Buffer   : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Name_Last     : Stream_Element_Offset;
      Name_Length   : Stream_Element_Offset;
      Raw_ID        : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_ID_Last   : Stream_Element_Offset;
      Hex_Buffer    : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Hex_Last      : Stream_Element_Offset;
      Next_Offset   : Natural := 0;
      Names_Cursor  : Stream_Element_Offset := Names'First;
      Status_Value  : Status;
   begin
      Count := 0;
      if Tree_Data'Length = 0 then
         return Ok;
      end if;

      while Cursor < Natural (Tree_Data'Length) loop
         if Count >= Modes'Length
           or else Count >= Name_Lasts'Length
           or else Count >= Object_IDs_Hex'Length
         then
            Count := 0;
            return Read_Failed;
         end if;

         Status_Value :=
           Parse_Tree_Entry
             (Tree_Data,
              Cursor,
              Mode_Value,
              Name_Buffer,
              Name_Last,
              Raw_ID,
              Raw_ID_Last,
              Next_Offset);
         if Status_Value /= Ok then
            Count := 0;
            return Status_Value;
         elsif Raw_ID_Last /= Raw_ID'Last
           or else Name_Last < Name_Buffer'First
           or else Next_Offset <= Cursor
         then
            Count := 0;
            return Invalid_Command;
         end if;

         Name_Length := Name_Last - Name_Buffer'First + 1;
         if Name_Length > Names'Length
           or else Names_Cursor > Names'Last
           or else Names'Last - Names_Cursor + 1 < Name_Length
         then
            Count := 0;
            return Read_Failed;
         end if;

         Status_Value :=
           Encode_Object_ID_Hex (Raw_ID, Hex_Buffer, Hex_Last);
         if Status_Value /= Ok then
            Count := 0;
            return Status_Value;
         elsif Hex_Last /= Hex_Buffer'Last then
            Count := 0;
            return Internal_Error;
         end if;

         Count := Count + 1;
         Modes (Modes'First + Count - 1) := Mode_Value;
         Names (Names_Cursor .. Names_Cursor + Name_Length - 1) :=
           Name_Buffer (Name_Buffer'First .. Name_Last);
         Name_Lasts (Name_Lasts'First + Count - 1) :=
           Names_Cursor + Name_Length - 1;

         for Index in 1 .. Object_ID_SHA1_Hex_Length loop
            Object_IDs_Hex (Object_IDs_Hex'First + Count - 1) (Index) :=
              Hex_Buffer (Hex_Buffer'First + Stream_Element_Offset (Index - 1));
         end loop;

         Names_Cursor := Names_Cursor + Name_Length;
         Cursor := Next_Offset;
      end loop;

      if Cursor /= Natural (Tree_Data'Length) then
         Count := 0;
         return Invalid_Command;
      end if;
      return Ok;
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Internal_Error;
   end List_Tree_Entries_Hex;

   function Read_Tree_Entries_Hex
     (Repository_Root     : String;
      Tree_ID_Hex         : Stream_Element_Array;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Names               : out Stream_Element_Array;
      Name_Lasts          : out Tree_Entry_Name_Last_Array;
      Modes               : out Tree_Entry_Mode_Array;
      Object_IDs_Hex      : out Object_ID_Hex_Array;
      Count               : out Natural)
      return Status
   is
      Tree_Kind : Pack_Object_Kind := Pack_Blob;
      Status_Value : Status;
   begin
      Tree_Last := Tree_Data'First - 1;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
      Count := 0;

      Status_Value :=
        Read_Any_Stored_Object_Validated
          (Repository_Root,
           Tree_ID_Hex,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Tree_Kind,
           Tree_Data,
           Tree_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Tree_Kind /= Pack_Tree then
         Tree_Last := Tree_Data'First - 1;
         return Invalid_Command;
      elsif Tree_Last < Tree_Data'First then
         return Ok;
      end if;

      return
        List_Tree_Entries_Hex
          (Tree_Data (Tree_Data'First .. Tree_Last),
           Names,
           Name_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
   exception
      when Constraint_Error =>
         Tree_Last := Tree_Data'First - 1;
         Count := 0;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Tree_Last := Tree_Data'First - 1;
         Count := 0;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Read_Tree_Entries_Hex;

   function List_Tree_Paths_Hex
     (Repository_Root  : String;
      Root_Tree_ID_Hex : Stream_Element_Array;
      Paths            : out Stream_Element_Array;
      Path_Lasts       : out Index_Path_Last_Array;
      Modes            : out Tree_Entry_Mode_Array;
      Object_IDs_Hex   : out Object_ID_Hex_Array;
      Count            : out Natural)
      return Status
   is
      Paths_Cursor : Stream_Element_Offset := Paths'First;
      Scratch      : Tree_Traversal_Scratch_Access := null;

      procedure Reset_Outputs is
      begin
         Count := 0;
         Paths_Cursor := Paths'First;
      end Reset_Outputs;

      procedure Append_Path
        (Path_Text : String;
         Mode      : Natural;
         Object_ID : Stream_Element_Array;
         Result    : out Status)
      is
      begin
         Result := Ok;
         if not Valid_Worktree_Path (Path_Text)
           or else Object_ID'Length /=
             Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
         then
            Result := Invalid_Command;
            return;
         elsif Count >= Path_Lasts'Length
           or else Count >= Modes'Length
           or else Count >= Object_IDs_Hex'Length
           or else Paths_Cursor + Stream_Element_Offset (Path_Text'Length) - 1
             > Paths'Last
         then
            Result := Read_Failed;
            return;
         end if;

         for Ch of Path_Text loop
            Paths (Paths_Cursor) := Stream_Element (Character'Pos (Ch));
            Paths_Cursor := Paths_Cursor + 1;
         end loop;
         Count := Count + 1;
         Path_Lasts (Path_Lasts'First + Count - 1) := Paths_Cursor - 1;
         Modes (Modes'First + Count - 1) := Mode;
         for Offset in 0 .. Object_ID_SHA1_Hex_Length - 1 loop
            Object_IDs_Hex (Object_IDs_Hex'First + Count - 1)
              (Positive (Offset + 1)) :=
                Object_ID (Object_ID'First + Stream_Element_Offset (Offset));
         end loop;
      exception
         when Constraint_Error =>
            Result := Invalid_Command;
      end Append_Path;

      procedure Walk_Tree
        (Tree_ID_Hex : Stream_Element_Array;
         Prefix      : String;
         Depth       : Natural;
         Result      : out Status)
      is
         Pack_Checksum_Last : Stream_Element_Offset;
         Tree_Data : Stream_Element_Array
           (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
         Tree_Last : Stream_Element_Offset;
         Tree_Kind : Pack_Object_Kind := Pack_Blob;
         Entry_Offset : Natural := 0;
         Entry_Mode : Natural := 0;
         Entry_Name : Stream_Element_Array
           (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
         Entry_Name_Last : Stream_Element_Offset;
         Raw_ID : Stream_Element_Array
           (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
         Raw_ID_Last : Stream_Element_Offset;
         Entry_ID_Hex : Stream_Element_Array
           (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
         Entry_ID_Last : Stream_Element_Offset;
         Next_Offset : Natural := 0;
      begin
         Result := Ok;
         if Depth > Maximum_Ref_Resolution_Depth then
            Result := Unsupported_Feature;
            return;
         end if;

         Result :=
           Read_Any_Stored_Object_Resolved_Validated
             (Repository_Root,
              Tree_ID_Hex,
              Scratch.Pack_Checksums_Hex,
              Scratch.Pack_Data,
              Scratch.Index_Data,
              Scratch.Base_Data,
              Scratch.Delta_Data,
              Scratch.Workspace,
              Scratch.Pack_Checksum_Hex,
              Pack_Checksum_Last,
              Tree_Kind,
              Tree_Data,
              Tree_Last);
         if Result /= Ok then
            return;
         elsif Tree_Kind /= Pack_Tree then
            Result := Invalid_Command;
            return;
         elsif Tree_Last < Tree_Data'First then
            return;
         end if;

         while Entry_Offset < Natural (Tree_Last - Tree_Data'First + 1) loop
            Result :=
              Parse_Tree_Entry
                (Tree_Data (Tree_Data'First .. Tree_Last),
                 Entry_Offset,
                 Entry_Mode,
                 Entry_Name,
                 Entry_Name_Last,
                 Raw_ID,
                 Raw_ID_Last,
                 Next_Offset);
            if Result /= Ok then
               return;
            elsif Raw_ID_Last /= Raw_ID'Last
              or else Entry_Name_Last < Entry_Name'First
              or else Next_Offset <= Entry_Offset
            then
               Result := Invalid_Command;
               return;
            end if;

            Result := Encode_Object_ID_Hex (Raw_ID, Entry_ID_Hex, Entry_ID_Last);
            if Result /= Ok then
               return;
            elsif Entry_ID_Last /= Entry_ID_Hex'Last then
               Result := Invalid_Command;
               return;
            end if;

            declare
               Name_Text : String
                 (1 .. Natural (Entry_Name_Last - Entry_Name'First + 1));
            begin
               for Index in Name_Text'Range loop
                  Name_Text (Index) :=
                    Character'Val
                      (Entry_Name
                         (Entry_Name'First + Stream_Element_Offset (Index - 1)));
               end loop;

               declare
                  Path_Text : constant String :=
                    (if Prefix'Length = 0 then Name_Text
                     else Prefix & "/" & Name_Text);
               begin
                  Append_Path
                    (Path_Text,
                     Entry_Mode,
                     Entry_ID_Hex,
                     Result);
                  if Result /= Ok then
                     return;
                  elsif Entry_Mode = 8#040000# then
                     Walk_Tree
                       (Entry_ID_Hex,
                        Path_Text,
                        Depth + 1,
                        Result);
                     if Result /= Ok then
                        return;
                     end if;
                  end if;
               end;
            end;

            Entry_Offset := Next_Offset;
         end loop;
      exception
         when Constraint_Error =>
            Result := Invalid_Command;
         when others =>
            Result := Read_Failed;
      end Walk_Tree;

      Status_Value : Status := Ok;
   begin
      Reset_Outputs;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Scratch := new Tree_Traversal_Scratch;
      Walk_Tree (Root_Tree_ID_Hex, "", 0, Status_Value);
      Free_Tree_Traversal_Scratch (Scratch);
      if Status_Value /= Ok then
         Reset_Outputs;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         if Scratch /= null then
            Free_Tree_Traversal_Scratch (Scratch);
         end if;
         Reset_Outputs;
         return Invalid_Command;
      when others =>
         if Scratch /= null then
            Free_Tree_Traversal_Scratch (Scratch);
         end if;
         Reset_Outputs;
         return Read_Failed;
   end List_Tree_Paths_Hex;

   function Filter_Tree_Paths_By_Pathspec
     (Pathspec       : String;
      Paths          : in out Stream_Element_Array;
      Path_Lasts     : in out Index_Path_Last_Array;
      Modes          : in out Tree_Entry_Mode_Array;
      Object_IDs_Hex : in out Object_ID_Hex_Array;
      Count          : in out Natural)
      return Status
   is
      Original_Count : constant Natural := Count;
      Source_First   : Stream_Element_Offset := Paths'First;
      Target_Cursor  : Stream_Element_Offset := Paths'First;
      Target_Count   : Natural := 0;
      Matches        : Boolean := False;
      Status_Value   : Status;
   begin
      for Entry_Number in 1 .. Original_Count loop
         declare
            Source_Index : constant Positive :=
              Path_Lasts'First + Entry_Number - 1;
            Source_Last : constant Stream_Element_Offset :=
              Path_Lasts (Source_Index);
         begin
            if Source_Index > Path_Lasts'Last
              or else Source_Index > Modes'Last
              or else Source_Index > Object_IDs_Hex'Last
              or else Source_Last < Source_First
              or else Source_Last > Paths'Last
            then
               Count := 0;
               return Invalid_Command;
            end if;

            declare
               Path_Text : String
                 (1 .. Natural (Source_Last - Source_First + 1));
            begin
               for Index in Path_Text'Range loop
                  Path_Text (Index) :=
                    Character'Val
                      (Paths
                         (Source_First
                          + Stream_Element_Offset (Index - 1)));
               end loop;

               Status_Value := Pathspec_Matches (Path_Text, Pathspec, Matches);
               if Status_Value /= Ok then
                  Count := 0;
                  return Status_Value;
               end if;

               if Matches then
                  if Target_Count >= Path_Lasts'Length
                    or else Target_Count >= Modes'Length
                    or else Target_Count >= Object_IDs_Hex'Length
                    or else Target_Cursor + Path_Text'Length - 1 > Paths'Last
                  then
                     Count := 0;
                     return Read_Failed;
                  end if;

                  for Offset in 0 .. Path_Text'Length - 1 loop
                     Paths (Target_Cursor + Stream_Element_Offset (Offset)) :=
                       Paths (Source_First + Stream_Element_Offset (Offset));
                  end loop;

                  Target_Count := Target_Count + 1;
                  Path_Lasts (Path_Lasts'First + Target_Count - 1) :=
                    Target_Cursor + Stream_Element_Offset (Path_Text'Length) - 1;
                  Modes (Modes'First + Target_Count - 1) := Modes (Source_Index);
                  Object_IDs_Hex (Object_IDs_Hex'First + Target_Count - 1) :=
                    Object_IDs_Hex (Source_Index);
                  Target_Cursor :=
                    Target_Cursor + Stream_Element_Offset (Path_Text'Length);
               end if;
            end;

            Source_First := Source_Last + 1;
         end;
      end loop;

      Count := Target_Count;
      return Ok;
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Read_Failed;
   end Filter_Tree_Paths_By_Pathspec;

   function List_Tree_Paths_Matching_Hex
     (Repository_Root  : String;
      Root_Tree_ID_Hex : Stream_Element_Array;
      Pathspec         : String;
      Paths            : out Stream_Element_Array;
      Path_Lasts       : out Index_Path_Last_Array;
      Modes            : out Tree_Entry_Mode_Array;
      Object_IDs_Hex   : out Object_ID_Hex_Array;
      Count            : out Natural)
      return Status
   is
      Status_Value : Status;
   begin
      Status_Value :=
        List_Tree_Paths_Hex
          (Repository_Root,
           Root_Tree_ID_Hex,
           Paths,
           Path_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return
        Filter_Tree_Paths_By_Pathspec
          (Pathspec, Paths, Path_Lasts, Modes, Object_IDs_Hex, Count);
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Read_Failed;
   end List_Tree_Paths_Matching_Hex;

   function Read_Path_Object
     (Repository_Root     : String;
      Root_Tree_ID_Hex    : Stream_Element_Array;
      Path                : Stream_Element_Array;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Kind                : out Pack_Object_Kind;
      Data                : out Stream_Element_Array;
      Last                : out Stream_Element_Offset)
      return Status
   is
      Current_Tree_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Current_Last : Stream_Element_Offset := Current_Tree_ID'First - 1;
      Entry_ID_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Entry_ID_Last : Stream_Element_Offset;
      Component : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Component_Last : Stream_Element_Offset;
      Cursor : Stream_Element_Offset;
      Component_First : Stream_Element_Offset;
      Tree_Kind : Pack_Object_Kind := Pack_Blob;
      Status_Value : Status;
   begin
      Entry_Mode := 0;
      Kind := Pack_Blob;
      Last := Data'First - 1;
      Tree_Last := Tree_Data'First - 1;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      if Path'Length = 0
        or else Root_Tree_ID_Hex'Length
          < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Invalid_Command;
      end if;

      Current_Tree_ID := Root_Tree_ID_Hex
        (Root_Tree_ID_Hex'First
         .. Root_Tree_ID_Hex'First
            + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
            - 1);
      Current_Last := Current_Tree_ID'Last;
      Cursor := Path'First;

      while Cursor <= Path'Last loop
         Component_First := Cursor;
         Component_Last := Component'First - 1;
         while Cursor <= Path'Last
           and then Path (Cursor) /= Stream_Element (Character'Pos ('/'))
         loop
            if Path (Cursor) = 0
              or else Component_Last >= Component'Last
            then
               Entry_Mode := 0;
               return Invalid_Command;
            end if;
            Component_Last := Component_Last + 1;
            Component (Component_Last) := Path (Cursor);
            Cursor := Cursor + 1;
         end loop;

         if Cursor = Component_First then
            Entry_Mode := 0;
            return Invalid_Command;
         end if;

         Status_Value :=
           Read_Any_Stored_Object_Validated
             (Repository_Root,
              Current_Tree_ID (Current_Tree_ID'First .. Current_Last),
              Pack_Checksums_Hex,
              Pack_Data,
              Index_Data,
              Pack_Checksum_Hex,
              Pack_Checksum_Last,
              Tree_Kind,
              Tree_Data,
              Tree_Last);
         if Status_Value /= Ok then
            Entry_Mode := 0;
            return Status_Value;
         elsif Tree_Kind /= Pack_Tree or else Tree_Last < Tree_Data'First then
            Entry_Mode := 0;
            Tree_Last := Tree_Data'First - 1;
            return Invalid_Command;
         end if;

         Status_Value :=
           Find_Tree_Entry_Hex
             (Tree_Data (Tree_Data'First .. Tree_Last),
              Component (Component'First .. Component_Last),
              Entry_Mode,
              Entry_ID_Hex,
              Entry_ID_Last);
         if Status_Value /= Ok then
            Entry_Mode := 0;
            return Status_Value;
         elsif Entry_ID_Last /= Entry_ID_Hex'Last then
            Entry_Mode := 0;
            return Invalid_Command;
         end if;

         if Cursor > Path'Last then
            return
              Read_Any_Stored_Object_Validated
                (Repository_Root,
                 Entry_ID_Hex,
                 Pack_Checksums_Hex,
                 Pack_Data,
                 Index_Data,
                 Pack_Checksum_Hex,
                 Pack_Checksum_Last,
                 Kind,
                 Data,
                 Last);
         end if;

         if Path (Cursor) /= Stream_Element (Character'Pos ('/')) then
            Entry_Mode := 0;
            return Invalid_Command;
         end if;
         Current_Tree_ID := Entry_ID_Hex;
         Current_Last := Current_Tree_ID'Last;
         Cursor := Cursor + 1;
         if Cursor > Path'Last then
            Entry_Mode := 0;
            return Invalid_Command;
         end if;
      end loop;

      Entry_Mode := 0;
      return Invalid_Command;
   exception
      when Constraint_Error =>
         Entry_Mode := 0;
         Kind := Pack_Blob;
         Last := Data'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Entry_Mode := 0;
         Kind := Pack_Blob;
         Last := Data'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Read_Path_Object;

   function Resolve_Path_Entry_Hex
     (Repository_Root     : String;
      Root_Tree_ID_Hex    : Stream_Element_Array;
      Path                : Stream_Element_Array;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Entry_ID_Hex        : out Stream_Element_Array;
      Entry_ID_Last       : out Stream_Element_Offset)
      return Status
   is
      Current_Tree_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Current_Last : Stream_Element_Offset := Current_Tree_ID'First - 1;
      Found_ID_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Found_ID_Last : Stream_Element_Offset;
      Component : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Component_Last : Stream_Element_Offset;
      Cursor : Stream_Element_Offset;
      Component_First : Stream_Element_Offset;
      Tree_Kind : Pack_Object_Kind := Pack_Blob;
      Status_Value : Status;
   begin
      Entry_Mode := 0;
      Entry_ID_Last := Entry_ID_Hex'First - 1;
      Tree_Last := Tree_Data'First - 1;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      if Path'Length = 0
        or else Root_Tree_ID_Hex'Length
          < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
        or else Entry_ID_Hex'Length
          < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Invalid_Command;
      end if;

      Current_Tree_ID := Root_Tree_ID_Hex
        (Root_Tree_ID_Hex'First
         .. Root_Tree_ID_Hex'First
            + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
            - 1);
      Current_Last := Current_Tree_ID'Last;
      Cursor := Path'First;

      while Cursor <= Path'Last loop
         Component_First := Cursor;
         Component_Last := Component'First - 1;
         while Cursor <= Path'Last
           and then Path (Cursor) /= Stream_Element (Character'Pos ('/'))
         loop
            if Path (Cursor) = 0
              or else Component_Last >= Component'Last
            then
               Entry_Mode := 0;
               Entry_ID_Last := Entry_ID_Hex'First - 1;
               return Invalid_Command;
            end if;
            Component_Last := Component_Last + 1;
            Component (Component_Last) := Path (Cursor);
            Cursor := Cursor + 1;
         end loop;

         if Cursor = Component_First then
            Entry_Mode := 0;
            Entry_ID_Last := Entry_ID_Hex'First - 1;
            return Invalid_Command;
         end if;

         Status_Value :=
           Read_Any_Stored_Object_Validated
             (Repository_Root,
              Current_Tree_ID (Current_Tree_ID'First .. Current_Last),
              Pack_Checksums_Hex,
              Pack_Data,
              Index_Data,
              Pack_Checksum_Hex,
              Pack_Checksum_Last,
              Tree_Kind,
              Tree_Data,
              Tree_Last);
         if Status_Value /= Ok then
            Entry_Mode := 0;
            Entry_ID_Last := Entry_ID_Hex'First - 1;
            return Status_Value;
         elsif Tree_Kind /= Pack_Tree or else Tree_Last < Tree_Data'First then
            Entry_Mode := 0;
            Entry_ID_Last := Entry_ID_Hex'First - 1;
            Tree_Last := Tree_Data'First - 1;
            return Invalid_Command;
         end if;

         Status_Value :=
           Find_Tree_Entry_Hex
             (Tree_Data (Tree_Data'First .. Tree_Last),
              Component (Component'First .. Component_Last),
              Entry_Mode,
              Found_ID_Hex,
              Found_ID_Last);
         if Status_Value /= Ok then
            Entry_Mode := 0;
            Entry_ID_Last := Entry_ID_Hex'First - 1;
            return Status_Value;
         elsif Found_ID_Last /= Found_ID_Hex'Last then
            Entry_Mode := 0;
            Entry_ID_Last := Entry_ID_Hex'First - 1;
            return Invalid_Command;
         end if;

         if Cursor > Path'Last then
            Entry_ID_Hex
              (Entry_ID_Hex'First
               .. Entry_ID_Hex'First
                  + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                  - 1) := Found_ID_Hex;
            Entry_ID_Last :=
              Entry_ID_Hex'First
              + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
              - 1;
            return Ok;
         end if;

         if Path (Cursor) /= Stream_Element (Character'Pos ('/')) then
            Entry_Mode := 0;
            Entry_ID_Last := Entry_ID_Hex'First - 1;
            return Invalid_Command;
         end if;
         Current_Tree_ID := Found_ID_Hex;
         Current_Last := Current_Tree_ID'Last;
         Cursor := Cursor + 1;
         if Cursor > Path'Last then
            Entry_Mode := 0;
            Entry_ID_Last := Entry_ID_Hex'First - 1;
            return Invalid_Command;
         end if;
      end loop;

      Entry_Mode := 0;
      Entry_ID_Last := Entry_ID_Hex'First - 1;
      return Invalid_Command;
   exception
      when Constraint_Error =>
         Entry_Mode := 0;
         Entry_ID_Last := Entry_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Entry_Mode := 0;
         Entry_ID_Last := Entry_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Resolve_Path_Entry_Hex;

   function Read_Path_Tree_Entries_Hex
     (Repository_Root     : String;
      Root_Tree_ID_Hex    : Stream_Element_Array;
      Path                : Stream_Element_Array;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Path_Tree_Data      : out Stream_Element_Array;
      Path_Tree_Last      : out Stream_Element_Offset;
      Path_Mode           : out Natural;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Names               : out Stream_Element_Array;
      Name_Lasts          : out Tree_Entry_Name_Last_Array;
      Modes               : out Tree_Entry_Mode_Array;
      Object_IDs_Hex      : out Object_ID_Hex_Array;
      Count               : out Natural)
      return Status
   is
      Entry_ID_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Entry_ID_Last : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Path_Mode := 0;
      Path_Tree_Last := Path_Tree_Data'First - 1;
      Tree_Last := Tree_Data'First - 1;
      Count := 0;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      Status_Value :=
        Resolve_Path_Entry_Hex
          (Repository_Root,
           Root_Tree_ID_Hex,
           Path,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Path_Tree_Data,
           Path_Tree_Last,
           Path_Mode,
           Entry_ID_Hex,
           Entry_ID_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Path_Mode /= 8#040000#
        or else Entry_ID_Last /= Entry_ID_Hex'Last
      then
         Path_Mode := 0;
         Count := 0;
         return Invalid_Command;
      end if;

      return
        Read_Tree_Entries_Hex
          (Repository_Root,
           Entry_ID_Hex,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Tree_Data,
           Tree_Last,
           Names,
           Name_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
   exception
      when Constraint_Error =>
         Path_Mode := 0;
         Path_Tree_Last := Path_Tree_Data'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Count := 0;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Path_Mode := 0;
         Path_Tree_Last := Path_Tree_Data'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Count := 0;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Read_Path_Tree_Entries_Hex;

   function Read_Commit_Path_Object
     (Repository_Root     : String;
      Commit_ID_Hex       : Stream_Element_Array;
      Path                : Stream_Element_Array;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Commit_Data         : out Stream_Element_Array;
      Commit_Last         : out Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Stream_Element_Array;
      Root_Tree_ID_Last   : out Stream_Element_Offset;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Kind                : out Pack_Object_Kind;
      Data                : out Stream_Element_Array;
      Last                : out Stream_Element_Offset)
      return Status
   is
      Commit_Kind : Pack_Object_Kind := Pack_Blob;
      Status_Value : Status;
   begin
      Entry_Mode := 0;
      Kind := Pack_Blob;
      Last := Data'First - 1;
      Tree_Last := Tree_Data'First - 1;
      Commit_Last := Commit_Data'First - 1;
      Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      Status_Value :=
        Read_Any_Stored_Object_Validated
          (Repository_Root,
           Commit_ID_Hex,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Commit_Kind,
           Commit_Data,
           Commit_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Commit_Kind /= Pack_Commit
        or else Commit_Last < Commit_Data'First
      then
         Commit_Last := Commit_Data'First - 1;
         return Invalid_Command;
      end if;

      Status_Value :=
        Parse_Commit_Tree_ID
          (Commit_Data (Commit_Data'First .. Commit_Last),
           Root_Tree_ID_Hex,
           Root_Tree_ID_Last);
      if Status_Value /= Ok then
         Entry_Mode := 0;
         Last := Data'First - 1;
         return Status_Value;
      elsif Root_Tree_ID_Last < Root_Tree_ID_Hex'First then
         Entry_Mode := 0;
         Last := Data'First - 1;
         return Invalid_Command;
      end if;

      return
        Read_Path_Object
          (Repository_Root,
           Root_Tree_ID_Hex
             (Root_Tree_ID_Hex'First .. Root_Tree_ID_Last),
           Path,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Tree_Data,
           Tree_Last,
           Entry_Mode,
           Kind,
           Data,
           Last);
   exception
      when Constraint_Error =>
         Entry_Mode := 0;
         Kind := Pack_Blob;
         Last := Data'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Entry_Mode := 0;
         Kind := Pack_Blob;
         Last := Data'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Read_Commit_Path_Object;

   function Resolve_Commit_Path_Entry_Hex
     (Repository_Root     : String;
      Commit_ID_Hex       : Stream_Element_Array;
      Path                : Stream_Element_Array;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Commit_Data         : out Stream_Element_Array;
      Commit_Last         : out Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Stream_Element_Array;
      Root_Tree_ID_Last   : out Stream_Element_Offset;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Entry_ID_Hex        : out Stream_Element_Array;
      Entry_ID_Last       : out Stream_Element_Offset)
      return Status
   is
      Commit_Kind : Pack_Object_Kind := Pack_Blob;
      Status_Value : Status;
   begin
      Entry_Mode := 0;
      Entry_ID_Last := Entry_ID_Hex'First - 1;
      Tree_Last := Tree_Data'First - 1;
      Commit_Last := Commit_Data'First - 1;
      Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      Status_Value :=
        Read_Any_Stored_Object_Validated
          (Repository_Root,
           Commit_ID_Hex,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Commit_Kind,
           Commit_Data,
           Commit_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Commit_Kind /= Pack_Commit
        or else Commit_Last < Commit_Data'First
      then
         Commit_Last := Commit_Data'First - 1;
         return Invalid_Command;
      end if;

      Status_Value :=
        Parse_Commit_Tree_ID
          (Commit_Data (Commit_Data'First .. Commit_Last),
           Root_Tree_ID_Hex,
           Root_Tree_ID_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Root_Tree_ID_Last < Root_Tree_ID_Hex'First then
         return Invalid_Command;
      end if;

      return
        Resolve_Path_Entry_Hex
          (Repository_Root,
           Root_Tree_ID_Hex
             (Root_Tree_ID_Hex'First .. Root_Tree_ID_Last),
           Path,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Tree_Data,
           Tree_Last,
           Entry_Mode,
           Entry_ID_Hex,
           Entry_ID_Last);
   exception
      when Constraint_Error =>
         Entry_Mode := 0;
         Entry_ID_Last := Entry_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Entry_Mode := 0;
         Entry_ID_Last := Entry_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Resolve_Commit_Path_Entry_Hex;

   function Read_Commit_Tree_Object
     (Repository_Root     : String;
      Commit_ID_Hex       : Stream_Element_Array;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Commit_Data         : out Stream_Element_Array;
      Commit_Last         : out Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Stream_Element_Array;
      Root_Tree_ID_Last   : out Stream_Element_Offset;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Entry_Count         : out Natural)
      return Status
   is
      Commit_Kind : Pack_Object_Kind := Pack_Blob;
      Tree_Kind   : Pack_Object_Kind := Pack_Blob;
      Status_Value : Status;
   begin
      Commit_Last := Commit_Data'First - 1;
      Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
      Tree_Last := Tree_Data'First - 1;
      Entry_Count := 0;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      Status_Value :=
        Read_Any_Stored_Object_Validated
          (Repository_Root,
           Commit_ID_Hex,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Commit_Kind,
           Commit_Data,
           Commit_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Commit_Kind /= Pack_Commit
        or else Commit_Last < Commit_Data'First
      then
         Commit_Last := Commit_Data'First - 1;
         return Invalid_Command;
      end if;

      Status_Value :=
        Parse_Commit_Tree_ID
          (Commit_Data (Commit_Data'First .. Commit_Last),
           Root_Tree_ID_Hex,
           Root_Tree_ID_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Root_Tree_ID_Last < Root_Tree_ID_Hex'First then
         return Invalid_Command;
      end if;

      Status_Value :=
        Read_Any_Stored_Object_Validated
          (Repository_Root,
           Root_Tree_ID_Hex (Root_Tree_ID_Hex'First .. Root_Tree_ID_Last),
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Tree_Kind,
           Tree_Data,
           Tree_Last);
      if Status_Value /= Ok then
         Tree_Last := Tree_Data'First - 1;
         Entry_Count := 0;
         return Status_Value;
      elsif Tree_Kind /= Pack_Tree or else Tree_Last < Tree_Data'First then
         Tree_Last := Tree_Data'First - 1;
         Entry_Count := 0;
         return Invalid_Command;
      end if;

      Status_Value :=
        Validate_Tree_Object
          (Tree_Data (Tree_Data'First .. Tree_Last),
           Entry_Count);
      if Status_Value /= Ok then
         Tree_Last := Tree_Data'First - 1;
         Entry_Count := 0;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Entry_Count := 0;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Entry_Count := 0;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Read_Commit_Tree_Object;

   function Read_Commit_Tree_Entries_Hex
     (Repository_Root     : String;
      Commit_ID_Hex       : Stream_Element_Array;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Commit_Data         : out Stream_Element_Array;
      Commit_Last         : out Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Stream_Element_Array;
      Root_Tree_ID_Last   : out Stream_Element_Offset;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Names               : out Stream_Element_Array;
      Name_Lasts          : out Tree_Entry_Name_Last_Array;
      Modes               : out Tree_Entry_Mode_Array;
      Object_IDs_Hex      : out Object_ID_Hex_Array;
      Count               : out Natural)
      return Status
   is
      Status_Value : Status;
      Tree_Count   : Natural := 0;
   begin
      Count := 0;
      Status_Value :=
        Read_Commit_Tree_Object
          (Repository_Root,
           Commit_ID_Hex,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Commit_Data,
           Commit_Last,
           Root_Tree_ID_Hex,
           Root_Tree_ID_Last,
           Tree_Data,
           Tree_Last,
           Tree_Count);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Tree_Last < Tree_Data'First then
         Count := 0;
         return Ok;
      end if;

      Status_Value :=
        List_Tree_Entries_Hex
          (Tree_Data (Tree_Data'First .. Tree_Last),
           Names,
           Name_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
      if Status_Value /= Ok then
         Count := 0;
      elsif Count /= Tree_Count then
         Count := 0;
         return Internal_Error;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Count := 0;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Count := 0;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Read_Commit_Tree_Entries_Hex;

   function List_Commit_Tree_Paths_Hex
     (Repository_Root : String;
      Commit_ID_Hex   : Stream_Element_Array;
      Paths           : out Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return Status
   is
      Commit_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Commit_Last : Stream_Element_Offset;
      Scratch : Tree_Traversal_Scratch_Access := null;
      Pack_Checksum_Last : Stream_Element_Offset;
      Root_Tree_ID_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Root_Tree_ID_Last : Stream_Element_Offset;
      Commit_Kind : Pack_Object_Kind := Pack_Blob;
      Status_Value : Status;
   begin
      Count := 0;
      Scratch := new Tree_Traversal_Scratch;
      Status_Value :=
        Read_Any_Stored_Object_Resolved_Validated
          (Repository_Root,
           Commit_ID_Hex,
           Scratch.Pack_Checksums_Hex,
           Scratch.Pack_Data,
           Scratch.Index_Data,
           Scratch.Base_Data,
           Scratch.Delta_Data,
           Scratch.Workspace,
           Scratch.Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Commit_Kind,
           Commit_Data,
           Commit_Last);
      if Status_Value /= Ok then
         Free_Tree_Traversal_Scratch (Scratch);
         return Status_Value;
      elsif Commit_Kind /= Pack_Commit
        or else Commit_Last < Commit_Data'First
      then
         Free_Tree_Traversal_Scratch (Scratch);
         return Invalid_Command;
      end if;

      Status_Value :=
        Parse_Commit_Tree_ID
          (Commit_Data (Commit_Data'First .. Commit_Last),
           Root_Tree_ID_Hex,
           Root_Tree_ID_Last);
      if Status_Value /= Ok then
         Free_Tree_Traversal_Scratch (Scratch);
         return Status_Value;
      elsif Root_Tree_ID_Last /= Root_Tree_ID_Hex'Last then
         Free_Tree_Traversal_Scratch (Scratch);
         return Invalid_Command;
      end if;

      Free_Tree_Traversal_Scratch (Scratch);
      return
        List_Tree_Paths_Hex
          (Repository_Root,
           Root_Tree_ID_Hex,
           Paths,
           Path_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
   exception
      when Constraint_Error =>
         if Scratch /= null then
            Free_Tree_Traversal_Scratch (Scratch);
         end if;
         Count := 0;
         return Invalid_Command;
      when others =>
         if Scratch /= null then
            Free_Tree_Traversal_Scratch (Scratch);
         end if;
         Count := 0;
         return Read_Failed;
   end List_Commit_Tree_Paths_Hex;

   function List_Commit_Tree_Paths_Matching_Hex
     (Repository_Root : String;
      Commit_ID_Hex   : Stream_Element_Array;
      Pathspec        : String;
      Paths           : out Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return Status
   is
      Status_Value : Status;
   begin
      Status_Value :=
        List_Commit_Tree_Paths_Hex
          (Repository_Root,
           Commit_ID_Hex,
           Paths,
           Path_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return
        Filter_Tree_Paths_By_Pathspec
          (Pathspec, Paths, Path_Lasts, Modes, Object_IDs_Hex, Count);
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Read_Failed;
   end List_Commit_Tree_Paths_Matching_Hex;

   function Read_Commit_Path_Tree_Entries_Hex
     (Repository_Root     : String;
      Commit_ID_Hex       : Stream_Element_Array;
      Path                : Stream_Element_Array;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Commit_Data         : out Stream_Element_Array;
      Commit_Last         : out Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Stream_Element_Array;
      Root_Tree_ID_Last   : out Stream_Element_Offset;
      Path_Tree_Data      : out Stream_Element_Array;
      Path_Tree_Last      : out Stream_Element_Offset;
      Path_Mode           : out Natural;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Names               : out Stream_Element_Array;
      Name_Lasts          : out Tree_Entry_Name_Last_Array;
      Modes               : out Tree_Entry_Mode_Array;
      Object_IDs_Hex      : out Object_ID_Hex_Array;
      Count               : out Natural)
      return Status
   is
      Commit_Kind : Pack_Object_Kind := Pack_Blob;
      Status_Value : Status;
   begin
      Commit_Last := Commit_Data'First - 1;
      Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
      Path_Tree_Last := Path_Tree_Data'First - 1;
      Path_Mode := 0;
      Tree_Last := Tree_Data'First - 1;
      Count := 0;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      Status_Value :=
        Read_Any_Stored_Object_Validated
          (Repository_Root,
           Commit_ID_Hex,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Commit_Kind,
           Commit_Data,
           Commit_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Commit_Kind /= Pack_Commit
        or else Commit_Last < Commit_Data'First
      then
         Commit_Last := Commit_Data'First - 1;
         return Invalid_Command;
      end if;

      Status_Value :=
        Parse_Commit_Tree_ID
          (Commit_Data (Commit_Data'First .. Commit_Last),
           Root_Tree_ID_Hex,
           Root_Tree_ID_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Root_Tree_ID_Last < Root_Tree_ID_Hex'First then
         return Invalid_Command;
      end if;

      return
        Read_Path_Tree_Entries_Hex
          (Repository_Root,
           Root_Tree_ID_Hex
             (Root_Tree_ID_Hex'First .. Root_Tree_ID_Last),
           Path,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Path_Tree_Data,
           Path_Tree_Last,
           Path_Mode,
           Tree_Data,
           Tree_Last,
           Names,
           Name_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
   exception
      when Constraint_Error =>
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Path_Tree_Last := Path_Tree_Data'First - 1;
         Path_Mode := 0;
         Tree_Last := Tree_Data'First - 1;
         Count := 0;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Path_Tree_Last := Path_Tree_Data'First - 1;
         Path_Mode := 0;
         Tree_Last := Tree_Data'First - 1;
         Count := 0;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Read_Commit_Path_Tree_Entries_Hex;

   function Read_Ref_Path_Object
     (Repository_Root     : String;
      Ref_Name            : String;
      Path                : Stream_Element_Array;
      Resolved_ID_Hex     : out Stream_Element_Array;
      Resolved_ID_Last    : out Stream_Element_Offset;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Commit_Data         : out Stream_Element_Array;
      Commit_Last         : out Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Stream_Element_Array;
      Root_Tree_ID_Last   : out Stream_Element_Offset;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Kind                : out Pack_Object_Kind;
      Data                : out Stream_Element_Array;
      Last                : out Stream_Element_Offset)
      return Status
   is
      Status_Value : Status;
   begin
      Entry_Mode := 0;
      Kind := Pack_Blob;
      Last := Data'First - 1;
      Tree_Last := Tree_Data'First - 1;
      Commit_Last := Commit_Data'First - 1;
      Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
      Resolved_ID_Last := Resolved_ID_Hex'First - 1;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      Status_Value :=
        Resolve_Ref
          (Repository_Root,
           Ref_Name,
           Resolved_ID_Hex,
           Resolved_ID_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Resolved_ID_Last < Resolved_ID_Hex'First then
         return Invalid_Command;
      end if;

      return
        Read_Commit_Path_Object
          (Repository_Root,
           Resolved_ID_Hex (Resolved_ID_Hex'First .. Resolved_ID_Last),
           Path,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Commit_Data,
           Commit_Last,
           Root_Tree_ID_Hex,
           Root_Tree_ID_Last,
           Tree_Data,
           Tree_Last,
           Entry_Mode,
           Kind,
           Data,
           Last);
   exception
      when Constraint_Error =>
         Entry_Mode := 0;
         Kind := Pack_Blob;
         Last := Data'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Resolved_ID_Last := Resolved_ID_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Entry_Mode := 0;
         Kind := Pack_Blob;
         Last := Data'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Resolved_ID_Last := Resolved_ID_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Read_Ref_Path_Object;

   function Read_Ref_Path_Tree_Entries_Hex
     (Repository_Root     : String;
      Ref_Name            : String;
      Path                : Stream_Element_Array;
      Resolved_ID_Hex     : out Stream_Element_Array;
      Resolved_ID_Last    : out Stream_Element_Offset;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Commit_Data         : out Stream_Element_Array;
      Commit_Last         : out Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Stream_Element_Array;
      Root_Tree_ID_Last   : out Stream_Element_Offset;
      Path_Tree_Data      : out Stream_Element_Array;
      Path_Tree_Last      : out Stream_Element_Offset;
      Path_Mode           : out Natural;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Names               : out Stream_Element_Array;
      Name_Lasts          : out Tree_Entry_Name_Last_Array;
      Modes               : out Tree_Entry_Mode_Array;
      Object_IDs_Hex      : out Object_ID_Hex_Array;
      Count               : out Natural)
      return Status
   is
      Status_Value : Status;
   begin
      Resolved_ID_Last := Resolved_ID_Hex'First - 1;
      Commit_Last := Commit_Data'First - 1;
      Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
      Path_Tree_Last := Path_Tree_Data'First - 1;
      Path_Mode := 0;
      Tree_Last := Tree_Data'First - 1;
      Count := 0;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      Status_Value :=
        Resolve_Ref
          (Repository_Root,
           Ref_Name,
           Resolved_ID_Hex,
           Resolved_ID_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Resolved_ID_Last < Resolved_ID_Hex'First then
         return Invalid_Command;
      end if;

      return
        Read_Commit_Path_Tree_Entries_Hex
          (Repository_Root,
           Resolved_ID_Hex (Resolved_ID_Hex'First .. Resolved_ID_Last),
           Path,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Commit_Data,
           Commit_Last,
           Root_Tree_ID_Hex,
           Root_Tree_ID_Last,
           Path_Tree_Data,
           Path_Tree_Last,
           Path_Mode,
           Tree_Data,
           Tree_Last,
           Names,
           Name_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
   exception
      when Constraint_Error =>
         Resolved_ID_Last := Resolved_ID_Hex'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Path_Tree_Last := Path_Tree_Data'First - 1;
         Path_Mode := 0;
         Tree_Last := Tree_Data'First - 1;
         Count := 0;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Resolved_ID_Last := Resolved_ID_Hex'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Path_Tree_Last := Path_Tree_Data'First - 1;
         Path_Mode := 0;
         Tree_Last := Tree_Data'First - 1;
         Count := 0;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Read_Ref_Path_Tree_Entries_Hex;

   function Resolve_Ref_Path_Entry_Hex
     (Repository_Root     : String;
      Ref_Name            : String;
      Path                : Stream_Element_Array;
      Resolved_ID_Hex     : out Stream_Element_Array;
      Resolved_ID_Last    : out Stream_Element_Offset;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Commit_Data         : out Stream_Element_Array;
      Commit_Last         : out Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Stream_Element_Array;
      Root_Tree_ID_Last   : out Stream_Element_Offset;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Entry_ID_Hex        : out Stream_Element_Array;
      Entry_ID_Last       : out Stream_Element_Offset)
      return Status
   is
      Status_Value : Status;
   begin
      Entry_Mode := 0;
      Entry_ID_Last := Entry_ID_Hex'First - 1;
      Tree_Last := Tree_Data'First - 1;
      Commit_Last := Commit_Data'First - 1;
      Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
      Resolved_ID_Last := Resolved_ID_Hex'First - 1;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      Status_Value :=
        Resolve_Ref
          (Repository_Root,
           Ref_Name,
           Resolved_ID_Hex,
           Resolved_ID_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Resolved_ID_Last < Resolved_ID_Hex'First then
         return Invalid_Command;
      end if;

      return
        Resolve_Commit_Path_Entry_Hex
          (Repository_Root,
           Resolved_ID_Hex (Resolved_ID_Hex'First .. Resolved_ID_Last),
           Path,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Commit_Data,
           Commit_Last,
           Root_Tree_ID_Hex,
           Root_Tree_ID_Last,
           Tree_Data,
           Tree_Last,
           Entry_Mode,
           Entry_ID_Hex,
           Entry_ID_Last);
   exception
      when Constraint_Error =>
         Entry_Mode := 0;
         Entry_ID_Last := Entry_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Resolved_ID_Last := Resolved_ID_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Entry_Mode := 0;
         Entry_ID_Last := Entry_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Resolved_ID_Last := Resolved_ID_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Resolve_Ref_Path_Entry_Hex;

   function Read_Tag_Path_Object
     (Repository_Root     : String;
      Tag_ID_Hex          : Stream_Element_Array;
      Path                : Stream_Element_Array;
      Peeled_Commit_Hex   : out Stream_Element_Array;
      Peeled_Commit_Last  : out Stream_Element_Offset;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Tag_Data            : out Stream_Element_Array;
      Tag_Last            : out Stream_Element_Offset;
      Commit_Data         : out Stream_Element_Array;
      Commit_Last         : out Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Stream_Element_Array;
      Root_Tree_ID_Last   : out Stream_Element_Offset;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Kind                : out Pack_Object_Kind;
      Data                : out Stream_Element_Array;
      Last                : out Stream_Element_Offset)
      return Status
   is
      Current_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Target_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Target_Last : Stream_Element_Offset;
      Target_Kind : Pack_Object_Kind := Pack_Blob;
      Object_Kind : Pack_Object_Kind := Pack_Blob;
      Status_Value : Status;
   begin
      Entry_Mode := 0;
      Kind := Pack_Blob;
      Last := Data'First - 1;
      Tree_Last := Tree_Data'First - 1;
      Commit_Last := Commit_Data'First - 1;
      Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
      Tag_Last := Tag_Data'First - 1;
      Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      if Tag_ID_Hex'Length
          < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
        or else Peeled_Commit_Hex'Length
          < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Invalid_Command;
      end if;

      Current_ID :=
        Tag_ID_Hex
          (Tag_ID_Hex'First
           .. Tag_ID_Hex'First
              + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
              - 1);

      for Depth in 1 .. Maximum_Ref_Resolution_Depth loop
         Status_Value :=
           Read_Any_Stored_Object_Validated
             (Repository_Root,
              Current_ID,
              Pack_Checksums_Hex,
              Pack_Data,
              Index_Data,
              Pack_Checksum_Hex,
              Pack_Checksum_Last,
              Object_Kind,
              Tag_Data,
              Tag_Last);
         if Status_Value /= Ok then
            return Status_Value;
         elsif Object_Kind /= Pack_Tag or else Tag_Last < Tag_Data'First then
            Tag_Last := Tag_Data'First - 1;
            return Invalid_Command;
         end if;

         Status_Value :=
           Parse_Tag_Target
             (Tag_Data (Tag_Data'First .. Tag_Last),
              Target_ID,
              Target_Last,
              Target_Kind);
         if Status_Value /= Ok then
            return Status_Value;
         elsif Target_Last /= Target_ID'Last then
            return Invalid_Command;
         end if;

         case Target_Kind is
            when Pack_Commit =>
               Peeled_Commit_Hex
                 (Peeled_Commit_Hex'First
                  .. Peeled_Commit_Hex'First
                     + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                     - 1) := Target_ID;
               Peeled_Commit_Last :=
                 Peeled_Commit_Hex'First
                 + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                 - 1;
               return
                 Read_Commit_Path_Object
                   (Repository_Root,
                    Peeled_Commit_Hex
                      (Peeled_Commit_Hex'First .. Peeled_Commit_Last),
                    Path,
                    Pack_Checksums_Hex,
                    Pack_Data,
                    Index_Data,
                    Pack_Checksum_Hex,
                    Pack_Checksum_Last,
                    Commit_Data,
                    Commit_Last,
                    Root_Tree_ID_Hex,
                    Root_Tree_ID_Last,
                    Tree_Data,
                    Tree_Last,
                    Entry_Mode,
                    Kind,
                    Data,
                    Last);
            when Pack_Tag =>
               Current_ID := Target_ID;
            when others =>
               return Invalid_Command;
         end case;
      end loop;

      return Invalid_Command;
   exception
      when Constraint_Error =>
         Entry_Mode := 0;
         Kind := Pack_Blob;
         Last := Data'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Tag_Last := Tag_Data'First - 1;
         Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Entry_Mode := 0;
         Kind := Pack_Blob;
         Last := Data'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Tag_Last := Tag_Data'First - 1;
         Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Read_Tag_Path_Object;

   function Read_Tag_Path_Tree_Entries_Hex
     (Repository_Root     : String;
      Tag_ID_Hex          : Stream_Element_Array;
      Path                : Stream_Element_Array;
      Peeled_Commit_Hex   : out Stream_Element_Array;
      Peeled_Commit_Last  : out Stream_Element_Offset;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Tag_Data            : out Stream_Element_Array;
      Tag_Last            : out Stream_Element_Offset;
      Commit_Data         : out Stream_Element_Array;
      Commit_Last         : out Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Stream_Element_Array;
      Root_Tree_ID_Last   : out Stream_Element_Offset;
      Path_Tree_Data      : out Stream_Element_Array;
      Path_Tree_Last      : out Stream_Element_Offset;
      Path_Mode           : out Natural;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Names               : out Stream_Element_Array;
      Name_Lasts          : out Tree_Entry_Name_Last_Array;
      Modes               : out Tree_Entry_Mode_Array;
      Object_IDs_Hex      : out Object_ID_Hex_Array;
      Count               : out Natural)
      return Status
   is
      Current_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Target_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Target_Last : Stream_Element_Offset;
      Target_Kind : Pack_Object_Kind := Pack_Blob;
      Object_Kind : Pack_Object_Kind := Pack_Blob;
      Status_Value : Status;
   begin
      Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
      Tag_Last := Tag_Data'First - 1;
      Commit_Last := Commit_Data'First - 1;
      Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
      Path_Tree_Last := Path_Tree_Data'First - 1;
      Path_Mode := 0;
      Tree_Last := Tree_Data'First - 1;
      Count := 0;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      if Tag_ID_Hex'Length
          < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
        or else Peeled_Commit_Hex'Length
          < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Invalid_Command;
      end if;

      Current_ID :=
        Tag_ID_Hex
          (Tag_ID_Hex'First
           .. Tag_ID_Hex'First
              + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
              - 1);

      for Depth in 1 .. Maximum_Ref_Resolution_Depth loop
         Status_Value :=
           Read_Any_Stored_Object_Validated
             (Repository_Root,
              Current_ID,
              Pack_Checksums_Hex,
              Pack_Data,
              Index_Data,
              Pack_Checksum_Hex,
              Pack_Checksum_Last,
              Object_Kind,
              Tag_Data,
              Tag_Last);
         if Status_Value /= Ok then
            return Status_Value;
         elsif Object_Kind /= Pack_Tag or else Tag_Last < Tag_Data'First then
            Tag_Last := Tag_Data'First - 1;
            return Invalid_Command;
         end if;

         Status_Value :=
           Parse_Tag_Target
             (Tag_Data (Tag_Data'First .. Tag_Last),
              Target_ID,
              Target_Last,
              Target_Kind);
         if Status_Value /= Ok then
            return Status_Value;
         elsif Target_Last /= Target_ID'Last then
            return Invalid_Command;
         end if;

         case Target_Kind is
            when Pack_Commit =>
               Peeled_Commit_Hex
                 (Peeled_Commit_Hex'First
                  .. Peeled_Commit_Hex'First
                     + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                     - 1) := Target_ID;
               Peeled_Commit_Last :=
                 Peeled_Commit_Hex'First
                 + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                 - 1;
               return
                 Read_Commit_Path_Tree_Entries_Hex
                   (Repository_Root,
                    Peeled_Commit_Hex
                      (Peeled_Commit_Hex'First .. Peeled_Commit_Last),
                    Path,
                    Pack_Checksums_Hex,
                    Pack_Data,
                    Index_Data,
                    Pack_Checksum_Hex,
                    Pack_Checksum_Last,
                    Commit_Data,
                    Commit_Last,
                    Root_Tree_ID_Hex,
                    Root_Tree_ID_Last,
                    Path_Tree_Data,
                    Path_Tree_Last,
                    Path_Mode,
                    Tree_Data,
                    Tree_Last,
                    Names,
                    Name_Lasts,
                    Modes,
                    Object_IDs_Hex,
                    Count);
            when Pack_Tag =>
               Current_ID := Target_ID;
            when others =>
               return Invalid_Command;
         end case;
      end loop;

      return Invalid_Command;
   exception
      when Constraint_Error =>
         Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
         Tag_Last := Tag_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Path_Tree_Last := Path_Tree_Data'First - 1;
         Path_Mode := 0;
         Tree_Last := Tree_Data'First - 1;
         Count := 0;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
         Tag_Last := Tag_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Path_Tree_Last := Path_Tree_Data'First - 1;
         Path_Mode := 0;
         Tree_Last := Tree_Data'First - 1;
         Count := 0;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Read_Tag_Path_Tree_Entries_Hex;

   function Resolve_Tag_Path_Entry_Hex
     (Repository_Root     : String;
      Tag_ID_Hex          : Stream_Element_Array;
      Path                : Stream_Element_Array;
      Peeled_Commit_Hex   : out Stream_Element_Array;
      Peeled_Commit_Last  : out Stream_Element_Offset;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Tag_Data            : out Stream_Element_Array;
      Tag_Last            : out Stream_Element_Offset;
      Commit_Data         : out Stream_Element_Array;
      Commit_Last         : out Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Stream_Element_Array;
      Root_Tree_ID_Last   : out Stream_Element_Offset;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Entry_ID_Hex        : out Stream_Element_Array;
      Entry_ID_Last       : out Stream_Element_Offset)
      return Status
   is
      Current_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Target_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Target_Last : Stream_Element_Offset;
      Target_Kind : Pack_Object_Kind := Pack_Blob;
      Object_Kind : Pack_Object_Kind := Pack_Blob;
      Status_Value : Status;
   begin
      Entry_Mode := 0;
      Entry_ID_Last := Entry_ID_Hex'First - 1;
      Tree_Last := Tree_Data'First - 1;
      Commit_Last := Commit_Data'First - 1;
      Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
      Tag_Last := Tag_Data'First - 1;
      Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      if Tag_ID_Hex'Length
          < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
        or else Peeled_Commit_Hex'Length
          < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Invalid_Command;
      end if;

      Current_ID :=
        Tag_ID_Hex
          (Tag_ID_Hex'First
           .. Tag_ID_Hex'First
              + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
              - 1);

      for Depth in 1 .. Maximum_Ref_Resolution_Depth loop
         Status_Value :=
           Read_Any_Stored_Object_Validated
             (Repository_Root,
              Current_ID,
              Pack_Checksums_Hex,
              Pack_Data,
              Index_Data,
              Pack_Checksum_Hex,
              Pack_Checksum_Last,
              Object_Kind,
              Tag_Data,
              Tag_Last);
         if Status_Value /= Ok then
            return Status_Value;
         elsif Object_Kind /= Pack_Tag or else Tag_Last < Tag_Data'First then
            Tag_Last := Tag_Data'First - 1;
            return Invalid_Command;
         end if;

         Status_Value :=
           Parse_Tag_Target
             (Tag_Data (Tag_Data'First .. Tag_Last),
              Target_ID,
              Target_Last,
              Target_Kind);
         if Status_Value /= Ok then
            return Status_Value;
         elsif Target_Last /= Target_ID'Last then
            return Invalid_Command;
         end if;

         case Target_Kind is
            when Pack_Commit =>
               Peeled_Commit_Hex
                 (Peeled_Commit_Hex'First
                  .. Peeled_Commit_Hex'First
                     + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                     - 1) := Target_ID;
               Peeled_Commit_Last :=
                 Peeled_Commit_Hex'First
                 + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                 - 1;
               return
                 Resolve_Commit_Path_Entry_Hex
                   (Repository_Root,
                    Peeled_Commit_Hex
                      (Peeled_Commit_Hex'First .. Peeled_Commit_Last),
                    Path,
                    Pack_Checksums_Hex,
                    Pack_Data,
                    Index_Data,
                    Pack_Checksum_Hex,
                    Pack_Checksum_Last,
                    Commit_Data,
                    Commit_Last,
                    Root_Tree_ID_Hex,
                    Root_Tree_ID_Last,
                    Tree_Data,
                    Tree_Last,
                    Entry_Mode,
                    Entry_ID_Hex,
                    Entry_ID_Last);
            when Pack_Tag =>
               Current_ID := Target_ID;
            when others =>
               return Invalid_Command;
         end case;
      end loop;

      return Invalid_Command;
   exception
      when Constraint_Error =>
         Entry_Mode := 0;
         Entry_ID_Last := Entry_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Tag_Last := Tag_Data'First - 1;
         Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Entry_Mode := 0;
         Entry_ID_Last := Entry_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Tag_Last := Tag_Data'First - 1;
         Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Resolve_Tag_Path_Entry_Hex;

   function Read_Ref_Commitish_Path_Object
     (Repository_Root     : String;
      Ref_Name            : String;
      Path                : Stream_Element_Array;
      Resolved_ID_Hex     : out Stream_Element_Array;
      Resolved_ID_Last    : out Stream_Element_Offset;
      Peeled_Commit_Hex   : out Stream_Element_Array;
      Peeled_Commit_Last  : out Stream_Element_Offset;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Tag_Data            : out Stream_Element_Array;
      Tag_Last            : out Stream_Element_Offset;
      Commit_Data         : out Stream_Element_Array;
      Commit_Last         : out Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Stream_Element_Array;
      Root_Tree_ID_Last   : out Stream_Element_Offset;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Kind                : out Pack_Object_Kind;
      Data                : out Stream_Element_Array;
      Last                : out Stream_Element_Offset)
      return Status
   is
      Status_Value : Status;
   begin
      Entry_Mode := 0;
      Kind := Pack_Blob;
      Last := Data'First - 1;
      Tree_Last := Tree_Data'First - 1;
      Commit_Last := Commit_Data'First - 1;
      Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
      Tag_Last := Tag_Data'First - 1;
      Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
      Resolved_ID_Last := Resolved_ID_Hex'First - 1;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      if Peeled_Commit_Hex'Length
          < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Invalid_Command;
      end if;

      Status_Value :=
        Resolve_Ref
          (Repository_Root,
           Ref_Name,
           Resolved_ID_Hex,
           Resolved_ID_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Resolved_ID_Last < Resolved_ID_Hex'First then
         return Invalid_Command;
      end if;

      Status_Value :=
        Read_Commit_Path_Object
          (Repository_Root,
           Resolved_ID_Hex (Resolved_ID_Hex'First .. Resolved_ID_Last),
           Path,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Commit_Data,
           Commit_Last,
           Root_Tree_ID_Hex,
           Root_Tree_ID_Last,
           Tree_Data,
           Tree_Last,
           Entry_Mode,
           Kind,
           Data,
           Last);
      if Status_Value = Ok then
         Peeled_Commit_Hex
           (Peeled_Commit_Hex'First
            .. Peeled_Commit_Hex'First
               + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
               - 1) :=
             Resolved_ID_Hex
               (Resolved_ID_Hex'First .. Resolved_ID_Last);
         Peeled_Commit_Last :=
           Peeled_Commit_Hex'First
           + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
           - 1;
         Tag_Last := Tag_Data'First - 1;
         return Ok;
      elsif Status_Value /= Invalid_Command then
         return Status_Value;
      end if;

      return
        Read_Tag_Path_Object
          (Repository_Root,
           Resolved_ID_Hex (Resolved_ID_Hex'First .. Resolved_ID_Last),
           Path,
           Peeled_Commit_Hex,
           Peeled_Commit_Last,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Tag_Data,
           Tag_Last,
           Commit_Data,
           Commit_Last,
           Root_Tree_ID_Hex,
           Root_Tree_ID_Last,
           Tree_Data,
           Tree_Last,
           Entry_Mode,
           Kind,
           Data,
           Last);
   exception
      when Constraint_Error =>
         Entry_Mode := 0;
         Kind := Pack_Blob;
         Last := Data'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Tag_Last := Tag_Data'First - 1;
         Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
         Resolved_ID_Last := Resolved_ID_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Entry_Mode := 0;
         Kind := Pack_Blob;
         Last := Data'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Tag_Last := Tag_Data'First - 1;
         Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
         Resolved_ID_Last := Resolved_ID_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Read_Ref_Commitish_Path_Object;

   function Read_Ref_Commitish_Path_Tree_Entries_Hex
     (Repository_Root     : String;
      Ref_Name            : String;
      Path                : Stream_Element_Array;
      Resolved_ID_Hex     : out Stream_Element_Array;
      Resolved_ID_Last    : out Stream_Element_Offset;
      Peeled_Commit_Hex   : out Stream_Element_Array;
      Peeled_Commit_Last  : out Stream_Element_Offset;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Tag_Data            : out Stream_Element_Array;
      Tag_Last            : out Stream_Element_Offset;
      Commit_Data         : out Stream_Element_Array;
      Commit_Last         : out Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Stream_Element_Array;
      Root_Tree_ID_Last   : out Stream_Element_Offset;
      Path_Tree_Data      : out Stream_Element_Array;
      Path_Tree_Last      : out Stream_Element_Offset;
      Path_Mode           : out Natural;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Names               : out Stream_Element_Array;
      Name_Lasts          : out Tree_Entry_Name_Last_Array;
      Modes               : out Tree_Entry_Mode_Array;
      Object_IDs_Hex      : out Object_ID_Hex_Array;
      Count               : out Natural)
      return Status
   is
      Status_Value : Status;
   begin
      Resolved_ID_Last := Resolved_ID_Hex'First - 1;
      Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
      Tag_Last := Tag_Data'First - 1;
      Commit_Last := Commit_Data'First - 1;
      Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
      Path_Tree_Last := Path_Tree_Data'First - 1;
      Path_Mode := 0;
      Tree_Last := Tree_Data'First - 1;
      Count := 0;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      if Peeled_Commit_Hex'Length
          < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Invalid_Command;
      end if;

      Status_Value :=
        Resolve_Ref
          (Repository_Root,
           Ref_Name,
           Resolved_ID_Hex,
           Resolved_ID_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Resolved_ID_Last < Resolved_ID_Hex'First then
         return Invalid_Command;
      end if;

      Status_Value :=
        Read_Commit_Path_Tree_Entries_Hex
          (Repository_Root,
           Resolved_ID_Hex (Resolved_ID_Hex'First .. Resolved_ID_Last),
           Path,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Commit_Data,
           Commit_Last,
           Root_Tree_ID_Hex,
           Root_Tree_ID_Last,
           Path_Tree_Data,
           Path_Tree_Last,
           Path_Mode,
           Tree_Data,
           Tree_Last,
           Names,
           Name_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
      if Status_Value = Ok then
         Peeled_Commit_Hex
           (Peeled_Commit_Hex'First
            .. Peeled_Commit_Hex'First
               + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
               - 1) :=
             Resolved_ID_Hex
               (Resolved_ID_Hex'First .. Resolved_ID_Last);
         Peeled_Commit_Last :=
           Peeled_Commit_Hex'First
           + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
           - 1;
         Tag_Last := Tag_Data'First - 1;
         return Ok;
      elsif Status_Value /= Invalid_Command then
         return Status_Value;
      end if;

      return
        Read_Tag_Path_Tree_Entries_Hex
          (Repository_Root,
           Resolved_ID_Hex (Resolved_ID_Hex'First .. Resolved_ID_Last),
           Path,
           Peeled_Commit_Hex,
           Peeled_Commit_Last,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Tag_Data,
           Tag_Last,
           Commit_Data,
           Commit_Last,
           Root_Tree_ID_Hex,
           Root_Tree_ID_Last,
           Path_Tree_Data,
           Path_Tree_Last,
           Path_Mode,
           Tree_Data,
           Tree_Last,
           Names,
           Name_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
   exception
      when Constraint_Error =>
         Resolved_ID_Last := Resolved_ID_Hex'First - 1;
         Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
         Tag_Last := Tag_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Path_Tree_Last := Path_Tree_Data'First - 1;
         Path_Mode := 0;
         Tree_Last := Tree_Data'First - 1;
         Count := 0;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Resolved_ID_Last := Resolved_ID_Hex'First - 1;
         Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
         Tag_Last := Tag_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Path_Tree_Last := Path_Tree_Data'First - 1;
         Path_Mode := 0;
         Tree_Last := Tree_Data'First - 1;
         Count := 0;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Read_Ref_Commitish_Path_Tree_Entries_Hex;

   function Resolve_Ref_Commitish_Path_Entry_Hex
     (Repository_Root     : String;
      Ref_Name            : String;
      Path                : Stream_Element_Array;
      Resolved_ID_Hex     : out Stream_Element_Array;
      Resolved_ID_Last    : out Stream_Element_Offset;
      Peeled_Commit_Hex   : out Stream_Element_Array;
      Peeled_Commit_Last  : out Stream_Element_Offset;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Tag_Data            : out Stream_Element_Array;
      Tag_Last            : out Stream_Element_Offset;
      Commit_Data         : out Stream_Element_Array;
      Commit_Last         : out Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Stream_Element_Array;
      Root_Tree_ID_Last   : out Stream_Element_Offset;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Entry_Mode          : out Natural;
      Entry_ID_Hex        : out Stream_Element_Array;
      Entry_ID_Last       : out Stream_Element_Offset)
      return Status
   is
      Current_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Target_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Target_Last : Stream_Element_Offset;
      Target_Kind : Pack_Object_Kind := Pack_Blob;
      Object_Kind : Pack_Object_Kind := Pack_Blob;
      Status_Value : Status;
   begin
      Entry_Mode := 0;
      Entry_ID_Last := Entry_ID_Hex'First - 1;
      Tree_Last := Tree_Data'First - 1;
      Commit_Last := Commit_Data'First - 1;
      Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
      Tag_Last := Tag_Data'First - 1;
      Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
      Resolved_ID_Last := Resolved_ID_Hex'First - 1;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;

      if Peeled_Commit_Hex'Length
          < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Invalid_Command;
      end if;

      Status_Value :=
        Resolve_Ref
          (Repository_Root,
           Ref_Name,
           Resolved_ID_Hex,
           Resolved_ID_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Resolved_ID_Last < Resolved_ID_Hex'First then
         return Invalid_Command;
      end if;

      Status_Value :=
        Resolve_Commit_Path_Entry_Hex
          (Repository_Root,
           Resolved_ID_Hex (Resolved_ID_Hex'First .. Resolved_ID_Last),
           Path,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Commit_Data,
           Commit_Last,
           Root_Tree_ID_Hex,
           Root_Tree_ID_Last,
           Tree_Data,
           Tree_Last,
           Entry_Mode,
           Entry_ID_Hex,
           Entry_ID_Last);
      if Status_Value = Ok then
         Peeled_Commit_Hex
           (Peeled_Commit_Hex'First
            .. Peeled_Commit_Hex'First
               + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
               - 1) :=
             Resolved_ID_Hex
               (Resolved_ID_Hex'First .. Resolved_ID_Last);
         Peeled_Commit_Last :=
           Peeled_Commit_Hex'First
           + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
           - 1;
         Tag_Last := Tag_Data'First - 1;
         return Ok;
      elsif Status_Value /= Invalid_Command then
         return Status_Value;
      end if;

      Current_ID := Resolved_ID_Hex (Resolved_ID_Hex'First .. Resolved_ID_Last);
      for Depth in 1 .. Maximum_Ref_Resolution_Depth loop
         Status_Value :=
           Read_Any_Stored_Object_Validated
             (Repository_Root,
              Current_ID,
              Pack_Checksums_Hex,
              Pack_Data,
              Index_Data,
              Pack_Checksum_Hex,
              Pack_Checksum_Last,
              Object_Kind,
              Tag_Data,
              Tag_Last);
         if Status_Value /= Ok then
            return Status_Value;
         elsif Object_Kind /= Pack_Tag or else Tag_Last < Tag_Data'First then
            Tag_Last := Tag_Data'First - 1;
            return Invalid_Command;
         end if;

         Status_Value :=
           Parse_Tag_Target
             (Tag_Data (Tag_Data'First .. Tag_Last),
              Target_ID,
              Target_Last,
              Target_Kind);
         if Status_Value /= Ok then
            return Status_Value;
         elsif Target_Last /= Target_ID'Last then
            return Invalid_Command;
         end if;

         case Target_Kind is
            when Pack_Commit =>
               Peeled_Commit_Hex
                 (Peeled_Commit_Hex'First
                  .. Peeled_Commit_Hex'First
                     + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                     - 1) := Target_ID;
               Peeled_Commit_Last :=
                 Peeled_Commit_Hex'First
                 + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                 - 1;
               return
                 Resolve_Commit_Path_Entry_Hex
                   (Repository_Root,
                    Peeled_Commit_Hex
                      (Peeled_Commit_Hex'First .. Peeled_Commit_Last),
                    Path,
                    Pack_Checksums_Hex,
                    Pack_Data,
                    Index_Data,
                    Pack_Checksum_Hex,
                    Pack_Checksum_Last,
                    Commit_Data,
                    Commit_Last,
                    Root_Tree_ID_Hex,
                    Root_Tree_ID_Last,
                    Tree_Data,
                    Tree_Last,
                    Entry_Mode,
                    Entry_ID_Hex,
                    Entry_ID_Last);
            when Pack_Tag =>
               Current_ID := Target_ID;
            when others =>
               return Invalid_Command;
         end case;
      end loop;

      return Invalid_Command;
   exception
      when Constraint_Error =>
         Entry_Mode := 0;
         Entry_ID_Last := Entry_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Tag_Last := Tag_Data'First - 1;
         Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
         Resolved_ID_Last := Resolved_ID_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Entry_Mode := 0;
         Entry_ID_Last := Entry_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Tag_Last := Tag_Data'First - 1;
         Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
         Resolved_ID_Last := Resolved_ID_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         return Read_Failed;
   end Resolve_Ref_Commitish_Path_Entry_Hex;

   function Read_Ref_Commitish_Tree_Object
     (Repository_Root     : String;
      Ref_Name            : String;
      Resolved_ID_Hex     : out Stream_Element_Array;
      Resolved_ID_Last    : out Stream_Element_Offset;
      Peeled_Commit_Hex   : out Stream_Element_Array;
      Peeled_Commit_Last  : out Stream_Element_Offset;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Tag_Data            : out Stream_Element_Array;
      Tag_Last            : out Stream_Element_Offset;
      Commit_Data         : out Stream_Element_Array;
      Commit_Last         : out Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Stream_Element_Array;
      Root_Tree_ID_Last   : out Stream_Element_Offset;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Entry_Count         : out Natural)
      return Status
   is
      Current_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Target_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Target_Last : Stream_Element_Offset;
      Target_Kind : Pack_Object_Kind := Pack_Blob;
      Object_Kind : Pack_Object_Kind := Pack_Blob;
      Status_Value : Status;
   begin
      Resolved_ID_Last := Resolved_ID_Hex'First - 1;
      Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
      Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
      Tag_Last := Tag_Data'First - 1;
      Commit_Last := Commit_Data'First - 1;
      Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
      Tree_Last := Tree_Data'First - 1;
      Entry_Count := 0;

      if Peeled_Commit_Hex'Length
          < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Invalid_Command;
      end if;

      Status_Value :=
        Resolve_Ref
          (Repository_Root,
           Ref_Name,
           Resolved_ID_Hex,
           Resolved_ID_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Resolved_ID_Last < Resolved_ID_Hex'First then
         return Invalid_Command;
      end if;

      Status_Value :=
        Read_Commit_Tree_Object
          (Repository_Root,
           Resolved_ID_Hex (Resolved_ID_Hex'First .. Resolved_ID_Last),
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Commit_Data,
           Commit_Last,
           Root_Tree_ID_Hex,
           Root_Tree_ID_Last,
           Tree_Data,
           Tree_Last,
           Entry_Count);
      if Status_Value = Ok then
         Peeled_Commit_Hex
           (Peeled_Commit_Hex'First
            .. Peeled_Commit_Hex'First
               + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
               - 1) :=
             Resolved_ID_Hex
               (Resolved_ID_Hex'First .. Resolved_ID_Last);
         Peeled_Commit_Last :=
           Peeled_Commit_Hex'First
           + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
           - 1;
         Tag_Last := Tag_Data'First - 1;
         return Ok;
      elsif Status_Value /= Invalid_Command then
         return Status_Value;
      end if;

      Current_ID := Resolved_ID_Hex (Resolved_ID_Hex'First .. Resolved_ID_Last);
      for Depth in 1 .. Maximum_Ref_Resolution_Depth loop
         Status_Value :=
           Read_Any_Stored_Object_Validated
             (Repository_Root,
              Current_ID,
              Pack_Checksums_Hex,
              Pack_Data,
              Index_Data,
              Pack_Checksum_Hex,
              Pack_Checksum_Last,
              Object_Kind,
              Tag_Data,
              Tag_Last);
         if Status_Value /= Ok then
            return Status_Value;
         elsif Object_Kind /= Pack_Tag or else Tag_Last < Tag_Data'First then
            Tag_Last := Tag_Data'First - 1;
            return Invalid_Command;
         end if;

         Status_Value :=
           Parse_Tag_Target
             (Tag_Data (Tag_Data'First .. Tag_Last),
              Target_ID,
              Target_Last,
              Target_Kind);
         if Status_Value /= Ok then
            return Status_Value;
         elsif Target_Last /= Target_ID'Last then
            return Invalid_Command;
         end if;

         case Target_Kind is
            when Pack_Commit =>
               Peeled_Commit_Hex
                 (Peeled_Commit_Hex'First
                  .. Peeled_Commit_Hex'First
                     + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                     - 1) := Target_ID;
               Peeled_Commit_Last :=
                 Peeled_Commit_Hex'First
                 + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                 - 1;
               return
                 Read_Commit_Tree_Object
                   (Repository_Root,
                    Peeled_Commit_Hex
                      (Peeled_Commit_Hex'First .. Peeled_Commit_Last),
                    Pack_Checksums_Hex,
                    Pack_Data,
                    Index_Data,
                    Pack_Checksum_Hex,
                    Pack_Checksum_Last,
                    Commit_Data,
                    Commit_Last,
                    Root_Tree_ID_Hex,
                    Root_Tree_ID_Last,
                    Tree_Data,
                    Tree_Last,
                    Entry_Count);
            when Pack_Tag =>
               Current_ID := Target_ID;
            when others =>
               return Invalid_Command;
         end case;
      end loop;

      return Invalid_Command;
   exception
      when Constraint_Error =>
         Resolved_ID_Last := Resolved_ID_Hex'First - 1;
         Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         Tag_Last := Tag_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Entry_Count := 0;
         return Invalid_Command;
      when others =>
         Resolved_ID_Last := Resolved_ID_Hex'First - 1;
         Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         Tag_Last := Tag_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Entry_Count := 0;
         return Read_Failed;
   end Read_Ref_Commitish_Tree_Object;

   function Read_Ref_Commitish_Tree_Entries_Hex
     (Repository_Root     : String;
      Ref_Name            : String;
      Resolved_ID_Hex     : out Stream_Element_Array;
      Resolved_ID_Last    : out Stream_Element_Offset;
      Peeled_Commit_Hex   : out Stream_Element_Array;
      Peeled_Commit_Last  : out Stream_Element_Offset;
      Pack_Checksums_Hex  : out Stream_Element_Array;
      Pack_Data           : out Stream_Element_Array;
      Index_Data          : out Stream_Element_Array;
      Pack_Checksum_Hex   : out Stream_Element_Array;
      Pack_Checksum_Last  : out Stream_Element_Offset;
      Tag_Data            : out Stream_Element_Array;
      Tag_Last            : out Stream_Element_Offset;
      Commit_Data         : out Stream_Element_Array;
      Commit_Last         : out Stream_Element_Offset;
      Root_Tree_ID_Hex    : out Stream_Element_Array;
      Root_Tree_ID_Last   : out Stream_Element_Offset;
      Tree_Data           : out Stream_Element_Array;
      Tree_Last           : out Stream_Element_Offset;
      Names               : out Stream_Element_Array;
      Name_Lasts          : out Tree_Entry_Name_Last_Array;
      Modes               : out Tree_Entry_Mode_Array;
      Object_IDs_Hex      : out Object_ID_Hex_Array;
      Count               : out Natural)
      return Status
   is
      Status_Value : Status;
      Tree_Count   : Natural := 0;
   begin
      Count := 0;
      Status_Value :=
        Read_Ref_Commitish_Tree_Object
          (Repository_Root,
           Ref_Name,
           Resolved_ID_Hex,
           Resolved_ID_Last,
           Peeled_Commit_Hex,
           Peeled_Commit_Last,
           Pack_Checksums_Hex,
           Pack_Data,
           Index_Data,
           Pack_Checksum_Hex,
           Pack_Checksum_Last,
           Tag_Data,
           Tag_Last,
           Commit_Data,
           Commit_Last,
           Root_Tree_ID_Hex,
           Root_Tree_ID_Last,
           Tree_Data,
           Tree_Last,
           Tree_Count);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Tree_Last < Tree_Data'First then
         Count := 0;
         return Ok;
      end if;

      Status_Value :=
        List_Tree_Entries_Hex
          (Tree_Data (Tree_Data'First .. Tree_Last),
           Names,
           Name_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
      if Status_Value /= Ok then
         Count := 0;
      elsif Count /= Tree_Count then
         Count := 0;
         return Internal_Error;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Resolved_ID_Last := Resolved_ID_Hex'First - 1;
         Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         Tag_Last := Tag_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Count := 0;
         return Invalid_Command;
      when others =>
         Resolved_ID_Last := Resolved_ID_Hex'First - 1;
         Peeled_Commit_Last := Peeled_Commit_Hex'First - 1;
         Pack_Checksum_Last := Pack_Checksum_Hex'First - 1;
         Tag_Last := Tag_Data'First - 1;
         Commit_Last := Commit_Data'First - 1;
         Root_Tree_ID_Last := Root_Tree_ID_Hex'First - 1;
         Tree_Last := Tree_Data'First - 1;
         Count := 0;
         return Read_Failed;
   end Read_Ref_Commitish_Tree_Entries_Hex;

   function List_Ref_Commitish_Tree_Paths_Hex
     (Repository_Root : String;
      Ref_Name        : String;
      Paths           : out Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return Status
   is
      Current_ID_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Current_ID_Last : Stream_Element_Offset;
      Object_Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Worktree_File_Length));
      Object_Last : Stream_Element_Offset;
      Scratch : Tree_Traversal_Scratch_Access := null;
      Pack_Checksum_Last : Stream_Element_Offset;
      Object_Kind : Pack_Object_Kind := Pack_Blob;
      Root_Tree_ID_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Root_Tree_ID_Last : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Count := 0;
      Scratch := new Tree_Traversal_Scratch;
      Status_Value := Resolve_Ref (Repository_Root, Ref_Name, Current_ID_Hex, Current_ID_Last);
      if Status_Value /= Ok then
         Free_Tree_Traversal_Scratch (Scratch);
         return Status_Value;
      elsif Current_ID_Last /= Current_ID_Hex'Last then
         Free_Tree_Traversal_Scratch (Scratch);
         return Invalid_Command;
      end if;

      for Depth in 1 .. Maximum_Ref_Resolution_Depth loop
         Status_Value :=
           Read_Any_Stored_Object_Resolved_Validated
             (Repository_Root,
              Current_ID_Hex,
              Scratch.Pack_Checksums_Hex,
              Scratch.Pack_Data,
              Scratch.Index_Data,
              Scratch.Base_Data,
              Scratch.Delta_Data,
              Scratch.Workspace,
              Scratch.Pack_Checksum_Hex,
              Pack_Checksum_Last,
              Object_Kind,
              Object_Data,
              Object_Last);
         if Status_Value /= Ok then
            Count := 0;
            Free_Tree_Traversal_Scratch (Scratch);
            return Status_Value;
         elsif Object_Last < Object_Data'First then
            Count := 0;
            Free_Tree_Traversal_Scratch (Scratch);
            return Invalid_Command;
         end if;

         case Object_Kind is
            when Pack_Commit =>
               Status_Value :=
                 Parse_Commit_Tree_ID
                   (Object_Data (Object_Data'First .. Object_Last),
                    Root_Tree_ID_Hex,
                    Root_Tree_ID_Last);
               if Status_Value /= Ok then
                  Count := 0;
                  Free_Tree_Traversal_Scratch (Scratch);
                  return Status_Value;
               elsif Root_Tree_ID_Last /= Root_Tree_ID_Hex'Last then
                  Count := 0;
                  Free_Tree_Traversal_Scratch (Scratch);
                  return Invalid_Command;
               end if;

               Free_Tree_Traversal_Scratch (Scratch);
               return
                 List_Tree_Paths_Hex
                   (Repository_Root,
                    Root_Tree_ID_Hex,
                    Paths,
                    Path_Lasts,
                    Modes,
                    Object_IDs_Hex,
                    Count);
            when Pack_Tag =>
               Status_Value :=
                 Parse_Tag_Target
                   (Object_Data (Object_Data'First .. Object_Last),
                    Current_ID_Hex,
                    Current_ID_Last,
                    Object_Kind);
               if Status_Value /= Ok then
                  Count := 0;
                  Free_Tree_Traversal_Scratch (Scratch);
                  return Status_Value;
               elsif Current_ID_Last /= Current_ID_Hex'Last then
                  Count := 0;
                  Free_Tree_Traversal_Scratch (Scratch);
                  return Invalid_Command;
               end if;
            when others =>
               Count := 0;
               Free_Tree_Traversal_Scratch (Scratch);
               return Invalid_Command;
         end case;
      end loop;

      Count := 0;
      Free_Tree_Traversal_Scratch (Scratch);
      return Unsupported_Feature;
   exception
      when Constraint_Error =>
         if Scratch /= null then
            Free_Tree_Traversal_Scratch (Scratch);
         end if;
         Count := 0;
         return Invalid_Command;
      when others =>
         if Scratch /= null then
            Free_Tree_Traversal_Scratch (Scratch);
         end if;
         Count := 0;
         return Read_Failed;
   end List_Ref_Commitish_Tree_Paths_Hex;

   function List_Ref_Commitish_Tree_Paths_Matching_Hex
     (Repository_Root : String;
      Ref_Name        : String;
      Pathspec        : String;
      Paths           : out Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return Status
   is
      Status_Value : Status;
   begin
      Status_Value :=
        List_Ref_Commitish_Tree_Paths_Hex
          (Repository_Root,
           Ref_Name,
           Paths,
           Path_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return
        Filter_Tree_Paths_By_Pathspec
          (Pathspec, Paths, Path_Lasts, Modes, Object_IDs_Hex, Count);
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Read_Failed;
   end List_Ref_Commitish_Tree_Paths_Matching_Hex;

   function List_HEAD_Tree_Paths_Hex
     (Repository_Root : String;
      Paths           : out Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return Status
   is
   begin
      return
        List_Ref_Commitish_Tree_Paths_Hex
          (Repository_Root,
           "HEAD",
           Paths,
           Path_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Read_Failed;
   end List_HEAD_Tree_Paths_Hex;

   function List_HEAD_Tree_Paths_Matching_Hex
     (Repository_Root : String;
      Pathspec        : String;
      Paths           : out Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return Status
   is
   begin
      return
        List_Ref_Commitish_Tree_Paths_Matching_Hex
          (Repository_Root,
           "HEAD",
           Pathspec,
           Paths,
           Path_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Read_Failed;
   end List_HEAD_Tree_Paths_Matching_Hex;

   function List_Branch_Tree_Paths_Hex
     (Repository_Root : String;
      Branch_Name     : String;
      Paths           : out Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return Status
   is
      Ref_Name : constant String := "refs/heads/" & Branch_Name;
   begin
      if not Valid_Ref_Name (Ref_Name) then
         Count := 0;
         return Invalid_Command;
      end if;

      return
        List_Ref_Commitish_Tree_Paths_Hex
          (Repository_Root,
           Ref_Name,
           Paths,
           Path_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Read_Failed;
   end List_Branch_Tree_Paths_Hex;

   function List_Branch_Tree_Paths_Matching_Hex
     (Repository_Root : String;
      Branch_Name     : String;
      Pathspec        : String;
      Paths           : out Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return Status
   is
      Ref_Name : constant String := "refs/heads/" & Branch_Name;
   begin
      if not Valid_Ref_Name (Ref_Name) then
         Count := 0;
         return Invalid_Command;
      end if;

      return
        List_Ref_Commitish_Tree_Paths_Matching_Hex
          (Repository_Root,
           Ref_Name,
           Pathspec,
           Paths,
           Path_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Read_Failed;
   end List_Branch_Tree_Paths_Matching_Hex;

   function List_Tag_Tree_Paths_Hex
     (Repository_Root : String;
      Tag_Name        : String;
      Paths           : out Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return Status
   is
      Ref_Name : constant String := "refs/tags/" & Tag_Name;
   begin
      if not Valid_Ref_Name (Ref_Name) then
         Count := 0;
         return Invalid_Command;
      end if;

      return
        List_Ref_Commitish_Tree_Paths_Hex
          (Repository_Root,
           Ref_Name,
           Paths,
           Path_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Read_Failed;
   end List_Tag_Tree_Paths_Hex;

   function List_Tag_Tree_Paths_Matching_Hex
     (Repository_Root : String;
      Tag_Name        : String;
      Pathspec        : String;
      Paths           : out Stream_Element_Array;
      Path_Lasts      : out Index_Path_Last_Array;
      Modes           : out Tree_Entry_Mode_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return Status
   is
      Ref_Name : constant String := "refs/tags/" & Tag_Name;
   begin
      if not Valid_Ref_Name (Ref_Name) then
         Count := 0;
         return Invalid_Command;
      end if;

      return
        List_Ref_Commitish_Tree_Paths_Matching_Hex
          (Repository_Root,
           Ref_Name,
           Pathspec,
           Paths,
           Path_Lasts,
           Modes,
           Object_IDs_Hex,
           Count);
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Read_Failed;
   end List_Tag_Tree_Paths_Matching_Hex;

   function Ref_File_Path
     (Repository_Root : String;
      Ref_Name        : String)
      return String
   is
   begin
      if Ref_Name = "HEAD" then
         return Git_Path (Repository_Root, "HEAD");
      else
         return Git_Path (Repository_Root, Ref_Name);
      end if;
   end Ref_File_Path;

   function Packed_Refs_Path (Repository_Root : String) return String is
   begin
      return Git_Path (Repository_Root, "packed-refs");
   end Packed_Refs_Path;

   function Reflog_File_Path
     (Repository_Root : String;
      Ref_Name        : String)
      return String
   is
   begin
      if Ref_Name = "HEAD" then
         return Git_Path (Repository_Root, "logs/HEAD");
      else
         return Git_Path (Repository_Root, "logs/" & Ref_Name);
      end if;
   end Reflog_File_Path;

   function Packable_Ref_Name (Ref_Name : String) return Boolean is
   begin
      return Ref_Name /= "HEAD" and then Valid_Ref_Name (Ref_Name);
   end Packable_Ref_Name;

   function Write_Direct_Ref
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : Stream_Element_Array)
      return Status
   is
      Raw_ID       : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last     : Stream_Element_Offset;
      Status_Value : Status;
      File         : Stream_IO.File_Type;
      Data         : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length + 1));
      Path         : constant String := Ref_File_Path (Repository_Root, Ref_Name);
   begin
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Ref_Name (Ref_Name)
      then
         return Invalid_Command;
      end if;
      Status_Value := Parse_Object_ID_Hex (Object_ID_Hex, Raw_ID, Raw_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      for Index in 0 .. Object_ID_SHA1_Hex_Length - 1 loop
         Data (Data'First + Stream_Element_Offset (Index)) :=
           Object_ID_Hex (Object_ID_Hex'First + Stream_Element_Offset (Index));
      end loop;
      Data (Data'Last) := Stream_Element (Character'Pos (Character'Val (10)));
      if Ref_Name /= "HEAD" then
         Ada.Directories.Create_Path (Ada.Directories.Containing_Directory (Path));
      end if;
      Stream_IO.Create (File, Stream_IO.Out_File, Path);
      Stream_IO.Write (File, Data);
      Stream_IO.Close (File);
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Write_Failed;
   end Write_Direct_Ref;

   function Read_Direct_Ref
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
      File      : Stream_IO.File_Type;
      Data      : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length + 1));
      File_Last : Stream_Element_Offset;
      Raw_ID    : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last  : Stream_Element_Offset;
      Path      : constant String := Ref_File_Path (Repository_Root, Ref_Name);
   begin
      Last := Object_ID_Hex'First - 1;
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Ref_Name (Ref_Name)
      then
         return Invalid_Command;
      elsif Object_ID_Hex'Length
        < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Read_Failed;
      end if;

      Stream_IO.Open (File, Stream_IO.In_File, Path);
      Stream_IO.Read (File, Data, File_Last);
      Stream_IO.Close (File);
      if File_Last /= Data'Last
        or else Data (Data'Last) /=
          Stream_Element (Character'Pos (Character'Val (10)))
      then
         return Invalid_Command;
      end if;
      if Parse_Object_ID_Hex
        (Data
           (Data'First
            .. Data'First
               + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
               - 1),
         Raw_ID,
         Raw_Last) /= Ok
      then
         return Invalid_Command;
      end if;
      Object_ID_Hex
        (Object_ID_Hex'First
         .. Object_ID_Hex'First
            + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
            - 1) :=
           Data
             (Data'First
              .. Data'First
                 + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                 - 1);
      Last :=
        Object_ID_Hex'First
        + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
        - 1;
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Last := Object_ID_Hex'First - 1;
         return Read_Failed;
   end Read_Direct_Ref;

   function Delete_Direct_Ref
     (Repository_Root : String;
      Ref_Name        : String)
      return Status
   is
      use type Ada.Directories.File_Kind;
      Path : constant String := Ref_File_Path (Repository_Root, Ref_Name);
   begin
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Ref_Name (Ref_Name)
      then
         return Invalid_Command;
      elsif not Ada.Directories.Exists (Path) then
         return Read_Failed;
      elsif Ada.Directories.Kind (Path) /= Ada.Directories.Ordinary_File then
         return Invalid_Command;
      end if;

      Ada.Directories.Delete_File (Path);
      return Ok;
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Delete_Direct_Ref;

   function Write_Symbolic_Ref
     (Repository_Root  : String;
      Ref_Name         : String;
      Target_Ref_Name  : String)
      return Status
   is
      File : Stream_IO.File_Type;
      Prefix : constant String := "ref: ";
      Data : Stream_Element_Array
        (1 .. Stream_Element_Offset (Target_Ref_Name'Length + 6));
      Path : constant String := Ref_File_Path (Repository_Root, Ref_Name);
      Cursor : Stream_Element_Offset := Data'First;
   begin
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Ref_Name (Ref_Name)
        or else not Valid_Ref_Name (Target_Ref_Name)
      then
         return Invalid_Command;
      end if;

      for Index in Prefix'Range loop
         Data (Cursor) := Stream_Element (Character'Pos (Prefix (Index)));
         Cursor := Cursor + 1;
      end loop;
      for Ch of Target_Ref_Name loop
         Data (Cursor) := Stream_Element (Character'Pos (Ch));
         Cursor := Cursor + 1;
      end loop;
      Data (Cursor) := Stream_Element (Character'Pos (Character'Val (10)));

      if Ref_Name /= "HEAD" then
         Ada.Directories.Create_Path (Ada.Directories.Containing_Directory (Path));
      end if;
      Stream_IO.Create (File, Stream_IO.Out_File, Path);
      Stream_IO.Write (File, Data);
      Stream_IO.Close (File);
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Write_Failed;
   end Write_Symbolic_Ref;

   function Read_Symbolic_Ref
     (Repository_Root  : String;
      Ref_Name         : String;
      Target_Ref_Name  : out Stream_Element_Array;
      Last             : out Stream_Element_Offset)
      return Status
   is
      File      : Stream_IO.File_Type;
      File_Size : Stream_IO.Count;
      Path      : constant String := Ref_File_Path (Repository_Root, Ref_Name);
      Prefix    : constant String := "ref: ";
   begin
      Last := Target_Ref_Name'First - 1;
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Ref_Name (Ref_Name)
      then
         return Invalid_Command;
      end if;

      Stream_IO.Open (File, Stream_IO.In_File, Path);
      File_Size := Stream_IO.Size (File);
      if File_Size <= Stream_IO.Count (Prefix'Length + 1)
        or else File_Size >
          Stream_IO.Count (Maximum_Ref_Name_Length + Prefix'Length + 1)
      then
         Stream_IO.Close (File);
         return Invalid_Command;
      end if;

      declare
         Data      : Stream_Element_Array
           (1 .. Stream_Element_Offset (File_Size));
         File_Last : Stream_Element_Offset;
         Target_First : constant Stream_Element_Offset :=
           Data'First + Stream_Element_Offset (Prefix'Length);
         Target_Last : constant Stream_Element_Offset := Data'Last - 1;
         Target_Length : constant Natural :=
           Natural (Target_Last - Target_First + 1);
      begin
         Stream_IO.Read (File, Data, File_Last);
         Stream_IO.Close (File);
         if File_Last /= Data'Last
           or else Data (Data'Last) /=
             Stream_Element (Character'Pos (Character'Val (10)))
         then
            return Invalid_Command;
         end if;
         for Index in Prefix'Range loop
            if Data
              (Data'First + Stream_Element_Offset (Index - Prefix'First))
              /= Stream_Element (Character'Pos (Prefix (Index)))
            then
               return Invalid_Command;
            end if;
         end loop;
         if Target_Length = 0
           or else Target_Ref_Name'Length < Stream_Element_Offset (Target_Length)
         then
            return Read_Failed;
         end if;

         declare
            Text : String (1 .. Target_Length);
         begin
            for Index in Text'Range loop
               Text (Index) :=
                 Character'Val
                   (Data
                      (Target_First + Stream_Element_Offset (Index - 1)));
            end loop;
            if not Valid_Ref_Name (Text) then
               return Invalid_Command;
            end if;
         end;

         Target_Ref_Name
           (Target_Ref_Name'First
            .. Target_Ref_Name'First + Stream_Element_Offset (Target_Length) - 1) :=
              Data (Target_First .. Target_Last);
         Last :=
           Target_Ref_Name'First + Stream_Element_Offset (Target_Length) - 1;
      end;

      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Last := Target_Ref_Name'First - 1;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Last := Target_Ref_Name'First - 1;
         return Read_Failed;
   end Read_Symbolic_Ref;

   function Delete_Symbolic_Ref
     (Repository_Root  : String;
      Ref_Name         : String;
      Target_Ref_Name  : out Stream_Element_Array;
      Last             : out Stream_Element_Offset)
      return Status
   is
      Status_Value : Status;
   begin
      Last := Target_Ref_Name'First - 1;
      Status_Value :=
        Read_Symbolic_Ref
          (Repository_Root, Ref_Name, Target_Ref_Name, Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value := Delete_Direct_Ref (Repository_Root, Ref_Name);
      if Status_Value /= Ok then
         Last := Target_Ref_Name'First - 1;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Last := Target_Ref_Name'First - 1;
         return Invalid_Command;
      when others =>
         Last := Target_Ref_Name'First - 1;
         return Write_Failed;
   end Delete_Symbolic_Ref;

   function Write_Packed_Ref
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : Stream_Element_Array)
      return Status
   is
      Raw_ID       : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last     : Stream_Element_Offset;
      Status_Value : Status;
      File         : Stream_IO.File_Type;
      Path         : constant String := Packed_Refs_Path (Repository_Root);
      Output       : Unbounded_String;
      Found        : Boolean := False;

      function Packed_Line return String is
         Result : String (1 .. Object_ID_SHA1_Hex_Length + 1 + Ref_Name'Length);
      begin
         for Index in 0 .. Object_ID_SHA1_Hex_Length - 1 loop
            Result (Result'First + Index) :=
              Character'Val
                (Object_ID_Hex
                   (Object_ID_Hex'First + Stream_Element_Offset (Index)));
         end loop;
         Result (Result'First + Object_ID_SHA1_Hex_Length) := ' ';
         Result
           (Result'First + Object_ID_SHA1_Hex_Length + 1 .. Result'Last) :=
             Ref_Name;
         return Result;
      end Packed_Line;

      procedure Append_Line (Line : String) is
      begin
         Append (Output, Line);
         Append (Output, Character'Val (10));
      end Append_Line;

      procedure Validate_Existing_Line
        (Line      : String;
         Line_Ref  : out Unbounded_String;
         Is_Direct : out Boolean;
         Status_Value : out Status)
      is
         Existing_Raw  : Stream_Element_Array
           (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
         Existing_Last : Stream_Element_Offset;
         Existing_Hex  : Stream_Element_Array
           (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      begin
         Line_Ref := Null_Unbounded_String;
         Is_Direct := False;
         Status_Value := Ok;
         if Line'Length = 0
           or else Line (Line'First) = '#'
           or else Line (Line'First) = '^'
         then
            return;
         elsif Line'Length < Object_ID_SHA1_Hex_Length + 2
           or else Line (Line'First + Object_ID_SHA1_Hex_Length) /= ' '
         then
            Status_Value := Invalid_Command;
            return;
         end if;

         for Index in Existing_Hex'Range loop
            Existing_Hex (Index) :=
              Stream_Element
                (Character'Pos
                   (Line
                      (Line'First + Natural (Index - Existing_Hex'First))));
         end loop;
         if Parse_Object_ID_Hex
           (Existing_Hex, Existing_Raw, Existing_Last) /= Ok
         then
            Status_Value := Invalid_Command;
            return;
         end if;

         declare
            Existing_Ref : constant String :=
              Line
                (Line'First + Object_ID_SHA1_Hex_Length + 1 .. Line'Last);
         begin
            if not Packable_Ref_Name (Existing_Ref) then
               Status_Value := Invalid_Command;
               return;
            end if;
            Line_Ref := To_Unbounded_String (Existing_Ref);
            Is_Direct := True;
         end;
      end Validate_Existing_Line;
   begin
      if not Valid_Repository_Root (Repository_Root)
        or else not Packable_Ref_Name (Ref_Name)
      then
         return Invalid_Command;
      end if;
      Status_Value := Parse_Object_ID_Hex (Object_ID_Hex, Raw_ID, Raw_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Ada.Directories.Exists (Path) then
         Stream_IO.Open (File, Stream_IO.In_File, Path);
         if Stream_IO.Size (File) > Maximum_Packed_Refs_File_Length then
            Stream_IO.Close (File);
            return Unsupported_Feature;
         end if;

         declare
            Data : Stream_Element_Array
              (1 .. Stream_Element_Offset (Stream_IO.Size (File)));
            Data_Last : Stream_Element_Offset;
            Cursor    : Stream_Element_Offset := Data'First;
            Skip_Peeled : Boolean := False;
         begin
            Stream_IO.Read (File, Data, Data_Last);
            Stream_IO.Close (File);
            if Data_Last /= Data'Last then
               return Read_Failed;
            end if;

            while Cursor <= Data'Last loop
               declare
                  Line_Start : constant Stream_Element_Offset := Cursor;
                  Line_End   : Stream_Element_Offset := Cursor - 1;
               begin
                  while Cursor <= Data'Last
                    and then Data (Cursor) /=
                      Stream_Element (Character'Pos (Character'Val (10)))
                  loop
                     Line_End := Cursor;
                     Cursor := Cursor + 1;
                  end loop;
                  if Cursor > Data'Last then
                     return Invalid_Command;
                  end if;
                  Cursor := Cursor + 1;

                  declare
                     Line : String
                       (1 .. Natural (Line_End - Line_Start + 1));
                     Line_Ref : Unbounded_String;
                     Is_Direct : Boolean;
                  begin
                     for Index in Line'Range loop
                        Line (Index) :=
                          Character'Val
                            (Data
                               (Line_Start
                                + Stream_Element_Offset (Index - 1)));
                     end loop;

                     if Skip_Peeled
                       and then Line'Length > 0
                       and then Line (Line'First) = '^'
                     then
                        Skip_Peeled := False;
                     else
                        Validate_Existing_Line
                          (Line, Line_Ref, Is_Direct, Status_Value);
                        if Status_Value /= Ok then
                           return Status_Value;
                        end if;
                        if Is_Direct and then To_String (Line_Ref) = Ref_Name then
                           Append_Line (Packed_Line);
                           Found := True;
                           Skip_Peeled := True;
                        else
                           Append_Line (Line);
                           Skip_Peeled := False;
                        end if;
                     end if;
                  end;
               end;
            end loop;
         end;
      else
         Append_Line ("# pack-refs with: peeled fully-peeled sorted");
      end if;

      if not Found then
         Append_Line (Packed_Line);
      end if;

      declare
         Text : constant String := To_String (Output);
         Data : Stream_Element_Array (1 .. Stream_Element_Offset (Text'Length));
      begin
         for Index in Text'Range loop
            Data (Stream_Element_Offset (Index - Text'First + 1)) :=
              Stream_Element (Character'Pos (Text (Index)));
         end loop;
         Stream_IO.Create (File, Stream_IO.Out_File, Path);
         Stream_IO.Write (File, Data);
         Stream_IO.Close (File);
      end;

      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Write_Failed;
   end Write_Packed_Ref;

   function Read_Packed_Ref
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
      File : Stream_IO.File_Type;
      Path : constant String := Packed_Refs_Path (Repository_Root);
   begin
      Last := Object_ID_Hex'First - 1;
      if not Valid_Repository_Root (Repository_Root)
        or else not Packable_Ref_Name (Ref_Name)
      then
         return Invalid_Command;
      elsif Object_ID_Hex'Length
        < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Read_Failed;
      end if;

      Stream_IO.Open (File, Stream_IO.In_File, Path);
      if Stream_IO.Size (File) > Maximum_Packed_Refs_File_Length then
         Stream_IO.Close (File);
         return Unsupported_Feature;
      elsif Stream_IO.Size (File) = 0 then
         Stream_IO.Close (File);
         return Read_Failed;
      end if;

      declare
         Data : Stream_Element_Array
           (1 .. Stream_Element_Offset (Stream_IO.Size (File)));
         Data_Last : Stream_Element_Offset;
         Cursor    : Stream_Element_Offset := Data'First;
         Raw_ID    : Stream_Element_Array
           (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
         Raw_Last  : Stream_Element_Offset;
      begin
         Stream_IO.Read (File, Data, Data_Last);
         Stream_IO.Close (File);
         if Data_Last /= Data'Last then
            return Read_Failed;
         end if;

         while Cursor <= Data'Last loop
            declare
               Line_Start : constant Stream_Element_Offset := Cursor;
               Line_End   : Stream_Element_Offset := Cursor - 1;
            begin
               while Cursor <= Data'Last
                 and then Data (Cursor) /=
                   Stream_Element (Character'Pos (Character'Val (10)))
               loop
                  Line_End := Cursor;
                  Cursor := Cursor + 1;
               end loop;
               if Cursor > Data'Last then
                  return Invalid_Command;
               end if;
               Cursor := Cursor + 1;

               declare
                  Line_Length : constant Natural :=
                    Natural (Line_End - Line_Start + 1);
               begin
                  if Line_Length = 0
                    or else Data (Line_Start) = Stream_Element (Character'Pos ('#'))
                    or else Data (Line_Start) = Stream_Element (Character'Pos ('^'))
                  then
                     null;
                  elsif Line_Length < Object_ID_SHA1_Hex_Length + 2
                    or else Data
                      (Line_Start
                       + Stream_Element_Offset (Object_ID_SHA1_Hex_Length))
                      /= Stream_Element (Character'Pos (' '))
                  then
                     return Invalid_Command;
                  else
                     declare
                        Existing_Ref_Length : constant Natural :=
                          Line_Length - Object_ID_SHA1_Hex_Length - 1;
                        Existing_Ref : String (1 .. Existing_Ref_Length);
                        Existing_Hex : Stream_Element_Array
                          (1 .. Stream_Element_Offset
                            (Object_ID_SHA1_Hex_Length));
                     begin
                        for Index in Existing_Hex'Range loop
                           Existing_Hex (Index) :=
                             Data
                               (Line_Start
                                + Stream_Element_Offset
                                  (Index - Existing_Hex'First));
                        end loop;
                        if Parse_Object_ID_Hex
                          (Existing_Hex, Raw_ID, Raw_Last) /= Ok
                        then
                           return Invalid_Command;
                        end if;
                        for Index in Existing_Ref'Range loop
                           Existing_Ref (Index) :=
                             Character'Val
                               (Data
                                  (Line_Start
                                   + Stream_Element_Offset
                                     (Object_ID_SHA1_Hex_Length + Index)));
                        end loop;
                        if not Packable_Ref_Name (Existing_Ref) then
                           return Invalid_Command;
                        elsif Existing_Ref = Ref_Name then
                           Object_ID_Hex
                             (Object_ID_Hex'First
                              .. Object_ID_Hex'First
                                 + Stream_Element_Offset
                                   (Object_ID_SHA1_Hex_Length)
                                 - 1) := Existing_Hex;
                           Last :=
                             Object_ID_Hex'First
                             + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                             - 1;
                           return Ok;
                        end if;
                     end;
                  end if;
               end;
            end;
         end loop;
      end;

      return Read_Failed;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Last := Object_ID_Hex'First - 1;
         return Read_Failed;
   end Read_Packed_Ref;

   function Delete_Packed_Ref
     (Repository_Root : String;
      Ref_Name        : String)
      return Status
   is
      File         : Stream_IO.File_Type;
      Path         : constant String := Packed_Refs_Path (Repository_Root);
      Output       : Unbounded_String;
      Found        : Boolean := False;
      Status_Value : Status := Ok;

      procedure Append_Line (Line : String) is
      begin
         Append (Output, Line);
         Append (Output, Character'Val (10));
      end Append_Line;

      procedure Validate_Existing_Line
        (Line         : String;
         Existing_Ref : out Unbounded_String;
         Is_Direct    : out Boolean;
         Status_Value : out Status)
      is
         Existing_Raw  : Stream_Element_Array
           (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
         Existing_Last : Stream_Element_Offset;
         Existing_Hex  : Stream_Element_Array
           (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      begin
         Existing_Ref := Null_Unbounded_String;
         Is_Direct := False;
         Status_Value := Ok;
         if Line'Length = 0
           or else Line (Line'First) = '#'
           or else Line (Line'First) = '^'
         then
            return;
         elsif Line'Length < Object_ID_SHA1_Hex_Length + 2
           or else Line (Line'First + Object_ID_SHA1_Hex_Length) /= ' '
         then
            Status_Value := Invalid_Command;
            return;
         end if;

         for Index in Existing_Hex'Range loop
            Existing_Hex (Index) :=
              Stream_Element
                (Character'Pos
                   (Line
                      (Line'First + Natural (Index - Existing_Hex'First))));
         end loop;
         if Parse_Object_ID_Hex
           (Existing_Hex, Existing_Raw, Existing_Last) /= Ok
         then
            Status_Value := Invalid_Command;
            return;
         end if;

         declare
            Ref_Text : constant String :=
              Line
                (Line'First + Object_ID_SHA1_Hex_Length + 1 .. Line'Last);
         begin
            if not Packable_Ref_Name (Ref_Text) then
               Status_Value := Invalid_Command;
               return;
            end if;
            Existing_Ref := To_Unbounded_String (Ref_Text);
            Is_Direct := True;
         end;
      end Validate_Existing_Line;
   begin
      if not Valid_Repository_Root (Repository_Root)
        or else not Packable_Ref_Name (Ref_Name)
      then
         return Invalid_Command;
      elsif not Ada.Directories.Exists (Path) then
         return Read_Failed;
      end if;

      Stream_IO.Open (File, Stream_IO.In_File, Path);
      if Stream_IO.Size (File) > Maximum_Packed_Refs_File_Length then
         Stream_IO.Close (File);
         return Unsupported_Feature;
      end if;

      declare
         Data : Stream_Element_Array
           (1 .. Stream_Element_Offset (Stream_IO.Size (File)));
         Data_Last : Stream_Element_Offset;
         Cursor    : Stream_Element_Offset := Data'First;
         Skip_Peeled : Boolean := False;
      begin
         Stream_IO.Read (File, Data, Data_Last);
         Stream_IO.Close (File);
         if Data_Last /= Data'Last then
            return Read_Failed;
         end if;

         while Cursor <= Data'Last loop
            declare
               Line_Start : constant Stream_Element_Offset := Cursor;
               Line_End   : Stream_Element_Offset := Cursor - 1;
            begin
               while Cursor <= Data'Last
                 and then Data (Cursor) /=
                   Stream_Element (Character'Pos (Character'Val (10)))
               loop
                  Line_End := Cursor;
                  Cursor := Cursor + 1;
               end loop;
               if Cursor > Data'Last then
                  return Invalid_Command;
               end if;
               Cursor := Cursor + 1;

               declare
                  Line : String (1 .. Natural (Line_End - Line_Start + 1));
                  Existing_Ref : Unbounded_String;
                  Is_Direct : Boolean;
               begin
                  for Index in Line'Range loop
                     Line (Index) :=
                       Character'Val
                         (Data
                            (Line_Start + Stream_Element_Offset (Index - 1)));
                  end loop;

                  if Skip_Peeled
                    and then Line'Length > 0
                    and then Line (Line'First) = '^'
                  then
                     Skip_Peeled := False;
                  else
                     Validate_Existing_Line
                       (Line, Existing_Ref, Is_Direct, Status_Value);
                     if Status_Value /= Ok then
                        return Status_Value;
                     elsif Is_Direct and then To_String (Existing_Ref) = Ref_Name
                     then
                        Found := True;
                        Skip_Peeled := True;
                     else
                        Append_Line (Line);
                        Skip_Peeled := False;
                     end if;
                  end if;
               end;
            end;
         end loop;
      end;

      if not Found then
         return Read_Failed;
      end if;

      declare
         Text : constant String := To_String (Output);
      begin
         Stream_IO.Create (File, Stream_IO.Out_File, Path);
         if Text'Length > 0 then
            declare
               Data : Stream_Element_Array
                 (1 .. Stream_Element_Offset (Text'Length));
            begin
               for Index in Text'Range loop
                  Data (Stream_Element_Offset (Index - Text'First + 1)) :=
                    Stream_Element (Character'Pos (Text (Index)));
               end loop;
               Stream_IO.Write (File, Data);
            end;
         end if;
         Stream_IO.Close (File);
      end;

      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Write_Failed;
   end Delete_Packed_Ref;

   function List_Refs
     (Repository_Root : String;
      Names           : out Stream_Element_Array;
      Name_Lasts      : out Ref_Name_Last_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return Status
   is
      Names_Last : Stream_Element_Offset := Names'First - 1;
      Raw_ID     : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last   : Stream_Element_Offset;

      function Existing_Ref (Ref_Name : String) return Boolean is
         Start : Stream_Element_Offset := Names'First;
      begin
         for Index in 1 .. Count loop
            declare
               Stop : constant Stream_Element_Offset := Name_Lasts (Index);
            begin
               if Natural (Stop - Start + 1) = Ref_Name'Length then
                  declare
                     Matches : Boolean := True;
                  begin
                     for Offset in 0 .. Ref_Name'Length - 1 loop
                        if Names (Start + Stream_Element_Offset (Offset)) /=
                          Stream_Element
                            (Character'Pos
                               (Ref_Name (Ref_Name'First + Offset)))
                        then
                           Matches := False;
                           exit;
                        end if;
                     end loop;
                     if Matches then
                        return True;
                     end if;
                  end;
               end if;
               Start := Stop + 1;
            end;
         end loop;
         return False;
      end Existing_Ref;

      procedure Append_Ref
        (Ref_Name     : String;
         Object_ID_Hex : Stream_Element_Array;
         Status_Value : out Status)
      is
      begin
         Status_Value := Ok;
         if not Packable_Ref_Name (Ref_Name) then
            Status_Value := Invalid_Command;
            return;
         elsif Existing_Ref (Ref_Name) then
            return;
         elsif Count >= Name_Lasts'Length
           or else Count >= Object_IDs_Hex'Length
           or else Names_Last + Stream_Element_Offset (Ref_Name'Length)
             > Names'Last
         then
            Status_Value := Read_Failed;
            return;
         elsif Object_ID_Hex'Length
           < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
         then
            Status_Value := Invalid_Command;
            return;
         end if;

         Status_Value := Parse_Object_ID_Hex (Object_ID_Hex, Raw_ID, Raw_Last);
         if Status_Value /= Ok then
            return;
         end if;

         Count := Count + 1;
         for Index in Ref_Name'Range loop
            Names_Last := Names_Last + 1;
            Names (Names_Last) :=
              Stream_Element (Character'Pos (Ref_Name (Index)));
         end loop;
         Name_Lasts (Count) := Names_Last;
         for Index in 0 .. Object_ID_SHA1_Hex_Length - 1 loop
            Object_IDs_Hex (Count) (Index + 1) :=
              Object_ID_Hex
                (Object_ID_Hex'First + Stream_Element_Offset (Index));
         end loop;
      exception
         when Constraint_Error =>
            Status_Value := Invalid_Command;
      end Append_Ref;

      procedure Scan_Loose_Directory
        (Directory_Path : String;
         Ref_Prefix     : String;
         Status_Value   : out Status)
      is
         Search : Ada.Directories.Search_Type;
      begin
         Status_Value := Ok;
         if not Ada.Directories.Exists (Directory_Path) then
            return;
         end if;

         Ada.Directories.Start_Search
           (Search,
            Directory_Path,
            "*",
            [Ada.Directories.Ordinary_File => True,
             Ada.Directories.Directory     => True,
             Ada.Directories.Special_File  => False]);
         while Ada.Directories.More_Entries (Search) loop
            declare
               Dir_Entry : Ada.Directories.Directory_Entry_Type;
            begin
               Ada.Directories.Get_Next_Entry (Search, Dir_Entry);
               declare
                  Simple : constant String :=
                    Ada.Directories.Simple_Name (Dir_Entry);
               begin
                  if Simple /= "." and then Simple /= ".." then
                     declare
                        Ref_Name : constant String := Ref_Prefix & "/" & Simple;
                     begin
                        case Ada.Directories.Kind (Dir_Entry) is
                           when Ada.Directories.Directory =>
                              Scan_Loose_Directory
                                (Ada.Directories.Full_Name (Dir_Entry),
                                 Ref_Name,
                                 Status_Value);
                              if Status_Value /= Ok then
                                 Ada.Directories.End_Search (Search);
                                 return;
                              end if;
                           when Ada.Directories.Ordinary_File =>
                              if Valid_Ref_Name (Ref_Name) then
                                 declare
                                    ID   : Stream_Element_Array
                                      (1 .. Stream_Element_Offset
                                        (Object_ID_SHA1_Hex_Length));
                                    Last : Stream_Element_Offset;
                                    Direct_Status : Status;
                                    Target : Stream_Element_Array
                                      (1 .. Stream_Element_Offset
                                        (Maximum_Ref_Name_Length));
                                    Target_Last : Stream_Element_Offset;
                                 begin
                                    Direct_Status :=
                                      Read_Direct_Ref
                                        (Repository_Root,
                                         Ref_Name,
                                         ID,
                                         Last);
                                    if Direct_Status = Ok then
                                       Append_Ref
                                         (Ref_Name, ID, Status_Value);
                                       if Status_Value /= Ok then
                                          Ada.Directories.End_Search (Search);
                                          return;
                                       end if;
                                    elsif Direct_Status = Invalid_Command
                                      and then Read_Symbolic_Ref
                                        (Repository_Root,
                                         Ref_Name,
                                         Target,
                                         Target_Last) = Ok
                                    then
                                       null;
                                    elsif Direct_Status /= Read_Failed then
                                       Status_Value := Direct_Status;
                                       Ada.Directories.End_Search (Search);
                                       return;
                                    end if;
                                 end;
                              end if;
                           when Ada.Directories.Special_File =>
                              null;
                        end case;
                     end;
                  end if;
               end;
            end;
         end loop;
         Ada.Directories.End_Search (Search);
      exception
         when Constraint_Error =>
            begin
               Ada.Directories.End_Search (Search);
            exception
               when others =>
                  null;
            end;
            Status_Value := Invalid_Command;
         when others =>
            begin
               Ada.Directories.End_Search (Search);
            exception
               when others =>
                  null;
            end;
            Status_Value := Read_Failed;
      end Scan_Loose_Directory;

      procedure Scan_Packed_Refs (Status_Value : out Status) is
         File : Stream_IO.File_Type;
         Path : constant String := Packed_Refs_Path (Repository_Root);
      begin
         Status_Value := Ok;
         if not Ada.Directories.Exists (Path) then
            return;
         end if;

         Stream_IO.Open (File, Stream_IO.In_File, Path);
         if Stream_IO.Size (File) > Maximum_Packed_Refs_File_Length then
            Stream_IO.Close (File);
            Status_Value := Unsupported_Feature;
            return;
         elsif Stream_IO.Size (File) = 0 then
            Stream_IO.Close (File);
            return;
         end if;

         declare
            Data : Stream_Element_Array
              (1 .. Stream_Element_Offset (Stream_IO.Size (File)));
            Data_Last : Stream_Element_Offset;
            Cursor    : Stream_Element_Offset := Data'First;
         begin
            Stream_IO.Read (File, Data, Data_Last);
            Stream_IO.Close (File);
            if Data_Last /= Data'Last then
               Status_Value := Read_Failed;
               return;
            end if;

            while Cursor <= Data'Last loop
               declare
                  Line_Start : constant Stream_Element_Offset := Cursor;
                  Line_End   : Stream_Element_Offset := Cursor - 1;
               begin
                  while Cursor <= Data'Last
                    and then Data (Cursor) /=
                      Stream_Element (Character'Pos (Character'Val (10)))
                  loop
                     Line_End := Cursor;
                     Cursor := Cursor + 1;
                  end loop;
                  if Cursor > Data'Last then
                     Status_Value := Invalid_Command;
                     return;
                  end if;
                  Cursor := Cursor + 1;

                  declare
                     Line_Length : constant Natural :=
                       Natural (Line_End - Line_Start + 1);
                  begin
                     if Line_Length = 0
                       or else Data (Line_Start) =
                         Stream_Element (Character'Pos ('#'))
                       or else Data (Line_Start) =
                         Stream_Element (Character'Pos ('^'))
                     then
                        null;
                     elsif Line_Length < Object_ID_SHA1_Hex_Length + 2
                       or else Data
                         (Line_Start
                          + Stream_Element_Offset
                            (Object_ID_SHA1_Hex_Length))
                         /= Stream_Element (Character'Pos (' '))
                     then
                        Status_Value := Invalid_Command;
                        return;
                     else
                        declare
                           Ref_Length : constant Natural :=
                             Line_Length - Object_ID_SHA1_Hex_Length - 1;
                           Ref_Name : String (1 .. Ref_Length);
                           ID : Stream_Element_Array
                             (1 .. Stream_Element_Offset
                               (Object_ID_SHA1_Hex_Length));
                        begin
                           for Index in ID'Range loop
                              ID (Index) :=
                                Data
                                  (Line_Start
                                   + Stream_Element_Offset
                                     (Index - ID'First));
                           end loop;
                           for Index in Ref_Name'Range loop
                              Ref_Name (Index) :=
                                Character'Val
                                  (Data
                                     (Line_Start
                                      + Stream_Element_Offset
                                        (Object_ID_SHA1_Hex_Length
                                         + Index)));
                           end loop;
                           Append_Ref (Ref_Name, ID, Status_Value);
                           if Status_Value /= Ok then
                              return;
                           end if;
                        end;
                     end if;
                  end;
               end;
            end loop;
         end;
      exception
         when Constraint_Error =>
            if Stream_IO.Is_Open (File) then
               Stream_IO.Close (File);
            end if;
            Status_Value := Invalid_Command;
         when others =>
            if Stream_IO.Is_Open (File) then
               Stream_IO.Close (File);
            end if;
            Status_Value := Read_Failed;
      end Scan_Packed_Refs;

      Status_Value : Status;
   begin
      Count := 0;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      Scan_Loose_Directory
        (Git_Path (Repository_Root, "refs"),
         "refs",
         Status_Value);
      if Status_Value /= Ok then
         Count := 0;
         return Status_Value;
      end if;

      Scan_Packed_Refs (Status_Value);
      if Status_Value /= Ok then
         Count := 0;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Read_Failed;
   end List_Refs;

   function List_Branches
     (Repository_Root : String;
      Names           : out Stream_Element_Array;
      Name_Lasts      : out Ref_Name_Last_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return Status
   is
      Prefix : constant String := "refs/heads/";
      Full_Count : Natural := 0;
      Read_Start : Stream_Element_Offset := Names'First;
      Write_Last : Stream_Element_Offset := Names'First - 1;
      Status_Value : Status;

      function Has_Prefix
        (Start : Stream_Element_Offset;
         Stop  : Stream_Element_Offset)
         return Boolean
      is
      begin
         if Natural (Stop - Start + 1) <= Prefix'Length then
            return False;
         end if;

         for Offset in 0 .. Prefix'Length - 1 loop
            if Names (Start + Stream_Element_Offset (Offset)) /=
              Stream_Element
                (Character'Pos (Prefix (Prefix'First + Offset)))
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when Constraint_Error =>
            return False;
      end Has_Prefix;
   begin
      Count := 0;
      Status_Value :=
        List_Refs
          (Repository_Root,
           Names,
           Name_Lasts,
           Object_IDs_Hex,
           Full_Count);
      if Status_Value /= Ok then
         Count := 0;
         return Status_Value;
      end if;

      for Index in 1 .. Full_Count loop
         declare
            Read_Stop : constant Stream_Element_Offset := Name_Lasts (Index);
         begin
            if Has_Prefix (Read_Start, Read_Stop) then
               Count := Count + 1;
               for Source in
                 Read_Start + Stream_Element_Offset (Prefix'Length)
                   .. Read_Stop
               loop
                  Write_Last := Write_Last + 1;
                  Names (Write_Last) := Names (Source);
               end loop;
               Name_Lasts (Count) := Write_Last;
               Object_IDs_Hex (Count) := Object_IDs_Hex (Index);
            end if;
            Read_Start := Read_Stop + 1;
         end;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Read_Failed;
   end List_Branches;

   function List_Tag_Refs
     (Repository_Root : String;
      Names           : out Stream_Element_Array;
      Name_Lasts      : out Ref_Name_Last_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return Status
   is
      Prefix : constant String := "refs/tags/";
      Full_Count : Natural := 0;
      Read_Start : Stream_Element_Offset := Names'First;
      Write_Last : Stream_Element_Offset := Names'First - 1;
      Status_Value : Status;

      function Has_Prefix
        (Start : Stream_Element_Offset;
         Stop  : Stream_Element_Offset)
         return Boolean
      is
      begin
         if Natural (Stop - Start + 1) <= Prefix'Length then
            return False;
         end if;

         for Offset in 0 .. Prefix'Length - 1 loop
            if Names (Start + Stream_Element_Offset (Offset)) /=
              Stream_Element
                (Character'Pos (Prefix (Prefix'First + Offset)))
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when Constraint_Error =>
            return False;
      end Has_Prefix;
   begin
      Count := 0;
      Status_Value :=
        List_Refs
          (Repository_Root,
           Names,
           Name_Lasts,
           Object_IDs_Hex,
           Full_Count);
      if Status_Value /= Ok then
         Count := 0;
         return Status_Value;
      end if;

      for Index in 1 .. Full_Count loop
         declare
            Read_Stop : constant Stream_Element_Offset := Name_Lasts (Index);
         begin
            if Has_Prefix (Read_Start, Read_Stop) then
               Count := Count + 1;
               for Source in
                 Read_Start + Stream_Element_Offset (Prefix'Length)
                   .. Read_Stop
               loop
                  Write_Last := Write_Last + 1;
                  Names (Write_Last) := Names (Source);
               end loop;
               Name_Lasts (Count) := Write_Last;
               Object_IDs_Hex (Count) := Object_IDs_Hex (Index);
            end if;
            Read_Start := Read_Stop + 1;
         end;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Read_Failed;
   end List_Tag_Refs;

   function List_Remote_Tracking_Branches
     (Repository_Root : String;
      Names           : out Stream_Element_Array;
      Name_Lasts      : out Ref_Name_Last_Array;
      Object_IDs_Hex  : out Object_ID_Hex_Array;
      Count           : out Natural)
      return Status
   is
      Prefix : constant String := "refs/remotes/";
      Full_Count : Natural := 0;
      Read_Start : Stream_Element_Offset := Names'First;
      Write_Last : Stream_Element_Offset := Names'First - 1;
      Status_Value : Status;

      function Has_Prefix
        (Start : Stream_Element_Offset;
         Stop  : Stream_Element_Offset)
         return Boolean
      is
      begin
         if Natural (Stop - Start + 1) <= Prefix'Length then
            return False;
         end if;

         for Offset in 0 .. Prefix'Length - 1 loop
            if Names (Start + Stream_Element_Offset (Offset)) /=
              Stream_Element
                (Character'Pos (Prefix (Prefix'First + Offset)))
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when Constraint_Error =>
            return False;
      end Has_Prefix;
   begin
      Count := 0;
      Status_Value :=
        List_Refs
          (Repository_Root,
           Names,
           Name_Lasts,
           Object_IDs_Hex,
           Full_Count);
      if Status_Value /= Ok then
         Count := 0;
         return Status_Value;
      end if;

      for Index in 1 .. Full_Count loop
         declare
            Read_Stop : constant Stream_Element_Offset := Name_Lasts (Index);
         begin
            if Has_Prefix (Read_Start, Read_Stop) then
               Count := Count + 1;
               for Source in
                 Read_Start + Stream_Element_Offset (Prefix'Length)
                   .. Read_Stop
               loop
                  Write_Last := Write_Last + 1;
                  Names (Write_Last) := Names (Source);
               end loop;
               Name_Lasts (Count) := Write_Last;
               Object_IDs_Hex (Count) := Object_IDs_Hex (Index);
            end if;
            Read_Start := Read_Stop + 1;
         end;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Read_Failed;
   end List_Remote_Tracking_Branches;

   function Resolve_Ref
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
      Current      : Unbounded_String := To_Unbounded_String (Ref_Name);
      Depth        : Natural := 0;
      Status_Value : Status;
      Target       : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Target_Last  : Stream_Element_Offset;
   begin
      Last := Object_ID_Hex'First - 1;
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Ref_Name (Ref_Name)
      then
         return Invalid_Command;
      elsif Object_ID_Hex'Length
        < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Read_Failed;
      end if;

      loop
         if Depth > Maximum_Ref_Resolution_Depth then
            Last := Object_ID_Hex'First - 1;
            return Unsupported_Feature;
         end if;

         declare
            Current_Name : constant String := To_String (Current);
            Direct_Status : Status;
            Symbolic_Status : Status;
         begin
            Direct_Status :=
              Read_Direct_Ref
                (Repository_Root, Current_Name, Object_ID_Hex, Last);
            if Direct_Status = Ok then
               return Ok;
            elsif Direct_Status /= Read_Failed
              and then Direct_Status /= Invalid_Command
            then
               return Direct_Status;
            end if;

            Symbolic_Status :=
              Read_Symbolic_Ref
                (Repository_Root, Current_Name, Target, Target_Last);
            if Symbolic_Status = Ok then
               declare
                  Target_Length : constant Natural :=
                    Natural (Target_Last - Target'First + 1);
                  Target_Name : String (1 .. Target_Length);
               begin
                  for Index in Target_Name'Range loop
                     Target_Name (Index) :=
                       Character'Val
                         (Target
                            (Target'First
                             + Stream_Element_Offset (Index - 1)));
                  end loop;
                  if not Valid_Ref_Name (Target_Name) then
                     Last := Object_ID_Hex'First - 1;
                     return Invalid_Command;
                  end if;
                  Current := To_Unbounded_String (Target_Name);
                  Depth := Depth + 1;
               end;
            else
               if Current_Name /= "HEAD" then
                  Status_Value :=
                    Read_Packed_Ref
                      (Repository_Root, Current_Name, Object_ID_Hex, Last);
                  if Status_Value = Ok then
                     return Ok;
                  elsif Status_Value /= Read_Failed then
                     return Status_Value;
                  end if;
               end if;

               if Direct_Status = Invalid_Command
                 or else Symbolic_Status = Invalid_Command
               then
                  Last := Object_ID_Hex'First - 1;
                  return Invalid_Command;
               else
                  Last := Object_ID_Hex'First - 1;
                  return Read_Failed;
               end if;
            end if;
         end;
      end loop;
   exception
      when Constraint_Error =>
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Last := Object_ID_Hex'First - 1;
         return Read_Failed;
   end Resolve_Ref;

   function Attach_HEAD
     (Repository_Root : String;
      Target_Ref_Name : String)
      return Status
   is
   begin
      return Write_Symbolic_Ref (Repository_Root, "HEAD", Target_Ref_Name);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Attach_HEAD;

   function Attach_HEAD_To_Branch
     (Repository_Root : String;
      Branch_Name     : String)
      return Status
   is
   begin
      if Branch_Name'Length = 0
        or else Branch_Name'Length > Maximum_Ref_Name_Length
        or else not Valid_Ref_Name ("refs/heads/" & Branch_Name)
      then
         return Invalid_Command;
      end if;
      return Attach_HEAD (Repository_Root, "refs/heads/" & Branch_Name);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Attach_HEAD_To_Branch;

   function Detach_HEAD
     (Repository_Root : String;
      Object_ID_Hex   : Stream_Element_Array)
      return Status
   is
   begin
      return Write_Direct_Ref (Repository_Root, "HEAD", Object_ID_Hex);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Detach_HEAD;

   function Resolve_HEAD
     (Repository_Root : String;
      Object_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
   begin
      return Resolve_Ref (Repository_Root, "HEAD", Object_ID_Hex, Last);
   exception
      when Constraint_Error =>
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Last := Object_ID_Hex'First - 1;
         return Read_Failed;
   end Resolve_HEAD;

   function Read_HEAD_Target
     (Repository_Root : String;
      Target_Ref_Name : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Attached        : out Boolean)
      return Status
   is
      Status_Value : Status;
   begin
      Attached := False;
      Last := Target_Ref_Name'First - 1;
      Status_Value :=
        Read_Symbolic_Ref
          (Repository_Root, "HEAD", Target_Ref_Name, Last);
      if Status_Value = Ok then
         Attached := True;
         return Ok;
      elsif Status_Value /= Read_Failed
        and then Status_Value /= Invalid_Command
      then
         return Status_Value;
      end if;

      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      end if;

      declare
         File : Stream_IO.File_Type;
         Path : constant String := Git_Path (Repository_Root, "HEAD");
      begin
         if not Ada.Directories.Exists (Path) then
            return Read_Failed;
         end if;

         Stream_IO.Open (File, Stream_IO.In_File, Path);
         if Stream_IO.Size (File) >
             Stream_IO.Count (Object_ID_SHA1_Hex_Length + 1)
           or else Stream_IO.Size (File) <
             Stream_IO.Count (Object_ID_SHA1_Hex_Length)
         then
            Stream_IO.Close (File);
            return Read_Failed;
         end if;

         declare
            Data : Stream_Element_Array
              (1 .. Stream_Element_Offset (Stream_IO.Size (File)));
            Data_Last : Stream_Element_Offset;
            Raw_ID : Stream_Element_Array
              (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
            Raw_Last : Stream_Element_Offset;
         begin
            Stream_IO.Read (File, Data, Data_Last);
            Stream_IO.Close (File);
            if Data_Last < Data'First
              + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
              - 1
            then
               return Read_Failed;
            end if;

            Status_Value :=
              Parse_Object_ID_Hex
                (Data
                   (Data'First
                    .. Data'First
                      + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                      - 1),
                 Raw_ID,
                 Raw_Last);
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         end;
      exception
         when Constraint_Error =>
            if Stream_IO.Is_Open (File) then
               Stream_IO.Close (File);
            end if;
            return Invalid_Command;
         when others =>
            if Stream_IO.Is_Open (File) then
               Stream_IO.Close (File);
            end if;
            return Read_Failed;
      end;

      Attached := False;
      Last := Target_Ref_Name'First - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Attached := False;
         Last := Target_Ref_Name'First - 1;
         return Invalid_Command;
      when others =>
         Attached := False;
         Last := Target_Ref_Name'First - 1;
         return Read_Failed;
   end Read_HEAD_Target;

   function Read_Current_Branch
     (Repository_Root : String;
      Branch_Name     : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
      Prefix : constant String := "refs/heads/";
      Target : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Target_Last : Stream_Element_Offset;
      Attached : Boolean := False;
      Status_Value : Status;
   begin
      Found := False;
      Last := Branch_Name'First - 1;
      Status_Value :=
        Read_HEAD_Target (Repository_Root, Target, Target_Last, Attached);
      if Status_Value /= Ok or else not Attached then
         return Status_Value;
      end if;

      if Target_Last - Target'First + 1 <=
        Stream_Element_Offset (Prefix'Length)
      then
         return Ok;
      end if;

      for Offset in 0 .. Prefix'Length - 1 loop
         if Target (Target'First + Stream_Element_Offset (Offset)) /=
           Stream_Element (Character'Pos (Prefix (Prefix'First + Offset)))
         then
            return Ok;
         end if;
      end loop;

      if Branch_Name'Length <
        Target_Last - Target'First + 1
          - Stream_Element_Offset (Prefix'Length)
      then
         return Read_Failed;
      end if;

      for Source in
        Target'First + Stream_Element_Offset (Prefix'Length) .. Target_Last
      loop
         Last := Last + 1;
         Branch_Name (Last) := Target (Source);
      end loop;
      Found := True;
      return Ok;
   exception
      when Constraint_Error =>
         Found := False;
         Last := Branch_Name'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Last := Branch_Name'First - 1;
         return Read_Failed;
   end Read_Current_Branch;

   function Branch_Ref_Name (Branch_Name : String) return String is
   begin
      return "refs/heads/" & Branch_Name;
   end Branch_Ref_Name;

   function Valid_Branch_Name (Branch_Name : String) return Boolean is
   begin
      return Branch_Name'Length > 0
        and then Branch_Name'Length <= Maximum_Ref_Name_Length
        and then Valid_Ref_Name (Branch_Ref_Name (Branch_Name));
   exception
      when others =>
         return False;
   end Valid_Branch_Name;

   function Write_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : Stream_Element_Array)
      return Status
   is
   begin
      if not Valid_Branch_Name (Branch_Name) then
         return Invalid_Command;
      end if;
      return
        Write_Direct_Ref
          (Repository_Root, Branch_Ref_Name (Branch_Name), Object_ID_Hex);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_Branch;

   function Create_Branch_From_HEAD
     (Repository_Root : String;
      Branch_Name     : String)
      return Status
   is
      Object_ID_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Last : Stream_Element_Offset;
      Status_Value : Status;
   begin
      if not Valid_Branch_Name (Branch_Name) then
         return Invalid_Command;
      end if;

      Status_Value := Resolve_HEAD (Repository_Root, Object_ID_Hex, Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Last /= Object_ID_Hex'Last then
         return Read_Failed;
      end if;

      return Write_Branch (Repository_Root, Branch_Name, Object_ID_Hex);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Create_Branch_From_HEAD;

   function Read_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
   begin
      Last := Object_ID_Hex'First - 1;
      if not Valid_Branch_Name (Branch_Name) then
         return Invalid_Command;
      end if;
      return
        Read_Direct_Ref
          (Repository_Root, Branch_Ref_Name (Branch_Name), Object_ID_Hex, Last);
   exception
      when Constraint_Error =>
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Last := Object_ID_Hex'First - 1;
         return Read_Failed;
   end Read_Branch;

   function Resolve_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
   begin
      Last := Object_ID_Hex'First - 1;
      if not Valid_Branch_Name (Branch_Name) then
         return Invalid_Command;
      end if;
      return
        Resolve_Ref
          (Repository_Root, Branch_Ref_Name (Branch_Name), Object_ID_Hex, Last);
   exception
      when Constraint_Error =>
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Last := Object_ID_Hex'First - 1;
         return Read_Failed;
   end Resolve_Branch;

   function Delete_Branch
     (Repository_Root : String;
      Branch_Name     : String)
      return Status
   is
   begin
      if not Valid_Branch_Name (Branch_Name) then
         return Invalid_Command;
      end if;
      return Delete_Direct_Ref (Repository_Root, Branch_Ref_Name (Branch_Name));
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Delete_Branch;

   function Branch_Exists
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
   begin
      Found := False;
      Last := Object_ID_Hex'First - 1;
      if not Valid_Branch_Name (Branch_Name) then
         return Invalid_Command;
      end if;
      return
        Ref_Exists
          (Repository_Root,
           Branch_Ref_Name (Branch_Name),
           Object_ID_Hex,
           Last,
           Found);
   exception
      when Constraint_Error =>
         Found := False;
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Last := Object_ID_Hex'First - 1;
         return Read_Failed;
   end Branch_Exists;

   function Remote_Tracking_Branch_Ref_Name
     (Branch_Name : String)
      return String
   is
   begin
      return "refs/remotes/" & Branch_Name;
   end Remote_Tracking_Branch_Ref_Name;

   function Valid_Remote_Tracking_Branch_Name
     (Branch_Name : String)
      return Boolean
   is
   begin
      return Branch_Name'Length > 0
        and then Branch_Name'Length <= Maximum_Ref_Name_Length
        and then
          Valid_Ref_Name (Remote_Tracking_Branch_Ref_Name (Branch_Name));
   exception
      when others =>
         return False;
   end Valid_Remote_Tracking_Branch_Name;

   function Write_Remote_Tracking_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : Stream_Element_Array)
      return Status
   is
   begin
      if not Valid_Remote_Tracking_Branch_Name (Branch_Name) then
         return Invalid_Command;
      end if;
      return
        Write_Direct_Ref
          (Repository_Root,
           Remote_Tracking_Branch_Ref_Name (Branch_Name),
           Object_ID_Hex);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_Remote_Tracking_Branch;

   function Create_Remote_Tracking_Branch_From_HEAD
     (Repository_Root : String;
      Branch_Name     : String)
      return Status
   is
      Object_ID_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Last : Stream_Element_Offset;
      Status_Value : Status;
   begin
      if not Valid_Remote_Tracking_Branch_Name (Branch_Name) then
         return Invalid_Command;
      end if;

      Status_Value := Resolve_HEAD (Repository_Root, Object_ID_Hex, Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Last /= Object_ID_Hex'Last then
         return Read_Failed;
      end if;

      return
        Write_Remote_Tracking_Branch
          (Repository_Root, Branch_Name, Object_ID_Hex);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Create_Remote_Tracking_Branch_From_HEAD;

   function Read_Remote_Tracking_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
   begin
      Last := Object_ID_Hex'First - 1;
      if not Valid_Remote_Tracking_Branch_Name (Branch_Name) then
         return Invalid_Command;
      end if;
      return
        Read_Direct_Ref
          (Repository_Root,
           Remote_Tracking_Branch_Ref_Name (Branch_Name),
           Object_ID_Hex,
           Last);
   exception
      when Constraint_Error =>
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Last := Object_ID_Hex'First - 1;
         return Read_Failed;
   end Read_Remote_Tracking_Branch;

   function Resolve_Remote_Tracking_Branch
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
   begin
      Last := Object_ID_Hex'First - 1;
      if not Valid_Remote_Tracking_Branch_Name (Branch_Name) then
         return Invalid_Command;
      end if;
      return
        Resolve_Ref
          (Repository_Root,
           Remote_Tracking_Branch_Ref_Name (Branch_Name),
           Object_ID_Hex,
           Last);
   exception
      when Constraint_Error =>
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Last := Object_ID_Hex'First - 1;
         return Read_Failed;
   end Resolve_Remote_Tracking_Branch;

   function Delete_Remote_Tracking_Branch
     (Repository_Root : String;
      Branch_Name     : String)
      return Status
   is
   begin
      if not Valid_Remote_Tracking_Branch_Name (Branch_Name) then
         return Invalid_Command;
      end if;
      return
        Delete_Direct_Ref
          (Repository_Root, Remote_Tracking_Branch_Ref_Name (Branch_Name));
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Delete_Remote_Tracking_Branch;

   function Remote_Tracking_Branch_Exists
     (Repository_Root : String;
      Branch_Name     : String;
      Object_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
   begin
      Found := False;
      Last := Object_ID_Hex'First - 1;
      if not Valid_Remote_Tracking_Branch_Name (Branch_Name) then
         return Invalid_Command;
      end if;
      return
        Ref_Exists
          (Repository_Root,
           Remote_Tracking_Branch_Ref_Name (Branch_Name),
           Object_ID_Hex,
           Last,
           Found);
   exception
      when Constraint_Error =>
         Found := False;
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Last := Object_ID_Hex'First - 1;
         return Read_Failed;
   end Remote_Tracking_Branch_Exists;

   function Apply_Fetch_Ref_Update
     (Repository_Root        : String;
      Remote_Name            : String;
      Branch_Name            : String;
      New_Commit_Hex         : Stream_Element_Array;
      Allow_Non_Fast_Forward : Boolean;
      Updated                : out Boolean)
      return Status
   is
      Remote_Branch : constant String := Remote_Name & "/" & Branch_Name;
      Current_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Current_Last : Stream_Element_Offset;
      Found : Boolean := False;
      Ancestor : Boolean := False;
      Status_Value : Status;
   begin
      Updated := False;
      if not Valid_Repository_Root (Repository_Root)
        or else New_Commit_Hex'Length /=
          Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
        or else Remote_Branch'Length > Maximum_Ref_Name_Length
      then
         return Invalid_Command;
      end if;

      Status_Value :=
        Remote_Tracking_Branch_Exists
          (Repository_Root,
           Remote_Branch,
           Current_ID,
           Current_Last,
           Found);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Found then
         if Current_Last /= Current_ID'Last then
            return Invalid_Command;
         elsif Current_ID = New_Commit_Hex then
            return Ok;
         elsif not Allow_Non_Fast_Forward then
            Status_Value :=
              Is_Ancestor_First_Parent
                (Repository_Root,
                 Current_ID,
                 New_Commit_Hex,
                 Ancestor);
            if Status_Value /= Ok then
               return Status_Value;
            elsif not Ancestor then
               return Unsupported_Feature;
            end if;
         end if;
      end if;

      Status_Value :=
        Write_Remote_Tracking_Branch
          (Repository_Root, Remote_Branch, New_Commit_Hex);
      if Status_Value = Ok then
         Updated := True;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Updated := False;
         return Invalid_Command;
      when others =>
         Updated := False;
         return Internal_Error;
   end Apply_Fetch_Ref_Update;

   function Tag_Ref_Name (Tag_Name : String) return String is
   begin
      return "refs/tags/" & Tag_Name;
   end Tag_Ref_Name;

   function Valid_Tag_Ref_Name (Tag_Name : String) return Boolean is
   begin
      return Tag_Name'Length > 0
        and then Tag_Name'Length <= Maximum_Ref_Name_Length
        and then Valid_Ref_Name (Tag_Ref_Name (Tag_Name));
   exception
      when others =>
         return False;
   end Valid_Tag_Ref_Name;

   function Write_Tag_Ref
     (Repository_Root : String;
      Tag_Name        : String;
      Object_ID_Hex   : Stream_Element_Array)
      return Status
   is
   begin
      if not Valid_Tag_Ref_Name (Tag_Name) then
         return Invalid_Command;
      end if;
      return
        Write_Direct_Ref
          (Repository_Root, Tag_Ref_Name (Tag_Name), Object_ID_Hex);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_Tag_Ref;

   function Create_Tag_Ref_From_HEAD
     (Repository_Root : String;
      Tag_Name        : String)
      return Status
   is
      Object_ID_Hex : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Last : Stream_Element_Offset;
      Status_Value : Status;
   begin
      if not Valid_Tag_Ref_Name (Tag_Name) then
         return Invalid_Command;
      end if;

      Status_Value := Resolve_HEAD (Repository_Root, Object_ID_Hex, Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Last /= Object_ID_Hex'Last then
         return Read_Failed;
      end if;

      return Write_Tag_Ref (Repository_Root, Tag_Name, Object_ID_Hex);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Create_Tag_Ref_From_HEAD;

   function Read_Tag_Ref
     (Repository_Root : String;
      Tag_Name        : String;
      Object_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
   begin
      Last := Object_ID_Hex'First - 1;
      if not Valid_Tag_Ref_Name (Tag_Name) then
         return Invalid_Command;
      end if;
      return
        Read_Direct_Ref
          (Repository_Root, Tag_Ref_Name (Tag_Name), Object_ID_Hex, Last);
   exception
      when Constraint_Error =>
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Last := Object_ID_Hex'First - 1;
         return Read_Failed;
   end Read_Tag_Ref;

   function Resolve_Tag_Ref
     (Repository_Root : String;
      Tag_Name        : String;
      Object_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
   begin
      Last := Object_ID_Hex'First - 1;
      if not Valid_Tag_Ref_Name (Tag_Name) then
         return Invalid_Command;
      end if;
      return
        Resolve_Ref
          (Repository_Root, Tag_Ref_Name (Tag_Name), Object_ID_Hex, Last);
   exception
      when Constraint_Error =>
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Last := Object_ID_Hex'First - 1;
         return Read_Failed;
   end Resolve_Tag_Ref;

   function Delete_Tag_Ref
     (Repository_Root : String;
      Tag_Name        : String)
      return Status
   is
   begin
      if not Valid_Tag_Ref_Name (Tag_Name) then
         return Invalid_Command;
      end if;
      return Delete_Direct_Ref (Repository_Root, Tag_Ref_Name (Tag_Name));
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Delete_Tag_Ref;

   function Tag_Ref_Exists
     (Repository_Root : String;
      Tag_Name        : String;
      Object_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
   begin
      Found := False;
      Last := Object_ID_Hex'First - 1;
      if not Valid_Tag_Ref_Name (Tag_Name) then
         return Invalid_Command;
      end if;
      return
        Ref_Exists
          (Repository_Root,
           Tag_Ref_Name (Tag_Name),
           Object_ID_Hex,
           Last,
           Found);
   exception
      when Constraint_Error =>
         Found := False;
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Last := Object_ID_Hex'First - 1;
         return Read_Failed;
   end Tag_Ref_Exists;

   function Append_Reflog_Entry
     (Repository_Root : String;
      Ref_Name        : String;
      Old_ID_Hex      : Stream_Element_Array;
      New_ID_Hex      : Stream_Element_Array;
      Actor           : String;
      Message         : String)
      return Status
   is
      Raw_ID       : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last     : Stream_Element_Offset;
      Status_Value : Status;
      File         : Stream_IO.File_Type;
      Path         : constant String := Reflog_File_Path (Repository_Root, Ref_Name);

      function Clean_Text (Text : String) return Boolean is
      begin
         if Text'Length > Maximum_Pkt_Line_Payload_Length then
            return False;
         end if;
         for Ch of Text loop
            if Ch = Character'Val (0)
              or else Ch = Character'Val (10)
              or else Ch = Character'Val (13)
            then
               return False;
            end if;
         end loop;
         return True;
      end Clean_Text;

      procedure Copy_ID
        (Source : Stream_Element_Array;
         Target : in out Stream_Element_Array;
         Cursor : in out Stream_Element_Offset)
      is
      begin
         Target
           (Cursor
            .. Cursor + Stream_Element_Offset (Object_ID_SHA1_Hex_Length) - 1) :=
           Source
             (Source'First
              .. Source'First
                 + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                 - 1);
         Cursor := Cursor + Stream_Element_Offset (Object_ID_SHA1_Hex_Length);
      end Copy_ID;

      procedure Copy_String
        (Source : String;
         Target : in out Stream_Element_Array;
         Cursor : in out Stream_Element_Offset)
      is
      begin
         for Ch of Source loop
            Target (Cursor) := Stream_Element (Character'Pos (Ch));
            Cursor := Cursor + 1;
         end loop;
      end Copy_String;
   begin
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Ref_Name (Ref_Name)
        or else not Clean_Text (Actor)
        or else not Clean_Text (Message)
      then
         return Invalid_Command;
      end if;

      Status_Value := Parse_Object_ID_Hex (Old_ID_Hex, Raw_ID, Raw_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Raw_Last /= Raw_ID'Last then
         return Invalid_Command;
      end if;
      Status_Value := Parse_Object_ID_Hex (New_ID_Hex, Raw_ID, Raw_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Raw_Last /= Raw_ID'Last then
         return Invalid_Command;
      end if;

      declare
         Line_Length : constant Natural :=
           Object_ID_SHA1_Hex_Length + 1
           + Object_ID_SHA1_Hex_Length + 1
           + Actor'Length + 1
           + Message'Length + 1;
      begin
         if Line_Length > Maximum_Pkt_Line_Payload_Length then
            return Unsupported_Feature;
         end if;
         declare
            Line : Stream_Element_Array
              (1 .. Stream_Element_Offset (Line_Length));
            Cursor : Stream_Element_Offset := Line'First;
         begin
            Copy_ID (Old_ID_Hex, Line, Cursor);
            Line (Cursor) := Stream_Element (Character'Pos (' '));
            Cursor := Cursor + 1;
            Copy_ID (New_ID_Hex, Line, Cursor);
            Line (Cursor) := Stream_Element (Character'Pos (' '));
            Cursor := Cursor + 1;
            Copy_String (Actor, Line, Cursor);
            Line (Cursor) := Stream_Element (Character'Pos (Character'Val (9)));
            Cursor := Cursor + 1;
            Copy_String (Message, Line, Cursor);
            Line (Cursor) := Stream_Element (Character'Pos (Character'Val (10)));

            Ada.Directories.Create_Path (Ada.Directories.Containing_Directory (Path));
            if Ada.Directories.Exists (Path) then
               Stream_IO.Open (File, Stream_IO.Append_File, Path);
            else
               Stream_IO.Create (File, Stream_IO.Out_File, Path);
            end if;
            Stream_IO.Write (File, Line);
            Stream_IO.Close (File);
         end;
      end;
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Write_Failed;
   end Append_Reflog_Entry;

   function Read_Reflog_Last_Entry
     (Repository_Root : String;
      Ref_Name        : String;
      Line            : out Stream_Element_Array;
      Last            : out Stream_Element_Offset)
      return Status
   is
      File      : Stream_IO.File_Type;
      File_Size : Stream_IO.Count;
      Path      : constant String := Reflog_File_Path (Repository_Root, Ref_Name);
   begin
      Last := Line'First - 1;
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Ref_Name (Ref_Name)
      then
         return Invalid_Command;
      end if;

      Stream_IO.Open (File, Stream_IO.In_File, Path);
      File_Size := Stream_IO.Size (File);
      if File_Size = 0 or else File_Size > Maximum_Reflog_File_Length then
         Stream_IO.Close (File);
         return Invalid_Command;
      end if;

      declare
         Data      : Stream_Element_Array
           (1 .. Stream_Element_Offset (File_Size));
         File_Last : Stream_Element_Offset;
         Entry_First : Stream_Element_Offset := Data'First;
         Entry_Last  : constant Stream_Element_Offset := Data'Last - 1;
      begin
         Stream_IO.Read (File, Data, File_Last);
         Stream_IO.Close (File);
         if File_Last /= Data'Last
           or else Data (Data'Last) /=
             Stream_Element (Character'Pos (Character'Val (10)))
         then
            return Invalid_Command;
         end if;

         if Data'Last > Data'First then
            for Cursor in reverse Data'First .. Data'Last - 1 loop
               if Data (Cursor) =
                 Stream_Element (Character'Pos (Character'Val (10)))
               then
                  Entry_First := Cursor + 1;
                  exit;
               end if;
            end loop;
         end if;

         if Entry_Last < Entry_First then
            return Invalid_Command;
         elsif Line'Length < Entry_Last - Entry_First + 1 then
            return Read_Failed;
         end if;
         Line (Line'First .. Line'First + (Entry_Last - Entry_First)) :=
           Data (Entry_First .. Entry_Last);
         Last := Line'First + (Entry_Last - Entry_First);
      end;
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Last := Line'First - 1;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Last := Line'First - 1;
         return Read_Failed;
   end Read_Reflog_Last_Entry;

   function Read_Config_Value
     (Repository_Root : String;
      Section         : String;
      Key             : String;
      Value           : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
      File      : Stream_IO.File_Type;
      File_Size : Stream_IO.Count;
      Path      : constant String := Config_File_Path (Repository_Root);

      function Clean_Name (Text : String) return Boolean is
      begin
         if Text'Length = 0 or else Text'Length > Maximum_Ref_Name_Length then
            return False;
         end if;
         for Ch of Text loop
            if Ch = Character'Val (0)
              or else Ch = Character'Val (10)
              or else Ch = Character'Val (13)
              or else Ch = '['
              or else Ch = ']'
              or else Ch = '='
            then
               return False;
            end if;
         end loop;
         return True;
      end Clean_Name;

      function Is_Space (Item : Stream_Element) return Boolean is
      begin
         return Item = Stream_Element (Character'Pos (' '))
           or else Item = Stream_Element (Character'Pos (Character'Val (9)));
      end Is_Space;

      function Matches_String
        (Data  : Stream_Element_Array;
         First : Stream_Element_Offset;
         Last_Value : Stream_Element_Offset;
         Text  : String)
         return Boolean
      is
      begin
         if Last_Value < First then
            return Text'Length = 0;
         elsif Last_Value - First + 1 /= Stream_Element_Offset (Text'Length) then
            return False;
         end if;
         for Index in Text'Range loop
            if Data (First + Stream_Element_Offset (Index - Text'First))
              /= Stream_Element (Character'Pos (Text (Index)))
            then
               return False;
            end if;
         end loop;
         return True;
      end Matches_String;

      procedure Trim
        (Data : Stream_Element_Array;
         First : in out Stream_Element_Offset;
         Last_Value : in out Stream_Element_Offset)
      is
      begin
         while First <= Last_Value and then Is_Space (Data (First)) loop
            First := First + 1;
         end loop;
         while Last_Value >= First and then Is_Space (Data (Last_Value)) loop
            Last_Value := Last_Value - 1;
         end loop;
      end Trim;
   begin
      Found := False;
      Last := Value'First - 1;
      if not Valid_Repository_Root (Repository_Root)
        or else not Clean_Name (Section)
        or else not Clean_Name (Key)
      then
         return Invalid_Command;
      end if;

      Stream_IO.Open (File, Stream_IO.In_File, Path);
      File_Size := Stream_IO.Size (File);
      if File_Size = 0 or else File_Size > Maximum_Config_File_Length then
         Stream_IO.Close (File);
         return Invalid_Command;
      end if;

      declare
         Data      : Stream_Element_Array
           (1 .. Stream_Element_Offset (File_Size));
         File_Last : Stream_Element_Offset;
         Cursor    : Stream_Element_Offset := Data'First;
         In_Section : Boolean := False;
      begin
         Stream_IO.Read (File, Data, File_Last);
         Stream_IO.Close (File);
         if File_Last /= Data'Last then
            return Read_Failed;
         end if;

         while Cursor <= Data'Last loop
            declare
               Line_First : Stream_Element_Offset := Cursor;
               Line_Last  : Stream_Element_Offset := Cursor;
            begin
               while Line_Last <= Data'Last
                 and then Data (Line_Last) /=
                   Stream_Element (Character'Pos (Character'Val (10)))
               loop
                  Line_Last := Line_Last + 1;
               end loop;
               if Line_Last > Data'Last then
                  Cursor := Data'Last + 1;
                  Line_Last := Data'Last;
               else
                  Cursor := Line_Last + 1;
                  Line_Last := Line_Last - 1;
               end if;
               if Line_Last >= Line_First
                 and then Data (Line_Last) =
                   Stream_Element (Character'Pos (Character'Val (13)))
               then
                  Line_Last := Line_Last - 1;
               end if;

               Trim (Data, Line_First, Line_Last);
               if Line_Last < Line_First then
                  null;
               elsif Data (Line_First) = Stream_Element (Character'Pos ('#'))
                 or else Data (Line_First) = Stream_Element (Character'Pos (';'))
               then
                  null;
               elsif Data (Line_First) = Stream_Element (Character'Pos ('[')) then
                  if Data (Line_Last) /= Stream_Element (Character'Pos (']'))
                    or else Line_Last <= Line_First + 1
                  then
                     return Invalid_Command;
                  end if;
                  declare
                     Name_First : Stream_Element_Offset := Line_First + 1;
                     Name_Last  : Stream_Element_Offset := Line_Last - 1;
                  begin
                     Trim (Data, Name_First, Name_Last);
                     In_Section :=
                       Matches_String (Data, Name_First, Name_Last, Section);
                  end;
               elsif In_Section then
                  declare
                     Equals : Stream_Element_Offset := Line_First;
                  begin
                     while Equals <= Line_Last
                       and then Data (Equals) /=
                         Stream_Element (Character'Pos ('='))
                     loop
                        Equals := Equals + 1;
                     end loop;
                     if Equals > Line_Last then
                        return Invalid_Command;
                     end if;
                     declare
                        Key_First : Stream_Element_Offset := Line_First;
                        Key_Last  : Stream_Element_Offset := Equals - 1;
                        Value_First : Stream_Element_Offset := Equals + 1;
                        Value_Last  : Stream_Element_Offset := Line_Last;
                     begin
                        Trim (Data, Key_First, Key_Last);
                        Trim (Data, Value_First, Value_Last);
                        if Matches_String (Data, Key_First, Key_Last, Key) then
                           Found := True;
                           if Value_Last < Value_First then
                              Last := Value'First - 1;
                              return Ok;
                           elsif Value'Length < Value_Last - Value_First + 1 then
                              Last := Value'First - 1;
                              return Read_Failed;
                           end if;
                           Value
                             (Value'First
                              .. Value'First + (Value_Last - Value_First)) :=
                             Data (Value_First .. Value_Last);
                           Last := Value'First + (Value_Last - Value_First);
                           return Ok;
                        end if;
                     end;
                  end;
               end if;
            end;
         end loop;
      end;
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Found := False;
         Last := Value'First - 1;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Found := False;
         Last := Value'First - 1;
         return Read_Failed;
   end Read_Config_Value;

   function Read_Config_Values
     (Repository_Root : String;
      Section         : String;
      Key             : String;
      Values          : out Stream_Element_Array;
      Value_Lasts     : out Config_Value_Last_Array;
      Count           : out Natural)
      return Status
   is
      File      : Stream_IO.File_Type;
      File_Size : Stream_IO.Count;
      Path      : constant String := Config_File_Path (Repository_Root);

      function Clean_Name (Text : String) return Boolean is
      begin
         if Text'Length = 0 or else Text'Length > Maximum_Ref_Name_Length then
            return False;
         end if;
         for Ch of Text loop
            if Ch = Character'Val (0)
              or else Ch = Character'Val (10)
              or else Ch = Character'Val (13)
              or else Ch = '['
              or else Ch = ']'
              or else Ch = '='
            then
               return False;
            end if;
         end loop;
         return True;
      end Clean_Name;

      function Is_Space (Item : Stream_Element) return Boolean is
      begin
         return Item = Stream_Element (Character'Pos (' '))
           or else Item = Stream_Element (Character'Pos (Character'Val (9)));
      end Is_Space;

      function Matches_String
        (Data  : Stream_Element_Array;
         First : Stream_Element_Offset;
         Last_Value : Stream_Element_Offset;
         Text  : String)
         return Boolean
      is
      begin
         if Last_Value < First then
            return Text'Length = 0;
         elsif Last_Value - First + 1 /= Stream_Element_Offset (Text'Length) then
            return False;
         end if;
         for Index in Text'Range loop
            if Data (First + Stream_Element_Offset (Index - Text'First))
              /= Stream_Element (Character'Pos (Text (Index)))
            then
               return False;
            end if;
         end loop;
         return True;
      end Matches_String;

      procedure Trim
        (Data : Stream_Element_Array;
         First : in out Stream_Element_Offset;
         Last_Value : in out Stream_Element_Offset)
      is
      begin
         while First <= Last_Value and then Is_Space (Data (First)) loop
            First := First + 1;
         end loop;
         while Last_Value >= First and then Is_Space (Data (Last_Value)) loop
            Last_Value := Last_Value - 1;
         end loop;
      end Trim;
   begin
      Count := 0;
      for Index in Value_Lasts'Range loop
         Value_Lasts (Index) := Values'First - 1;
      end loop;
      if not Valid_Repository_Root (Repository_Root)
        or else not Clean_Name (Section)
        or else not Clean_Name (Key)
      then
         return Invalid_Command;
      end if;

      Stream_IO.Open (File, Stream_IO.In_File, Path);
      File_Size := Stream_IO.Size (File);
      if File_Size = 0 or else File_Size > Maximum_Config_File_Length then
         Stream_IO.Close (File);
         return Invalid_Command;
      end if;

      declare
         Data      : Stream_Element_Array
           (1 .. Stream_Element_Offset (File_Size));
         File_Last : Stream_Element_Offset;
         Cursor    : Stream_Element_Offset := Data'First;
         In_Section : Boolean := False;
         Output_Cursor : Stream_Element_Offset := Values'First;
      begin
         Stream_IO.Read (File, Data, File_Last);
         Stream_IO.Close (File);
         if File_Last /= Data'Last then
            return Read_Failed;
         end if;

         while Cursor <= Data'Last loop
            declare
               Line_First : Stream_Element_Offset := Cursor;
               Line_Last  : Stream_Element_Offset := Cursor;
            begin
               while Line_Last <= Data'Last
                 and then Data (Line_Last) /=
                   Stream_Element (Character'Pos (Character'Val (10)))
               loop
                  Line_Last := Line_Last + 1;
               end loop;
               if Line_Last > Data'Last then
                  Cursor := Data'Last + 1;
                  Line_Last := Data'Last;
               else
                  Cursor := Line_Last + 1;
                  Line_Last := Line_Last - 1;
               end if;
               if Line_Last >= Line_First
                 and then Data (Line_Last) =
                   Stream_Element (Character'Pos (Character'Val (13)))
               then
                  Line_Last := Line_Last - 1;
               end if;

               Trim (Data, Line_First, Line_Last);
               if Line_Last < Line_First then
                  null;
               elsif Data (Line_First) = Stream_Element (Character'Pos ('#'))
                 or else Data (Line_First) = Stream_Element (Character'Pos (';'))
               then
                  null;
               elsif Data (Line_First) = Stream_Element (Character'Pos ('[')) then
                  if Data (Line_Last) /= Stream_Element (Character'Pos (']'))
                    or else Line_Last <= Line_First + 1
                  then
                     return Invalid_Command;
                  end if;
                  declare
                     Name_First : Stream_Element_Offset := Line_First + 1;
                     Name_Last  : Stream_Element_Offset := Line_Last - 1;
                  begin
                     Trim (Data, Name_First, Name_Last);
                     In_Section :=
                       Matches_String (Data, Name_First, Name_Last, Section);
                  end;
               elsif In_Section then
                  declare
                     Equals : Stream_Element_Offset := Line_First;
                  begin
                     while Equals <= Line_Last
                       and then Data (Equals) /=
                         Stream_Element (Character'Pos ('='))
                     loop
                        Equals := Equals + 1;
                     end loop;
                     if Equals > Line_Last then
                        return Invalid_Command;
                     end if;
                     declare
                        Key_First : Stream_Element_Offset := Line_First;
                        Key_Last  : Stream_Element_Offset := Equals - 1;
                        Value_First : Stream_Element_Offset := Equals + 1;
                        Value_Last  : Stream_Element_Offset := Line_Last;
                     begin
                        Trim (Data, Key_First, Key_Last);
                        Trim (Data, Value_First, Value_Last);
                        if Matches_String (Data, Key_First, Key_Last, Key) then
                           if Count = Value_Lasts'Length then
                              Count := 0;
                              return Read_Failed;
                           end if;
                           declare
                              Length : constant Stream_Element_Offset :=
                                (if Value_Last < Value_First
                                 then 0
                                 else Value_Last - Value_First + 1);
                           begin
                              if Length > 0 then
                                 if Output_Cursor > Values'Last
                                   or else Length >
                                     Values'Last - Output_Cursor + 1
                                 then
                                    Count := 0;
                                    return Read_Failed;
                                 end if;
                                 Values
                                   (Output_Cursor
                                    .. Output_Cursor + Length - 1) :=
                                   Data (Value_First .. Value_Last);
                                 Output_Cursor := Output_Cursor + Length;
                              end if;
                              Count := Count + 1;
                              Value_Lasts (Value_Lasts'First + Count - 1) :=
                                Output_Cursor - 1;
                           end;
                        end if;
                     end;
                  end;
               end if;
            end;
         end loop;
      end;
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Count := 0;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Count := 0;
         return Read_Failed;
   end Read_Config_Values;

   function Write_Config_Value
     (Repository_Root : String;
      Section         : String;
      Key             : String;
      Value           : String)
      return Status
   is
      File      : Stream_IO.File_Type;
      File_Size : Stream_IO.Count := 0;
      Path      : constant String := Config_File_Path (Repository_Root);

      function Clean_Name (Text : String) return Boolean is
      begin
         if Text'Length = 0 or else Text'Length > Maximum_Ref_Name_Length then
            return False;
         end if;
         for Ch of Text loop
            if Ch = Character'Val (0)
              or else Ch = Character'Val (10)
              or else Ch = Character'Val (13)
              or else Ch = '['
              or else Ch = ']'
              or else Ch = '='
            then
               return False;
            end if;
         end loop;
         return True;
      end Clean_Name;

      function Clean_Value (Text : String) return Boolean is
      begin
         if Text'Length > Maximum_Pkt_Line_Payload_Length then
            return False;
         end if;
         for Ch of Text loop
            if Ch = Character'Val (0)
              or else Ch = Character'Val (10)
              or else Ch = Character'Val (13)
            then
               return False;
            end if;
         end loop;
         return True;
      end Clean_Value;

      function Is_Space (Item : Stream_Element) return Boolean is
      begin
         return Item = Stream_Element (Character'Pos (' '))
           or else Item = Stream_Element (Character'Pos (Character'Val (9)));
      end Is_Space;

      function Matches_String
        (Data  : Stream_Element_Array;
         First : Stream_Element_Offset;
         Last_Value : Stream_Element_Offset;
         Text  : String)
         return Boolean
      is
      begin
         if Last_Value < First then
            return Text'Length = 0;
         elsif Last_Value - First + 1 /= Stream_Element_Offset (Text'Length) then
            return False;
         end if;
         for Index in Text'Range loop
            if Data (First + Stream_Element_Offset (Index - Text'First))
              /= Stream_Element (Character'Pos (Text (Index)))
            then
               return False;
            end if;
         end loop;
         return True;
      end Matches_String;

      procedure Trim
        (Data : Stream_Element_Array;
         First : in out Stream_Element_Offset;
         Last_Value : in out Stream_Element_Offset)
      is
      begin
         while First <= Last_Value and then Is_Space (Data (First)) loop
            First := First + 1;
         end loop;
         while Last_Value >= First and then Is_Space (Data (Last_Value)) loop
            Last_Value := Last_Value - 1;
         end loop;
      end Trim;

      procedure Store_String
        (Text : String;
         Target : in out Stream_Element_Array;
         Cursor : in out Stream_Element_Offset)
      is
      begin
         for Ch of Text loop
            Target (Cursor) := Stream_Element (Character'Pos (Ch));
            Cursor := Cursor + 1;
         end loop;
      end Store_String;
   begin
      if not Valid_Repository_Root (Repository_Root)
        or else not Clean_Name (Section)
        or else not Clean_Name (Key)
        or else not Clean_Value (Value)
      then
         return Invalid_Command;
      end if;

      if Ada.Directories.Exists (Path) then
         Stream_IO.Open (File, Stream_IO.In_File, Path);
         File_Size := Stream_IO.Size (File);
         if File_Size > Maximum_Config_File_Length then
            Stream_IO.Close (File);
            return Invalid_Command;
         end if;
      end if;

      declare
         Existing_Last : constant Stream_Element_Offset :=
           Stream_Element_Offset (File_Size);
         Existing : Stream_Element_Array (1 .. Existing_Last);
         File_Last : Stream_Element_Offset := 0;
      begin
         if File_Size > 0 then
            Stream_IO.Read (File, Existing, File_Last);
            Stream_IO.Close (File);
            if File_Last /= Existing'Last then
               return Read_Failed;
            end if;
         elsif Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;

         declare
            New_Line_Text : constant String :=
              Character'Val (9) & Key & " = " & Value & Character'Val (10);
            Section_Text : constant String :=
              "[" & Section & "]" & Character'Val (10);
            Extra_Length : constant Natural :=
              Section_Text'Length + New_Line_Text'Length + 1;
            Updated : Stream_Element_Array
              (1 .. Existing_Last + Stream_Element_Offset (Extra_Length));
            Cursor : Stream_Element_Offset := Updated'First;
            Read_Cursor : Stream_Element_Offset := Existing'First;
            In_Section : Boolean := False;
            Section_Found : Boolean := False;
            Key_Written : Boolean := False;
         begin
            while Read_Cursor <= Existing'Last loop
               declare
                  Line_First : constant Stream_Element_Offset := Read_Cursor;
                  Line_End   : Stream_Element_Offset := Read_Cursor;
                  Line_Last  : Stream_Element_Offset;
                  Trim_First : Stream_Element_Offset;
                  Trim_Last  : Stream_Element_Offset;
                  Is_Target_Key : Boolean := False;
                  Is_Section_Header : Boolean := False;
                  Starts_New_Section : Boolean := False;
               begin
                  while Line_End <= Existing'Last
                    and then Existing (Line_End) /=
                      Stream_Element (Character'Pos (Character'Val (10)))
                  loop
                     Line_End := Line_End + 1;
                  end loop;
                  if Line_End <= Existing'Last then
                     Line_Last := Line_End;
                     Read_Cursor := Line_End + 1;
                  else
                     Line_Last := Existing'Last;
                     Read_Cursor := Existing'Last + 1;
                  end if;

                  Trim_First := Line_First;
                  Trim_Last :=
                    (if Existing (Line_Last) =
                       Stream_Element (Character'Pos (Character'Val (10)))
                     then Line_Last - 1
                     else Line_Last);
                  if Trim_Last >= Trim_First
                    and then Existing (Trim_Last) =
                      Stream_Element (Character'Pos (Character'Val (13)))
                  then
                     Trim_Last := Trim_Last - 1;
                  end if;
                  Trim (Existing, Trim_First, Trim_Last);

                  if Trim_Last >= Trim_First
                    and then Existing (Trim_First) =
                      Stream_Element (Character'Pos ('['))
                  then
                     Starts_New_Section := True;
                     if Existing (Trim_Last) /=
                       Stream_Element (Character'Pos (']'))
                       or else Trim_Last <= Trim_First + 1
                     then
                        return Invalid_Command;
                     end if;
                     declare
                        Name_First : Stream_Element_Offset := Trim_First + 1;
                        Name_Last  : Stream_Element_Offset := Trim_Last - 1;
                     begin
                        Trim (Existing, Name_First, Name_Last);
                        Is_Section_Header :=
                          Matches_String
                            (Existing, Name_First, Name_Last, Section);
                     end;
                  end if;

                  if In_Section
                    and then Starts_New_Section
                    and then not Key_Written
                  then
                     Store_String (New_Line_Text, Updated, Cursor);
                     Key_Written := True;
                  end if;

                  if Starts_New_Section then
                     In_Section := Is_Section_Header;
                     if In_Section then
                        Section_Found := True;
                     end if;
                  elsif In_Section and then Trim_Last >= Trim_First then
                     declare
                        Equals : Stream_Element_Offset := Trim_First;
                     begin
                        while Equals <= Trim_Last
                          and then Existing (Equals) /=
                            Stream_Element (Character'Pos ('='))
                        loop
                           Equals := Equals + 1;
                        end loop;
                        if Equals <= Trim_Last then
                           declare
                              Key_First : Stream_Element_Offset := Trim_First;
                              Key_Last  : Stream_Element_Offset := Equals - 1;
                           begin
                              Trim (Existing, Key_First, Key_Last);
                              Is_Target_Key :=
                                Matches_String
                                  (Existing, Key_First, Key_Last, Key);
                           end;
                        end if;
                     end;
                  end if;

                  if Is_Target_Key and then not Key_Written then
                     Store_String (New_Line_Text, Updated, Cursor);
                     Key_Written := True;
                  else
                     Updated (Cursor .. Cursor + (Line_Last - Line_First)) :=
                       Existing (Line_First .. Line_Last);
                     Cursor := Cursor + (Line_Last - Line_First) + 1;
                  end if;
               end;
            end loop;

            if Section_Found and then not Key_Written then
               if Cursor > Updated'First
                 and then Updated (Cursor - 1) /=
                   Stream_Element (Character'Pos (Character'Val (10)))
               then
                  Updated (Cursor) :=
                    Stream_Element (Character'Pos (Character'Val (10)));
                  Cursor := Cursor + 1;
               end if;
               Store_String (New_Line_Text, Updated, Cursor);
            elsif not Section_Found then
               if Cursor > Updated'First
                 and then Updated (Cursor - 1) /=
                   Stream_Element (Character'Pos (Character'Val (10)))
               then
                  Updated (Cursor) :=
                    Stream_Element (Character'Pos (Character'Val (10)));
                  Cursor := Cursor + 1;
               end if;
               Store_String (Section_Text, Updated, Cursor);
               Store_String (New_Line_Text, Updated, Cursor);
            end if;

            Ada.Directories.Create_Path
              (Ada.Directories.Containing_Directory (Path));
            Stream_IO.Create (File, Stream_IO.Out_File, Path);
            if Cursor > Updated'First then
               Stream_IO.Write (File, Updated (Updated'First .. Cursor - 1));
            end if;
            Stream_IO.Close (File);
         end;
      end;
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Write_Failed;
   end Write_Config_Value;

   function Append_Config_Value
     (Repository_Root : String;
      Section         : String;
      Key             : String;
      Value           : String)
      return Status
   is
      Path      : constant String := Config_File_Path (Repository_Root);
      File      : Stream_IO.File_Type;
      File_Size : Stream_IO.Count := 0;

      function Clean_Name (Text : String) return Boolean is
      begin
         if Text'Length = 0 or else Text'Length > Maximum_Ref_Name_Length then
            return False;
         end if;
         for Ch of Text loop
            if Ch = Character'Val (0)
              or else Ch = Character'Val (10)
              or else Ch = Character'Val (13)
              or else Ch = '['
              or else Ch = ']'
              or else Ch = '='
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Clean_Name;

      function Clean_Value (Text : String) return Boolean is
      begin
         if Text'Length > Maximum_Pkt_Line_Payload_Length then
            return False;
         end if;
         for Ch of Text loop
            if Ch = Character'Val (0)
              or else Ch = Character'Val (10)
              or else Ch = Character'Val (13)
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Clean_Value;

      function Is_Space (Item : Stream_Element) return Boolean is
      begin
         return Item = Stream_Element (Character'Pos (' '))
           or else Item = Stream_Element (Character'Pos (Character'Val (9)));
      end Is_Space;

      function Matches_String
        (Data  : Stream_Element_Array;
         First : Stream_Element_Offset;
         Last_Value : Stream_Element_Offset;
         Text  : String)
         return Boolean
      is
      begin
         if Last_Value < First then
            return Text'Length = 0;
         elsif Last_Value - First + 1 /= Stream_Element_Offset (Text'Length) then
            return False;
         end if;
         for Index in Text'Range loop
            if Data (First + Stream_Element_Offset (Index - Text'First))
              /= Stream_Element (Character'Pos (Text (Index)))
            then
               return False;
            end if;
         end loop;
         return True;
      end Matches_String;

      procedure Trim
        (Data : Stream_Element_Array;
         First : in out Stream_Element_Offset;
         Last_Value : in out Stream_Element_Offset)
      is
      begin
         while First <= Last_Value and then Is_Space (Data (First)) loop
            First := First + 1;
         end loop;
         while Last_Value >= First and then Is_Space (Data (Last_Value)) loop
            Last_Value := Last_Value - 1;
         end loop;
      end Trim;

      procedure Store_String
        (Text : String;
         Target : in out Stream_Element_Array;
         Cursor : in out Stream_Element_Offset)
      is
      begin
         for Ch of Text loop
            Target (Cursor) := Stream_Element (Character'Pos (Ch));
            Cursor := Cursor + 1;
         end loop;
      end Store_String;
   begin
      if not Valid_Repository_Root (Repository_Root)
        or else not Clean_Name (Section)
        or else not Clean_Name (Key)
        or else not Clean_Value (Value)
      then
         return Invalid_Command;
      end if;

      if Ada.Directories.Exists (Path) then
         Stream_IO.Open (File, Stream_IO.In_File, Path);
         File_Size := Stream_IO.Size (File);
         if File_Size > Maximum_Config_File_Length then
            Stream_IO.Close (File);
            return Invalid_Command;
         end if;
      end if;

      declare
         Existing_Last : constant Stream_Element_Offset :=
           Stream_Element_Offset (File_Size);
         Existing : Stream_Element_Array (1 .. Existing_Last);
         File_Last : Stream_Element_Offset := 0;
      begin
         if File_Size > 0 then
            Stream_IO.Read (File, Existing, File_Last);
            Stream_IO.Close (File);
            if File_Last /= Existing'Last then
               return Read_Failed;
            end if;
         elsif Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;

         declare
            New_Line_Text : constant String :=
              Character'Val (9) & Key & " = " & Value & Character'Val (10);
            Section_Text : constant String :=
              "[" & Section & "]" & Character'Val (10);
            Extra_Length : constant Natural :=
              Section_Text'Length + New_Line_Text'Length + 1;
            Updated : Stream_Element_Array
              (1 .. Existing_Last + Stream_Element_Offset (Extra_Length));
            Cursor : Stream_Element_Offset := Updated'First;
            Read_Cursor : Stream_Element_Offset := Existing'First;
            In_Section : Boolean := False;
            Section_Found : Boolean := False;
            Value_Written : Boolean := False;
         begin
            while Read_Cursor <= Existing'Last loop
               declare
                  Line_First : constant Stream_Element_Offset := Read_Cursor;
                  Line_End   : Stream_Element_Offset := Read_Cursor;
                  Line_Last  : Stream_Element_Offset;
                  Trim_First : Stream_Element_Offset;
                  Trim_Last  : Stream_Element_Offset;
                  Is_Section_Header : Boolean := False;
                  Starts_New_Section : Boolean := False;
               begin
                  while Line_End <= Existing'Last
                    and then Existing (Line_End) /=
                      Stream_Element (Character'Pos (Character'Val (10)))
                  loop
                     Line_End := Line_End + 1;
                  end loop;
                  if Line_End <= Existing'Last then
                     Line_Last := Line_End;
                     Read_Cursor := Line_End + 1;
                  else
                     Line_Last := Existing'Last;
                     Read_Cursor := Existing'Last + 1;
                  end if;

                  Trim_First := Line_First;
                  Trim_Last :=
                    (if Existing (Line_Last) =
                       Stream_Element (Character'Pos (Character'Val (10)))
                     then Line_Last - 1
                     else Line_Last);
                  if Trim_Last >= Trim_First
                    and then Existing (Trim_Last) =
                      Stream_Element (Character'Pos (Character'Val (13)))
                  then
                     Trim_Last := Trim_Last - 1;
                  end if;
                  Trim (Existing, Trim_First, Trim_Last);

                  if Trim_Last >= Trim_First
                    and then Existing (Trim_First) =
                      Stream_Element (Character'Pos ('['))
                  then
                     Starts_New_Section := True;
                     if Existing (Trim_Last) /=
                       Stream_Element (Character'Pos (']'))
                       or else Trim_Last <= Trim_First + 1
                     then
                        return Invalid_Command;
                     end if;
                     declare
                        Name_First : Stream_Element_Offset := Trim_First + 1;
                        Name_Last  : Stream_Element_Offset := Trim_Last - 1;
                     begin
                        Trim (Existing, Name_First, Name_Last);
                        Is_Section_Header :=
                          Matches_String
                            (Existing, Name_First, Name_Last, Section);
                     end;
                  end if;

                  if In_Section
                    and then Starts_New_Section
                    and then not Value_Written
                  then
                     Store_String (New_Line_Text, Updated, Cursor);
                     Value_Written := True;
                  end if;

                  if Starts_New_Section then
                     In_Section := Is_Section_Header;
                     if In_Section then
                        Section_Found := True;
                     end if;
                  end if;

                  Updated (Cursor .. Cursor + (Line_Last - Line_First)) :=
                    Existing (Line_First .. Line_Last);
                  Cursor := Cursor + (Line_Last - Line_First) + 1;
               end;
            end loop;

            if Section_Found and then not Value_Written then
               if Cursor > Updated'First
                 and then Updated (Cursor - 1) /=
                   Stream_Element (Character'Pos (Character'Val (10)))
               then
                  Updated (Cursor) :=
                    Stream_Element (Character'Pos (Character'Val (10)));
                  Cursor := Cursor + 1;
               end if;
               Store_String (New_Line_Text, Updated, Cursor);
            elsif not Section_Found then
               if Cursor > Updated'First
                 and then Updated (Cursor - 1) /=
                   Stream_Element (Character'Pos (Character'Val (10)))
               then
                  Updated (Cursor) :=
                    Stream_Element (Character'Pos (Character'Val (10)));
                  Cursor := Cursor + 1;
               end if;
               Store_String (Section_Text, Updated, Cursor);
               Store_String (New_Line_Text, Updated, Cursor);
            end if;

            Ada.Directories.Create_Path
              (Ada.Directories.Containing_Directory (Path));
            Stream_IO.Create (File, Stream_IO.Out_File, Path);
            if Cursor > Updated'First then
               Stream_IO.Write (File, Updated (Updated'First .. Cursor - 1));
            end if;
            Stream_IO.Close (File);
         end;
      end;
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         return Write_Failed;
   end Append_Config_Value;

   function Delete_Config_Value
     (Repository_Root : String;
      Section         : String;
      Key             : String;
      Removed         : out Boolean)
      return Status
   is
      File      : Stream_IO.File_Type;
      File_Size : Stream_IO.Count := 0;
      Path      : constant String := Config_File_Path (Repository_Root);

      function Clean_Name (Text : String) return Boolean is
      begin
         if Text'Length = 0 or else Text'Length > Maximum_Ref_Name_Length then
            return False;
         end if;
         for Ch of Text loop
            if Ch = Character'Val (0)
              or else Ch = Character'Val (10)
              or else Ch = Character'Val (13)
              or else Ch = '['
              or else Ch = ']'
              or else Ch = '='
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Clean_Name;

      function Is_Space (Item : Stream_Element) return Boolean is
      begin
         return Item = Stream_Element (Character'Pos (' '))
           or else Item = Stream_Element (Character'Pos (Character'Val (9)));
      end Is_Space;

      function Matches_String
        (Data  : Stream_Element_Array;
         First : Stream_Element_Offset;
         Last_Value : Stream_Element_Offset;
         Text  : String)
         return Boolean
      is
      begin
         if Last_Value < First then
            return Text'Length = 0;
         elsif Last_Value - First + 1 /= Stream_Element_Offset (Text'Length) then
            return False;
         end if;
         for Index in Text'Range loop
            if Data (First + Stream_Element_Offset (Index - Text'First))
              /= Stream_Element (Character'Pos (Text (Index)))
            then
               return False;
            end if;
         end loop;
         return True;
      end Matches_String;

      procedure Trim
        (Data : Stream_Element_Array;
         First : in out Stream_Element_Offset;
         Last_Value : in out Stream_Element_Offset)
      is
      begin
         while First <= Last_Value and then Is_Space (Data (First)) loop
            First := First + 1;
         end loop;
         while Last_Value >= First and then Is_Space (Data (Last_Value)) loop
            Last_Value := Last_Value - 1;
         end loop;
      end Trim;
   begin
      Removed := False;
      if not Valid_Repository_Root (Repository_Root)
        or else not Clean_Name (Section)
        or else not Clean_Name (Key)
      then
         return Invalid_Command;
      end if;

      Stream_IO.Open (File, Stream_IO.In_File, Path);
      File_Size := Stream_IO.Size (File);
      if File_Size = 0 or else File_Size > Maximum_Config_File_Length then
         Stream_IO.Close (File);
         return Invalid_Command;
      end if;

      declare
         Existing : Stream_Element_Array
           (1 .. Stream_Element_Offset (File_Size));
         File_Last : Stream_Element_Offset;
      begin
         Stream_IO.Read (File, Existing, File_Last);
         Stream_IO.Close (File);
         if File_Last /= Existing'Last then
            return Read_Failed;
         end if;

         declare
            Updated : Stream_Element_Array (Existing'Range);
            Cursor : Stream_Element_Offset := Updated'First;
            Read_Cursor : Stream_Element_Offset := Existing'First;
            In_Section : Boolean := False;
         begin
            while Read_Cursor <= Existing'Last loop
               declare
                  Line_First : constant Stream_Element_Offset := Read_Cursor;
                  Line_End   : Stream_Element_Offset := Read_Cursor;
                  Line_Last  : Stream_Element_Offset;
                  Trim_First : Stream_Element_Offset;
                  Trim_Last  : Stream_Element_Offset;
                  Starts_New_Section : Boolean := False;
                  Is_Target_Key : Boolean := False;
               begin
                  while Line_End <= Existing'Last
                    and then Existing (Line_End) /=
                      Stream_Element (Character'Pos (Character'Val (10)))
                  loop
                     Line_End := Line_End + 1;
                  end loop;
                  if Line_End <= Existing'Last then
                     Line_Last := Line_End;
                     Read_Cursor := Line_End + 1;
                  else
                     Line_Last := Existing'Last;
                     Read_Cursor := Existing'Last + 1;
                  end if;

                  Trim_First := Line_First;
                  Trim_Last :=
                    (if Existing (Line_Last) =
                       Stream_Element (Character'Pos (Character'Val (10)))
                     then Line_Last - 1
                     else Line_Last);
                  if Trim_Last >= Trim_First
                    and then Existing (Trim_Last) =
                      Stream_Element (Character'Pos (Character'Val (13)))
                  then
                     Trim_Last := Trim_Last - 1;
                  end if;
                  Trim (Existing, Trim_First, Trim_Last);

                  if Trim_Last >= Trim_First
                    and then Existing (Trim_First) =
                      Stream_Element (Character'Pos ('['))
                  then
                     Starts_New_Section := True;
                     if Existing (Trim_Last) /=
                       Stream_Element (Character'Pos (']'))
                       or else Trim_Last <= Trim_First + 1
                     then
                        return Invalid_Command;
                     end if;
                     declare
                        Name_First : Stream_Element_Offset := Trim_First + 1;
                        Name_Last  : Stream_Element_Offset := Trim_Last - 1;
                     begin
                        Trim (Existing, Name_First, Name_Last);
                        In_Section :=
                          Matches_String
                            (Existing, Name_First, Name_Last, Section);
                     end;
                  elsif In_Section and then Trim_Last >= Trim_First then
                     if Existing (Trim_First) =
                       Stream_Element (Character'Pos ('#'))
                       or else Existing (Trim_First) =
                         Stream_Element (Character'Pos (';'))
                     then
                        null;
                     else
                        declare
                           Equals : Stream_Element_Offset := Trim_First;
                        begin
                           while Equals <= Trim_Last
                             and then Existing (Equals) /=
                               Stream_Element (Character'Pos ('='))
                           loop
                              Equals := Equals + 1;
                           end loop;
                           if Equals <= Trim_Last then
                              declare
                                 Key_First : Stream_Element_Offset :=
                                   Trim_First;
                                 Key_Last  : Stream_Element_Offset :=
                                   Equals - 1;
                              begin
                                 Trim (Existing, Key_First, Key_Last);
                                 Is_Target_Key :=
                                   Matches_String
                                     (Existing, Key_First, Key_Last, Key);
                              end;
                           else
                              return Invalid_Command;
                           end if;
                        end;
                     end if;
                  end if;

                  if Starts_New_Section or else not Is_Target_Key then
                     Updated (Cursor .. Cursor + (Line_Last - Line_First)) :=
                       Existing (Line_First .. Line_Last);
                     Cursor := Cursor + (Line_Last - Line_First) + 1;
                  else
                     Removed := True;
                  end if;
               end;
            end loop;

            if Removed then
               Stream_IO.Create (File, Stream_IO.Out_File, Path);
               if Cursor > Updated'First then
                  Stream_IO.Write (File, Updated (Updated'First .. Cursor - 1));
               end if;
               Stream_IO.Close (File);
            end if;
         end;
      end;
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Removed := False;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Removed := False;
         return Read_Failed;
   end Delete_Config_Value;

   function Valid_Config_Component (Text : String) return Boolean is
   begin
      if Text'Length = 0 or else Text'Length > Maximum_Ref_Name_Length then
         return False;
      end if;
      for Ch of Text loop
         if Ch = Character'Val (0)
           or else Ch = Character'Val (10)
           or else Ch = Character'Val (13)
           or else Ch = '['
           or else Ch = ']'
           or else Ch = '='
           or else Ch = Character'Val (9)
         then
            return False;
         end if;
      end loop;
      return True;
   exception
      when others =>
         return False;
   end Valid_Config_Component;

   function Valid_Config_Value_Text (Text : String) return Boolean is
   begin
      if Text'Length = 0 or else Text'Length > Maximum_Ref_Name_Length then
         return False;
      end if;

      for Ch of Text loop
         if Ch = Character'Val (0)
           or else Ch = Character'Val (10)
           or else Ch = Character'Val (13)
         then
            return False;
         end if;
      end loop;
      return True;
   exception
      when others =>
         return False;
   end Valid_Config_Value_Text;

   function Write_Remote_URL
     (Repository_Root : String;
      Remote_Name     : String;
      URL             : String)
      return Status
   is
   begin
      if not Valid_Config_Component (Remote_Name) then
         return Invalid_Command;
      end if;
      return
        Write_Config_Value
          (Repository_Root, "remote " & Remote_Name, "url", URL);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_Remote_URL;

   function Read_Remote_URL
     (Repository_Root : String;
      Remote_Name     : String;
      URL             : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
   begin
      Found := False;
      Last := URL'First - 1;
      if not Valid_Config_Component (Remote_Name) then
         return Invalid_Command;
      end if;
      return
        Read_Config_Value
          (Repository_Root, "remote " & Remote_Name, "url", URL, Last, Found);
   exception
      when Constraint_Error =>
         Found := False;
         Last := URL'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Last := URL'First - 1;
         return Read_Failed;
   end Read_Remote_URL;

   function Delete_Remote_URL
     (Repository_Root : String;
      Remote_Name     : String;
      Removed         : out Boolean)
      return Status
   is
   begin
      Removed := False;
      if not Valid_Config_Component (Remote_Name) then
         return Invalid_Command;
      end if;
      return
        Delete_Config_Value
          (Repository_Root, "remote " & Remote_Name, "url", Removed);
   exception
      when Constraint_Error =>
         Removed := False;
         return Invalid_Command;
      when others =>
         Removed := False;
         return Write_Failed;
   end Delete_Remote_URL;

   function Write_Remote_Fetch_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : String)
      return Status
   is
   begin
      if not Valid_Config_Component (Remote_Name)
        or else not Valid_Fetch_Refspec (RefSpec)
      then
         return Invalid_Command;
      end if;
      return
        Write_Config_Value
          (Repository_Root, "remote " & Remote_Name, "fetch", RefSpec);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_Remote_Fetch_Refspec;

   function Read_Remote_Fetch_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
   begin
      Found := False;
      Last := RefSpec'First - 1;
      if not Valid_Config_Component (Remote_Name) then
         return Invalid_Command;
      end if;
      return
        Read_Config_Value
          (Repository_Root,
           "remote " & Remote_Name,
           "fetch",
           RefSpec,
           Last,
           Found);
   exception
      when Constraint_Error =>
         Found := False;
         Last := RefSpec'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Last := RefSpec'First - 1;
         return Read_Failed;
   end Read_Remote_Fetch_Refspec;

   function Append_Remote_Fetch_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : String)
      return Status
   is
   begin
      if not Valid_Config_Component (Remote_Name)
        or else not Valid_Fetch_Refspec (RefSpec)
      then
         return Invalid_Command;
      end if;
      return
        Append_Config_Value
          (Repository_Root, "remote " & Remote_Name, "fetch", RefSpec);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Append_Remote_Fetch_Refspec;

   function Read_Remote_Fetch_Refspecs
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpecs        : out Stream_Element_Array;
      RefSpec_Lasts   : out Config_Value_Last_Array;
      Count           : out Natural)
      return Status
   is
   begin
      Count := 0;
      for Index in RefSpec_Lasts'Range loop
         RefSpec_Lasts (Index) := RefSpecs'First - 1;
      end loop;
      if not Valid_Config_Component (Remote_Name) then
         return Invalid_Command;
      end if;
      return
        Read_Config_Values
          (Repository_Root,
           "remote " & Remote_Name,
           "fetch",
           RefSpecs,
           RefSpec_Lasts,
           Count);
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Read_Failed;
   end Read_Remote_Fetch_Refspecs;

   function Delete_Remote_Fetch_Refspecs
     (Repository_Root : String;
      Remote_Name     : String;
      Removed         : out Boolean)
      return Status
   is
   begin
      Removed := False;
      if not Valid_Config_Component (Remote_Name) then
         return Invalid_Command;
      end if;
      return
        Delete_Config_Value
          (Repository_Root, "remote " & Remote_Name, "fetch", Removed);
   exception
      when Constraint_Error =>
         Removed := False;
         return Invalid_Command;
      when others =>
         Removed := False;
         return Write_Failed;
   end Delete_Remote_Fetch_Refspecs;

   function Write_Remote_Push_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : String)
      return Status
   is
   begin
      if not Valid_Config_Component (Remote_Name)
        or else not Valid_Push_Refspec (RefSpec)
      then
         return Invalid_Command;
      end if;
      return
        Write_Config_Value
          (Repository_Root, "remote " & Remote_Name, "push", RefSpec);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_Remote_Push_Refspec;

   function Read_Remote_Push_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
   begin
      Found := False;
      Last := RefSpec'First - 1;
      if not Valid_Config_Component (Remote_Name) then
         return Invalid_Command;
      end if;
      return
        Read_Config_Value
          (Repository_Root,
           "remote " & Remote_Name,
           "push",
           RefSpec,
           Last,
           Found);
   exception
      when Constraint_Error =>
         Found := False;
         Last := RefSpec'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Last := RefSpec'First - 1;
         return Read_Failed;
   end Read_Remote_Push_Refspec;

   function Append_Remote_Push_Refspec
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpec         : String)
      return Status
   is
   begin
      if not Valid_Config_Component (Remote_Name)
        or else not Valid_Push_Refspec (RefSpec)
      then
         return Invalid_Command;
      end if;
      return
        Append_Config_Value
          (Repository_Root, "remote " & Remote_Name, "push", RefSpec);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Append_Remote_Push_Refspec;

   function Read_Remote_Push_Refspecs
     (Repository_Root : String;
      Remote_Name     : String;
      RefSpecs        : out Stream_Element_Array;
      RefSpec_Lasts   : out Config_Value_Last_Array;
      Count           : out Natural)
      return Status
   is
   begin
      Count := 0;
      for Index in RefSpec_Lasts'Range loop
         RefSpec_Lasts (Index) := RefSpecs'First - 1;
      end loop;
      if not Valid_Config_Component (Remote_Name) then
         return Invalid_Command;
      end if;
      return
        Read_Config_Values
          (Repository_Root,
           "remote " & Remote_Name,
           "push",
           RefSpecs,
           RefSpec_Lasts,
           Count);
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Read_Failed;
   end Read_Remote_Push_Refspecs;

   function Delete_Remote_Push_Refspecs
     (Repository_Root : String;
      Remote_Name     : String;
      Removed         : out Boolean)
      return Status
   is
   begin
      Removed := False;
      if not Valid_Config_Component (Remote_Name) then
         return Invalid_Command;
      end if;
      return
        Delete_Config_Value
          (Repository_Root, "remote " & Remote_Name, "push", Removed);
   exception
      when Constraint_Error =>
         Removed := False;
         return Invalid_Command;
      when others =>
         Removed := False;
         return Write_Failed;
   end Delete_Remote_Push_Refspecs;

   function Write_Credential_Helper
     (Repository_Root : String;
      Helper          : String)
      return Status
   is
   begin
      if not Valid_Config_Value_Text (Helper) then
         return Invalid_Command;
      end if;
      return
        Write_Config_Value
          (Repository_Root, "credential", "helper", Helper);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_Credential_Helper;

   function Read_Credential_Helper
     (Repository_Root : String;
      Helper          : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
   begin
      Found := False;
      Last := Helper'First - 1;
      return
        Read_Config_Value
          (Repository_Root,
           "credential",
           "helper",
           Helper,
           Last,
           Found);
   exception
      when Constraint_Error =>
         Found := False;
         Last := Helper'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Last := Helper'First - 1;
         return Read_Failed;
   end Read_Credential_Helper;

   function Append_Credential_Helper
     (Repository_Root : String;
      Helper          : String)
      return Status
   is
   begin
      if not Valid_Config_Value_Text (Helper) then
         return Invalid_Command;
      end if;
      return
        Append_Config_Value
          (Repository_Root, "credential", "helper", Helper);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Append_Credential_Helper;

   function Read_Credential_Helpers
     (Repository_Root : String;
      Helpers         : out Stream_Element_Array;
      Lasts           : out Config_Value_Last_Array;
      Count           : out Natural)
      return Status
   is
   begin
      Count := 0;
      return
        Read_Config_Values
          (Repository_Root,
           "credential",
           "helper",
           Helpers,
           Lasts,
           Count);
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Read_Failed;
   end Read_Credential_Helpers;

   function Delete_Credential_Helper
     (Repository_Root : String;
      Removed         : out Boolean)
      return Status
   is
   begin
      Removed := False;
      return
        Delete_Config_Value
          (Repository_Root, "credential", "helper", Removed);
   exception
      when Constraint_Error =>
         Removed := False;
         return Invalid_Command;
      when others =>
         Removed := False;
         return Write_Failed;
   end Delete_Credential_Helper;

   function Write_Credential_Username
     (Repository_Root : String;
      Username        : String)
      return Status
   is
   begin
      if not Valid_Config_Value_Text (Username) then
         return Invalid_Command;
      end if;
      return
        Write_Config_Value
          (Repository_Root, "credential", "username", Username);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_Credential_Username;

   function Read_Credential_Username
     (Repository_Root : String;
      Username        : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
   begin
      Found := False;
      Last := Username'First - 1;
      return
        Read_Config_Value
          (Repository_Root,
           "credential",
           "username",
           Username,
           Last,
           Found);
   exception
      when Constraint_Error =>
         Found := False;
         Last := Username'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Last := Username'First - 1;
         return Read_Failed;
   end Read_Credential_Username;

   function Delete_Credential_Username
     (Repository_Root : String;
      Removed         : out Boolean)
      return Status
   is
   begin
      Removed := False;
      return
        Delete_Config_Value
          (Repository_Root, "credential", "username", Removed);
   exception
      when Constraint_Error =>
         Removed := False;
         return Invalid_Command;
      when others =>
         Removed := False;
         return Write_Failed;
   end Delete_Credential_Username;

   function Build_Credential_Helper_Request
     (Protocol : String;
      Host     : String;
      Path     : String;
      Username : String;
      Password : String;
      Data     : out Stream_Element_Array;
      Last     : out Stream_Element_Offset)
      return Status
   is
      Cursor : Stream_Element_Offset := Data'First;

      function Valid_Field (Text : String) return Boolean is
      begin
         for Ch of Text loop
            if Ch = Character'Val (0)
              or else Ch = Character'Val (10)
              or else Ch = Character'Val (13)
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Valid_Field;

      procedure Append_Line
        (Key    : String;
         Value  : String;
         Result : out Status)
      is
      begin
         Result := Ok;
         if Value'Length = 0 then
            return;
         elsif Cursor + Stream_Element_Offset
           (Key'Length + 1 + Value'Length) > Data'Last
         then
            Result := Read_Failed;
            return;
         end if;

         for Ch of Key loop
            Data (Cursor) := Character'Pos (Ch);
            Cursor := Cursor + 1;
         end loop;
         Data (Cursor) := Character'Pos ('=');
         Cursor := Cursor + 1;
         for Ch of Value loop
            Data (Cursor) := Character'Pos (Ch);
            Cursor := Cursor + 1;
         end loop;
         Data (Cursor) := Character'Pos (Character'Val (10));
         Cursor := Cursor + 1;
      end Append_Line;

      Status_Value : Status := Ok;
   begin
      Last := Data'First - 1;
      if not Valid_Field (Protocol)
        or else not Valid_Field (Host)
        or else not Valid_Field (Path)
        or else not Valid_Field (Username)
        or else not Valid_Field (Password)
      then
         return Invalid_Command;
      end if;

      Append_Line ("protocol", Protocol, Status_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Append_Line ("host", Host, Status_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Append_Line ("path", Path, Status_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Append_Line ("username", Username, Status_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Append_Line ("password", Password, Status_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Cursor > Data'Last then
         return Read_Failed;
      end if;
      Data (Cursor) := Character'Pos (Character'Val (10));
      Last := Cursor;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Data'First - 1;
         return Invalid_Command;
      when others =>
         Last := Data'First - 1;
         return Internal_Error;
   end Build_Credential_Helper_Request;

   function Parse_Credential_Helper_Response
     (Data         : Stream_Element_Array;
      Username     : out Stream_Element_Array;
      Username_Last : out Stream_Element_Offset;
      Has_Username : out Boolean;
      Password     : out Stream_Element_Array;
      Password_Last : out Stream_Element_Offset;
      Has_Password : out Boolean)
      return Status
   is
      Cursor : Stream_Element_Offset := Data'First;

      function Key_Matches
        (First : Stream_Element_Offset;
         Last_Key : Stream_Element_Offset;
         Text : String) return Boolean
      is
      begin
         if Last_Key < First
           or else Last_Key - First + 1 /= Stream_Element_Offset (Text'Length)
         then
            return False;
         end if;
         for Index in Text'Range loop
            if Data (First + Stream_Element_Offset (Index - Text'First))
              /= Character'Pos (Text (Index))
            then
               return False;
            end if;
         end loop;
         return True;
      end Key_Matches;

      procedure Copy_Value
        (Value_First : Stream_Element_Offset;
         Value_Last  : Stream_Element_Offset;
         Target      : in out Stream_Element_Array;
         Target_Last : out Stream_Element_Offset;
         Result      : out Status)
      is
         Length : constant Stream_Element_Offset :=
           Value_Last - Value_First + 1;
      begin
         Result := Ok;
         Target_Last := Target'First - 1;
         if Value_Last < Value_First then
            return;
         elsif Length > Target'Length then
            Result := Read_Failed;
            return;
         end if;

         Target (Target'First .. Target'First + Length - 1) :=
           Data (Value_First .. Value_Last);
         Target_Last := Target'First + Length - 1;
      end Copy_Value;

      Status_Value : Status := Ok;
   begin
      Username_Last := Username'First - 1;
      Password_Last := Password'First - 1;
      Has_Username := False;
      Has_Password := False;

      while Cursor <= Data'Last loop
         declare
            Line_First : constant Stream_Element_Offset := Cursor;
            Equal_Pos  : Stream_Element_Offset := Data'First - 1;
            LF_Pos     : Stream_Element_Offset := Data'First - 1;
         begin
            while Cursor <= Data'Last loop
               if Data (Cursor) = Character'Pos (Character'Val (10)) then
                  LF_Pos := Cursor;
                  exit;
               elsif Data (Cursor) = Character'Pos (Character'Val (0))
                 or else Data (Cursor) = Character'Pos (Character'Val (13))
               then
                  return Invalid_Command;
               elsif Data (Cursor) = Character'Pos ('=')
                 and then Equal_Pos < Data'First
               then
                  Equal_Pos := Cursor;
               end if;
               Cursor := Cursor + 1;
            end loop;

            if LF_Pos < Data'First then
               return Invalid_Command;
            elsif LF_Pos = Line_First then
               return Ok;
            elsif Equal_Pos <= Line_First or else Equal_Pos > LF_Pos then
               return Invalid_Command;
            elsif Key_Matches (Line_First, Equal_Pos - 1, "username") then
               Copy_Value
                 (Equal_Pos + 1,
                  LF_Pos - 1,
                  Username,
                  Username_Last,
                  Status_Value);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Has_Username := True;
            elsif Key_Matches (Line_First, Equal_Pos - 1, "password") then
               Copy_Value
                 (Equal_Pos + 1,
                  LF_Pos - 1,
                  Password,
                  Password_Last,
                  Status_Value);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Has_Password := True;
            end if;

            Cursor := LF_Pos + 1;
         end;
      end loop;

      return Invalid_Command;
   exception
      when Constraint_Error =>
         Username_Last := Username'First - 1;
         Password_Last := Password'First - 1;
         Has_Username := False;
         Has_Password := False;
         return Invalid_Command;
      when others =>
         Username_Last := Username'First - 1;
         Password_Last := Password'First - 1;
         Has_Username := False;
         Has_Password := False;
         return Internal_Error;
   end Parse_Credential_Helper_Response;

   function Wait_For_Helper_FD
     (FD         : GNAT.OS_Lib.File_Descriptor;
      For_Write  : Boolean;
      Timeout_MS : Natural) return Status
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
            return Write_Failed;
         end if;
         return Read_Failed;
      end if;

      if Timeout_MS = 0 then
         Poll_Timeout := -1;
      else
         Poll_Timeout := Interfaces.C.int (Timeout_MS);
      end if;

      Result := C_Poll (Poll_Item'Access, 1, Poll_Timeout);
      if Result > 0 then
         return Ok;
      elsif Result = 0 then
         return Timeout;
      elsif For_Write then
         return Write_Failed;
      else
         return Read_Failed;
      end if;
   exception
      when others =>
         if For_Write then
            return Write_Failed;
         end if;
         return Read_Failed;
   end Wait_For_Helper_FD;

   function Execute_Credential_Helper
     (Helper_Command : String;
      Protocol       : String;
      Host           : String;
      Path           : String;
      Username       : String;
      Password       : String;
      Timeout_MS     : Natural;
      Out_Username   : out Stream_Element_Array;
      Username_Last  : out Stream_Element_Offset;
      Has_Username   : out Boolean;
      Out_Password   : out Stream_Element_Array;
      Password_Last  : out Stream_Element_Offset;
      Has_Password   : out Boolean)
      return Status
   is
      Shell_Name   : constant String :=
        (if GNAT.OS_Lib.Directory_Separator = '\' then "cmd.exe" else "sh");
      Shell_Switch : constant String :=
        (if GNAT.OS_Lib.Directory_Separator = '\' then "/C" else "-c");
      Shell_Path   : GNAT.OS_Lib.String_Access :=
        GNAT.OS_Lib.Locate_Exec_On_Path (Shell_Name);
      Arg_1        : aliased String := Shell_Switch;
      Arg_2        : aliased String := Helper_Command;
      Args         : constant GNAT.OS_Lib.Argument_List (1 .. 2) :=
        [Arg_1'Unchecked_Access, Arg_2'Unchecked_Access];
      Process      : GNAT.Expect.Process_Descriptor;
      Request      : Stream_Element_Array (1 .. 4096);
      Request_Last : Stream_Element_Offset;
      Response     : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Credential_Helper_Output_Length));
      Response_Last : Stream_Element_Offset := Response'First - 1;
      Status_Value : Status;
      Child_Status : Integer := 0;

      procedure Close_Helper is
      begin
         GNAT.Expect.Close (Process, Child_Status);
      exception
         when others =>
            null;
      end Close_Helper;
   begin
      Username_Last := Out_Username'First - 1;
      Password_Last := Out_Password'First - 1;
      Has_Username := False;
      Has_Password := False;

      if Helper_Command'Length = 0 then
         return Invalid_Command;
      elsif Shell_Path = null then
         return Unsupported_Feature;
      end if;

      Status_Value :=
        Build_Credential_Helper_Request
          (Protocol,
           Host,
           Path,
           Username,
           Password,
           Request,
           Request_Last);
      if Status_Value /= Ok then
         GNAT.OS_Lib.Free (Shell_Path);
         return Status_Value;
      end if;

      GNAT.Expect.Non_Blocking_Spawn
        (Process,
         Shell_Path.all,
         Args,
         Buffer_Size => 0,
         Err_To_Out  => False);
      GNAT.OS_Lib.Free (Shell_Path);

      declare
         Input_FD : constant GNAT.OS_Lib.File_Descriptor :=
           GNAT.Expect.Get_Input_Fd (Process);
         First_Index : Stream_Element_Offset := Request'First;
      begin
         while First_Index <= Request_Last loop
            declare
               Ready_Status : constant Status :=
                 Wait_For_Helper_FD (Input_FD, True, Timeout_MS);
               Remaining : constant Stream_Element_Offset :=
                 Request_Last - First_Index + 1;
               Written : Integer;
            begin
               if Ready_Status /= Ok then
                  Close_Helper;
                  return Ready_Status;
               end if;
               Written :=
                 GNAT.OS_Lib.Write
                   (Input_FD,
                    Request (First_Index)'Address,
                    Integer (Remaining));
               if Written <= 0 then
                  Close_Helper;
                  return Write_Failed;
               end if;
               First_Index := First_Index + Stream_Element_Offset (Written);
            end;
         end loop;
      end;

      declare
         Output_FD : constant GNAT.OS_Lib.File_Descriptor :=
           GNAT.Expect.Get_Output_Fd (Process);
         Byte      : Stream_Element := 0;
         Count     : Integer;
      begin
         loop
            Status_Value := Wait_For_Helper_FD (Output_FD, False, Timeout_MS);
            if Status_Value /= Ok then
               Close_Helper;
               return Status_Value;
            end if;

            Count := GNAT.OS_Lib.Read (Output_FD, Byte'Address, 1);
            if Count = 0 then
               exit;
            elsif Count < 0 then
               Close_Helper;
               return Read_Failed;
            elsif Response_Last = Response'Last then
               Close_Helper;
               return Read_Failed;
            end if;

            Response_Last := Response_Last + 1;
            Response (Response_Last) := Byte;
            exit when Response_Last > Response'First
              and then Response (Response_Last) =
                Character'Pos (Character'Val (10))
              and then Response (Response_Last - 1) =
                Character'Pos (Character'Val (10));
         end loop;
      end;

      Close_Helper;
      if Response_Last < Response'First then
         return Invalid_Command;
      end if;

      return
        Parse_Credential_Helper_Response
          (Response (Response'First .. Response_Last),
           Out_Username,
           Username_Last,
           Has_Username,
           Out_Password,
           Password_Last,
           Has_Password);
   exception
      when GNAT.Expect.Invalid_Process =>
         if Shell_Path /= null then
            GNAT.OS_Lib.Free (Shell_Path);
         end if;
         Username_Last := Out_Username'First - 1;
         Password_Last := Out_Password'First - 1;
         Has_Username := False;
         Has_Password := False;
         return Connection_Failed;
      when Constraint_Error =>
         if Shell_Path /= null then
            GNAT.OS_Lib.Free (Shell_Path);
         end if;
         Username_Last := Out_Username'First - 1;
         Password_Last := Out_Password'First - 1;
         Has_Username := False;
         Has_Password := False;
         return Invalid_Command;
      when others =>
         if Shell_Path /= null then
            GNAT.OS_Lib.Free (Shell_Path);
         end if;
         Username_Last := Out_Username'First - 1;
         Password_Last := Out_Password'First - 1;
         Has_Username := False;
         Has_Password := False;
         return Internal_Error;
   end Execute_Credential_Helper;

   function Build_Credential_Password_Prompt
     (Protocol : String;
      Host     : String;
      Path     : String;
      Username : String;
      Prompt   : out Stream_Element_Array;
      Last     : out Stream_Element_Offset)
      return Status
   is
      Cursor : Stream_Element_Offset := Prompt'First;

      function Valid_Field (Text : String) return Boolean is
      begin
         for Ch of Text loop
            if Ch = Character'Val (0)
              or else Ch = Character'Val (10)
              or else Ch = Character'Val (13)
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Valid_Field;

      procedure Append_Text (Text : String; Result : out Status) is
      begin
         Result := Ok;
         if Text'Length = 0 then
            return;
         elsif Cursor + Stream_Element_Offset (Text'Length) - 1
           > Prompt'Last
         then
            Result := Read_Failed;
            return;
         end if;

         for Ch of Text loop
            Prompt (Cursor) := Character'Pos (Ch);
            Cursor := Cursor + 1;
         end loop;
      end Append_Text;

      Status_Value : Status := Ok;
   begin
      Last := Prompt'First - 1;
      if not Valid_Field (Protocol)
        or else not Valid_Field (Host)
        or else not Valid_Field (Path)
        or else not Valid_Field (Username)
        or else Host'Length = 0
      then
         return Invalid_Command;
      end if;

      Append_Text ("Password for '", Status_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if Protocol'Length > 0 then
         Append_Text (Protocol & "://", Status_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end if;
      if Username'Length > 0 then
         Append_Text (Username & "@", Status_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end if;
      Append_Text (Host, Status_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if Path'Length > 0 then
         Append_Text ("/" & Path, Status_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end if;
      Append_Text ("': ", Status_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Last := Cursor - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Prompt'First - 1;
         return Invalid_Command;
      when others =>
         Last := Prompt'First - 1;
         return Internal_Error;
   end Build_Credential_Password_Prompt;

   function Prompt_Credential_Password
     (Protocol : String;
      Host     : String;
      Path     : String;
      Username : String;
      Password : out Stream_Element_Array;
      Last     : out Stream_Element_Offset)
      return Status
   is
      Prompt : Stream_Element_Array (1 .. 1024);
      Prompt_Last : Stream_Element_Offset;
      Line : String (1 .. Natural (Password'Length));
      Line_Last : Natural := 0;
      Status_Value : Status;
   begin
      Last := Password'First - 1;
      Status_Value :=
        Build_Credential_Password_Prompt
          (Protocol, Host, Path, Username, Prompt, Prompt_Last);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Password'Length = 0 then
         return Read_Failed;
      end if;

      for Index in Prompt'First .. Prompt_Last loop
         Ada.Text_IO.Put (Character'Val (Prompt (Index)));
      end loop;
      Ada.Text_IO.Get_Line (Line, Line_Last);

      if Line_Last = 0 then
         Last := Password'First - 1;
         return Ok;
      elsif Stream_Element_Offset (Line_Last) > Password'Length then
         Last := Password'First - 1;
         return Read_Failed;
      end if;

      for Index in 1 .. Line_Last loop
         Password (Password'First + Stream_Element_Offset (Index - 1)) :=
           Character'Pos (Line (Index));
      end loop;
      Last := Password'First + Stream_Element_Offset (Line_Last) - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Password'First - 1;
         return Invalid_Command;
      when others =>
         Last := Password'First - 1;
         return Read_Failed;
   end Prompt_Credential_Password;

   function Credential_Store_Path (Repository_Root : String) return String is
   begin
      return Git_Path (Repository_Root, "credentials");
   end Credential_Store_Path;

   function Valid_Credential_Field (Text : String) return Boolean is
   begin
      for Ch of Text loop
         if Ch = Character'Val (0)
           or else Ch = Character'Val (10)
           or else Ch = Character'Val (13)
         then
            return False;
         end if;
      end loop;
      return True;
   exception
      when others =>
         return False;
   end Valid_Credential_Field;

   function Credential_Record_Matches
     (Data     : Stream_Element_Array;
      Protocol : String;
      Host     : String;
      Path     : String;
      Username : String) return Boolean
   is
      Has_Protocol : Boolean := False;
      Has_Host     : Boolean := False;
      Has_Path     : Boolean := Path'Length = 0;
      Has_Username : Boolean := False;
      Cursor       : Stream_Element_Offset := Data'First;

      function Field_Matches
        (Line_First : Stream_Element_Offset;
         Equal_Pos  : Stream_Element_Offset;
         LF_Pos     : Stream_Element_Offset;
         Key        : String;
         Value      : String) return Boolean
      is
      begin
         if Equal_Pos - Line_First /= Stream_Element_Offset (Key'Length)
           or else LF_Pos - Equal_Pos - 1 /=
             Stream_Element_Offset (Value'Length)
         then
            return False;
         end if;

         for Index in Key'Range loop
            if Data (Line_First + Stream_Element_Offset (Index - Key'First))
              /= Character'Pos (Key (Index))
            then
               return False;
            end if;
         end loop;

         for Index in Value'Range loop
            if Data
              (Equal_Pos + 1 + Stream_Element_Offset (Index - Value'First))
              /= Character'Pos (Value (Index))
            then
               return False;
            end if;
         end loop;
         return True;
      end Field_Matches;
   begin
      while Cursor <= Data'Last loop
         declare
            Line_First : constant Stream_Element_Offset := Cursor;
            Equal_Pos  : Stream_Element_Offset := Data'First - 1;
            LF_Pos     : Stream_Element_Offset := Data'First - 1;
         begin
            while Cursor <= Data'Last loop
               if Data (Cursor) = Character'Pos (Character'Val (10)) then
                  LF_Pos := Cursor;
                  exit;
               elsif Data (Cursor) = Character'Pos ('=')
                 and then Equal_Pos < Data'First
               then
                  Equal_Pos := Cursor;
               end if;
               Cursor := Cursor + 1;
            end loop;

            if LF_Pos < Data'First then
               return False;
            elsif LF_Pos = Line_First then
               exit;
            elsif Equal_Pos <= Line_First or else Equal_Pos >= LF_Pos then
               return False;
            elsif Field_Matches
              (Line_First, Equal_Pos, LF_Pos, "protocol", Protocol)
            then
               Has_Protocol := True;
            elsif Field_Matches (Line_First, Equal_Pos, LF_Pos, "host", Host)
            then
               Has_Host := True;
            elsif Field_Matches (Line_First, Equal_Pos, LF_Pos, "path", Path)
            then
               Has_Path := True;
            elsif Field_Matches
              (Line_First, Equal_Pos, LF_Pos, "username", Username)
            then
               Has_Username := True;
            end if;
            Cursor := LF_Pos + 1;
         end;
      end loop;

      return Has_Protocol and then Has_Host and then Has_Path
        and then Has_Username;
   exception
      when others =>
         return False;
   end Credential_Record_Matches;

   function Read_Credential_Store_File
     (Repository_Root : String;
      Data            : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Exists          : out Boolean) return Status
   is
      File      : Stream_IO.File_Type;
      Path_Name : constant String := Credential_Store_Path (Repository_Root);
      Size      : Ada.Directories.File_Size;
   begin
      Last := Data'First - 1;
      Exists := False;
      if not Valid_Repository_Root (Repository_Root) then
         return Invalid_Command;
      elsif not Ada.Directories.Exists (Path_Name) then
         return Ok;
      end if;

      Size := Ada.Directories.Size (Path_Name);
      if Size = 0 then
         Exists := True;
         return Ok;
      elsif Stream_IO.Count (Size) > Maximum_Config_File_Length
        or else Stream_Element_Offset (Size) > Data'Length
      then
         return Read_Failed;
      end if;

      Stream_IO.Open (File, Stream_IO.In_File, Path_Name);
      Stream_IO.Read (File, Data, Last);
      Stream_IO.Close (File);
      Exists := True;
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Last := Data'First - 1;
         Exists := False;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Last := Data'First - 1;
         Exists := False;
         return Read_Failed;
   end Read_Credential_Store_File;

   function Rewrite_Credential_Store
     (Repository_Root : String;
      Protocol        : String;
      Host            : String;
      Path            : String;
      Username        : String;
      New_Record      : Stream_Element_Array;
      Append_New      : Boolean;
      Removed         : out Boolean) return Status
   is
      Existing : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Config_File_Length));
      Existing_Last : Stream_Element_Offset;
      Existing_Found : Boolean := False;
      Output : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Config_File_Length));
      Output_Last : Stream_Element_Offset := Output'First - 1;
      Cursor : Stream_Element_Offset;
      Status_Value : Status;
      File : Stream_IO.File_Type;
      Store_Path : constant String := Credential_Store_Path (Repository_Root);

      procedure Append_Bytes
        (Bytes  : Stream_Element_Array;
         Result : out Status)
      is
      begin
         Result := Ok;
         if Bytes'Length = 0 then
            return;
         elsif Output_Last + Bytes'Length > Output'Last then
            Result := Write_Failed;
            return;
         end if;
         Output (Output_Last + 1 .. Output_Last + Bytes'Length) := Bytes;
         Output_Last := Output_Last + Bytes'Length;
      end Append_Bytes;
   begin
      Removed := False;
      Status_Value :=
        Read_Credential_Store_File
          (Repository_Root, Existing, Existing_Last, Existing_Found);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Existing_Found and then Existing_Last >= Existing'First then
         Cursor := Existing'First;
         while Cursor <= Existing_Last loop
            declare
               Record_First : constant Stream_Element_Offset := Cursor;
               Record_Last  : Stream_Element_Offset := Existing_Last;
            begin
               while Cursor <= Existing_Last loop
                  if Existing (Cursor) =
                    Character'Pos (Character'Val (10))
                    and then Cursor > Existing'First
                    and then Existing (Cursor - 1) =
                      Character'Pos (Character'Val (10))
                  then
                     Record_Last := Cursor;
                     Cursor := Cursor + 1;
                     exit;
                  end if;
                  Cursor := Cursor + 1;
               end loop;

               if Credential_Record_Matches
                 (Existing (Record_First .. Record_Last),
                  Protocol,
                  Host,
                  Path,
                  Username)
               then
                  Removed := True;
               else
                  Append_Bytes
                    (Existing (Record_First .. Record_Last), Status_Value);
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;
                  if Output_Last < Output'First
                    or else Output (Output_Last) /=
                      Character'Pos (Character'Val (10))
                  then
                     Append_Bytes
                       ([1 => Character'Pos (Character'Val (10))],
                        Status_Value);
                     if Status_Value /= Ok then
                        return Status_Value;
                     end if;
                  end if;
               end if;
            end;
         end loop;
      end if;

      if Append_New then
         Append_Bytes (New_Record, Status_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end if;

      Ada.Directories.Create_Path
        (Ada.Directories.Containing_Directory (Store_Path));
      Stream_IO.Create (File, Stream_IO.Out_File, Store_Path);
      if Output_Last >= Output'First then
         Stream_IO.Write (File, Output (Output'First .. Output_Last));
      end if;
      Stream_IO.Close (File);
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Removed := False;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Removed := False;
         return Write_Failed;
   end Rewrite_Credential_Store;

   function Write_Credential_Store
     (Repository_Root : String;
      Protocol        : String;
      Host            : String;
      Path            : String;
      Username        : String;
      Password        : String)
      return Status
   is
      Record_Data : Stream_Element_Array (1 .. 4096);
      Record_Last : Stream_Element_Offset;
      Removed : Boolean := False;
      Status_Value : Status;
   begin
      if not Valid_Repository_Root (Repository_Root)
        or else Protocol'Length = 0
        or else Host'Length = 0
        or else Username'Length = 0
        or else not Valid_Credential_Field (Protocol)
        or else not Valid_Credential_Field (Host)
        or else not Valid_Credential_Field (Path)
        or else not Valid_Credential_Field (Username)
        or else not Valid_Credential_Field (Password)
      then
         return Invalid_Command;
      end if;

      Status_Value :=
        Build_Credential_Helper_Request
          (Protocol, Host, Path, Username, Password, Record_Data, Record_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      return
        Rewrite_Credential_Store
          (Repository_Root,
           Protocol,
           Host,
           Path,
           Username,
           Record_Data (Record_Data'First .. Record_Last),
           True,
           Removed);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_Credential_Store;

   function Read_Credential_Store
     (Repository_Root : String;
      Protocol        : String;
      Host            : String;
      Path            : String;
      Username        : String;
      Password        : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
      Existing : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Config_File_Length));
      Existing_Last : Stream_Element_Offset;
      Existing_Found : Boolean := False;
      Cursor : Stream_Element_Offset;
      Status_Value : Status;
      Dummy_Username : Stream_Element_Array (1 .. 1024);
      Dummy_Username_Last : Stream_Element_Offset;
      Has_Username_Value : Boolean;
   begin
      Last := Password'First - 1;
      Found := False;
      if not Valid_Repository_Root (Repository_Root)
        or else Protocol'Length = 0
        or else Host'Length = 0
        or else Username'Length = 0
        or else not Valid_Credential_Field (Protocol)
        or else not Valid_Credential_Field (Host)
        or else not Valid_Credential_Field (Path)
        or else not Valid_Credential_Field (Username)
      then
         return Invalid_Command;
      end if;

      Status_Value :=
        Read_Credential_Store_File
          (Repository_Root, Existing, Existing_Last, Existing_Found);
      if Status_Value /= Ok then
         return Status_Value;
      elsif not Existing_Found or else Existing_Last < Existing'First then
         return Ok;
      end if;

      Cursor := Existing'First;
      while Cursor <= Existing_Last loop
         declare
            Record_First : constant Stream_Element_Offset := Cursor;
            Record_Last  : Stream_Element_Offset := Existing_Last;
         begin
            while Cursor <= Existing_Last loop
               if Existing (Cursor) = Character'Pos (Character'Val (10))
                 and then Cursor > Existing'First
                 and then Existing (Cursor - 1) =
                   Character'Pos (Character'Val (10))
               then
                  Record_Last := Cursor;
                  Cursor := Cursor + 1;
                  exit;
               end if;
               Cursor := Cursor + 1;
            end loop;

            if Credential_Record_Matches
              (Existing (Record_First .. Record_Last),
               Protocol,
               Host,
               Path,
               Username)
            then
               Status_Value :=
                 Parse_Credential_Helper_Response
                   (Existing (Record_First .. Record_Last),
                    Dummy_Username,
                    Dummy_Username_Last,
                    Has_Username_Value,
                    Password,
                    Last,
                    Found);
               if Status_Value /= Ok then
                  Found := False;
                  Last := Password'First - 1;
                  return Status_Value;
               end if;
               return Ok;
            end if;
         end;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         Found := False;
         Last := Password'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Last := Password'First - 1;
         return Read_Failed;
   end Read_Credential_Store;

   function Delete_Credential_Store
     (Repository_Root : String;
      Protocol        : String;
      Host            : String;
      Path            : String;
      Username        : String;
      Removed         : out Boolean)
      return Status
   is
      Empty_Record : constant Stream_Element_Array (1 .. 1) := [1 => 0];
   begin
      Removed := False;
      if not Valid_Repository_Root (Repository_Root)
        or else Protocol'Length = 0
        or else Host'Length = 0
        or else Username'Length = 0
        or else not Valid_Credential_Field (Protocol)
        or else not Valid_Credential_Field (Host)
        or else not Valid_Credential_Field (Path)
        or else not Valid_Credential_Field (Username)
      then
         return Invalid_Command;
      end if;

      return
        Rewrite_Credential_Store
          (Repository_Root,
           Protocol,
           Host,
           Path,
           Username,
           Empty_Record,
           False,
           Removed);
   exception
      when Constraint_Error =>
         Removed := False;
         return Invalid_Command;
      when others =>
         Removed := False;
         return Write_Failed;
   end Delete_Credential_Store;

   procedure Clear_Credential_Data
     (Data : in out Stream_Element_Array)
   is
   begin
      Data := [others => 0];
   end Clear_Credential_Data;

   function Write_Core_Bare
     (Repository_Root : String;
      Is_Bare         : Boolean)
      return Status
   is
   begin
      if Is_Bare then
         return Write_Config_Value (Repository_Root, "core", "bare", "true");
      else
         return Write_Config_Value (Repository_Root, "core", "bare", "false");
      end if;
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_Core_Bare;

   function Read_Core_Bare
     (Repository_Root : String;
      Is_Bare         : out Boolean;
      Found           : out Boolean)
      return Status
   is
      Value : Stream_Element_Array (1 .. 16);
      Last  : Stream_Element_Offset := 0;
      Status_Value : Status;
   begin
      Is_Bare := False;
      Found := False;

      Status_Value :=
        Read_Config_Value
          (Repository_Root, "core", "bare", Value, Last, Found);

      if Status_Value /= Ok or else not Found then
         return Status_Value;
      end if;

      if Last = Value'First + 3
        and then Value (Value'First) = Character'Pos ('t')
        and then Value (Value'First + 1) = Character'Pos ('r')
        and then Value (Value'First + 2) = Character'Pos ('u')
        and then Value (Value'First + 3) = Character'Pos ('e')
      then
         Is_Bare := True;
         return Ok;
      elsif Last = Value'First + 4
        and then Value (Value'First) = Character'Pos ('f')
        and then Value (Value'First + 1) = Character'Pos ('a')
        and then Value (Value'First + 2) = Character'Pos ('l')
        and then Value (Value'First + 3) = Character'Pos ('s')
        and then Value (Value'First + 4) = Character'Pos ('e')
      then
         Is_Bare := False;
         return Ok;
      else
         Found := False;
         return Invalid_Command;
      end if;
   exception
      when Constraint_Error =>
         Is_Bare := False;
         Found := False;
         return Invalid_Command;
      when others =>
         Is_Bare := False;
         Found := False;
         return Read_Failed;
   end Read_Core_Bare;

   function Delete_Core_Bare
     (Repository_Root : String;
      Removed         : out Boolean)
      return Status
   is
   begin
      Removed := False;
      return Delete_Config_Value (Repository_Root, "core", "bare", Removed);
   exception
      when Constraint_Error =>
         Removed := False;
         return Invalid_Command;
      when others =>
         Removed := False;
         return Write_Failed;
   end Delete_Core_Bare;

   function Write_Core_Filemode
     (Repository_Root : String;
      Filemode        : Boolean)
      return Status
   is
   begin
      if Filemode then
         return Write_Config_Value (Repository_Root, "core", "filemode", "true");
      else
         return Write_Config_Value (Repository_Root, "core", "filemode", "false");
      end if;
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_Core_Filemode;

   function Read_Core_Filemode
     (Repository_Root : String;
      Filemode        : out Boolean;
      Found           : out Boolean)
      return Status
   is
      Value : Stream_Element_Array (1 .. 16);
      Last  : Stream_Element_Offset := 0;
      Status_Value : Status;
   begin
      Filemode := False;
      Found := False;

      Status_Value :=
        Read_Config_Value
          (Repository_Root, "core", "filemode", Value, Last, Found);

      if Status_Value /= Ok or else not Found then
         return Status_Value;
      end if;

      if Last = Value'First + 3
        and then Value (Value'First) = Character'Pos ('t')
        and then Value (Value'First + 1) = Character'Pos ('r')
        and then Value (Value'First + 2) = Character'Pos ('u')
        and then Value (Value'First + 3) = Character'Pos ('e')
      then
         Filemode := True;
         return Ok;
      elsif Last = Value'First + 4
        and then Value (Value'First) = Character'Pos ('f')
        and then Value (Value'First + 1) = Character'Pos ('a')
        and then Value (Value'First + 2) = Character'Pos ('l')
        and then Value (Value'First + 3) = Character'Pos ('s')
        and then Value (Value'First + 4) = Character'Pos ('e')
      then
         Filemode := False;
         return Ok;
      else
         Found := False;
         return Invalid_Command;
      end if;
   exception
      when Constraint_Error =>
         Filemode := False;
         Found := False;
         return Invalid_Command;
      when others =>
         Filemode := False;
         Found := False;
         return Read_Failed;
   end Read_Core_Filemode;

   function Delete_Core_Filemode
     (Repository_Root : String;
      Removed         : out Boolean)
      return Status
   is
   begin
      Removed := False;
      return Delete_Config_Value (Repository_Root, "core", "filemode", Removed);
   exception
      when Constraint_Error =>
         Removed := False;
         return Invalid_Command;
      when others =>
         Removed := False;
         return Write_Failed;
   end Delete_Core_Filemode;

   function Write_Core_Log_All_Ref_Updates
     (Repository_Root      : String;
      Log_All_Ref_Updates : Boolean)
      return Status
   is
   begin
      if Log_All_Ref_Updates then
         return
           Write_Config_Value
             (Repository_Root, "core", "logAllRefUpdates", "true");
      else
         return
           Write_Config_Value
             (Repository_Root, "core", "logAllRefUpdates", "false");
      end if;
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_Core_Log_All_Ref_Updates;

   function Read_Core_Log_All_Ref_Updates
     (Repository_Root      : String;
      Log_All_Ref_Updates : out Boolean;
      Found                : out Boolean)
      return Status
   is
      Value : Stream_Element_Array (1 .. 16);
      Last  : Stream_Element_Offset := 0;
      Status_Value : Status;
   begin
      Log_All_Ref_Updates := False;
      Found := False;

      Status_Value :=
        Read_Config_Value
          (Repository_Root, "core", "logAllRefUpdates", Value, Last, Found);

      if Status_Value /= Ok or else not Found then
         return Status_Value;
      end if;

      if Last = Value'First + 3
        and then Value (Value'First) = Character'Pos ('t')
        and then Value (Value'First + 1) = Character'Pos ('r')
        and then Value (Value'First + 2) = Character'Pos ('u')
        and then Value (Value'First + 3) = Character'Pos ('e')
      then
         Log_All_Ref_Updates := True;
         return Ok;
      elsif Last = Value'First + 4
        and then Value (Value'First) = Character'Pos ('f')
        and then Value (Value'First + 1) = Character'Pos ('a')
        and then Value (Value'First + 2) = Character'Pos ('l')
        and then Value (Value'First + 3) = Character'Pos ('s')
        and then Value (Value'First + 4) = Character'Pos ('e')
      then
         Log_All_Ref_Updates := False;
         return Ok;
      else
         Found := False;
         return Invalid_Command;
      end if;
   exception
      when Constraint_Error =>
         Log_All_Ref_Updates := False;
         Found := False;
         return Invalid_Command;
      when others =>
         Log_All_Ref_Updates := False;
         Found := False;
         return Read_Failed;
   end Read_Core_Log_All_Ref_Updates;

   function Delete_Core_Log_All_Ref_Updates
     (Repository_Root : String;
      Removed         : out Boolean)
      return Status
   is
   begin
      Removed := False;
      return
        Delete_Config_Value
          (Repository_Root, "core", "logAllRefUpdates", Removed);
   exception
      when Constraint_Error =>
         Removed := False;
         return Invalid_Command;
      when others =>
         Removed := False;
         return Write_Failed;
   end Delete_Core_Log_All_Ref_Updates;

   function Write_User_Name
     (Repository_Root : String;
      User_Name       : String)
      return Status
   is
   begin
      if not Valid_Config_Value_Text (User_Name) then
         return Invalid_Command;
      end if;
      return Write_Config_Value (Repository_Root, "user", "name", User_Name);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_User_Name;

   function Read_User_Name
     (Repository_Root : String;
      User_Name       : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
   begin
      Found := False;
      Last := User_Name'First - 1;
      return
        Read_Config_Value
          (Repository_Root, "user", "name", User_Name, Last, Found);
   exception
      when Constraint_Error =>
         Found := False;
         Last := User_Name'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Last := User_Name'First - 1;
         return Read_Failed;
   end Read_User_Name;

   function Delete_User_Name
     (Repository_Root : String;
      Removed         : out Boolean)
      return Status
   is
   begin
      Removed := False;
      return Delete_Config_Value (Repository_Root, "user", "name", Removed);
   exception
      when Constraint_Error =>
         Removed := False;
         return Invalid_Command;
      when others =>
         Removed := False;
         return Write_Failed;
   end Delete_User_Name;

   function Write_User_Email
     (Repository_Root : String;
      User_Email      : String)
      return Status
   is
   begin
      if not Valid_Config_Value_Text (User_Email) then
         return Invalid_Command;
      end if;
      return Write_Config_Value (Repository_Root, "user", "email", User_Email);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_User_Email;

   function Read_User_Email
     (Repository_Root : String;
      User_Email      : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
   begin
      Found := False;
      Last := User_Email'First - 1;
      return
        Read_Config_Value
          (Repository_Root, "user", "email", User_Email, Last, Found);
   exception
      when Constraint_Error =>
         Found := False;
         Last := User_Email'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Last := User_Email'First - 1;
         return Read_Failed;
   end Read_User_Email;

   function Delete_User_Email
     (Repository_Root : String;
      Removed         : out Boolean)
      return Status
   is
   begin
      Removed := False;
      return Delete_Config_Value (Repository_Root, "user", "email", Removed);
   exception
      when Constraint_Error =>
         Removed := False;
         return Invalid_Command;
      when others =>
         Removed := False;
         return Write_Failed;
   end Delete_User_Email;

   function Write_Init_Default_Branch
     (Repository_Root : String;
      Branch_Name     : String)
      return Status
   is
   begin
      if Branch_Name'Length = 0
        or else Branch_Name'Length > Maximum_Ref_Name_Length
        or else not Valid_Ref_Name ("refs/heads/" & Branch_Name)
      then
         return Invalid_Command;
      end if;
      return
        Write_Config_Value
          (Repository_Root, "init", "defaultBranch", Branch_Name);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_Init_Default_Branch;

   function Read_Init_Default_Branch
     (Repository_Root : String;
      Branch_Name     : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
   begin
      Found := False;
      Last := Branch_Name'First - 1;
      return
        Read_Config_Value
          (Repository_Root,
           "init",
           "defaultBranch",
           Branch_Name,
           Last,
           Found);
   exception
      when Constraint_Error =>
         Found := False;
         Last := Branch_Name'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Last := Branch_Name'First - 1;
         return Read_Failed;
   end Read_Init_Default_Branch;

   function Delete_Init_Default_Branch
     (Repository_Root : String;
      Removed         : out Boolean)
      return Status
   is
   begin
      Removed := False;
      return
        Delete_Config_Value
          (Repository_Root, "init", "defaultBranch", Removed);
   exception
      when Constraint_Error =>
         Removed := False;
         return Invalid_Command;
      when others =>
         Removed := False;
         return Write_Failed;
   end Delete_Init_Default_Branch;

   function Write_Push_Default
     (Repository_Root : String;
      Mode            : String)
      return Status
   is
   begin
      if not Valid_Push_Default_Mode (Mode) then
         return Invalid_Command;
      end if;
      return Write_Config_Value (Repository_Root, "push", "default", Mode);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_Push_Default;

   function Read_Push_Default
     (Repository_Root : String;
      Mode            : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
   begin
      Found := False;
      Last := Mode'First - 1;
      return
        Read_Config_Value
          (Repository_Root, "push", "default", Mode, Last, Found);
   exception
      when Constraint_Error =>
         Found := False;
         Last := Mode'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Last := Mode'First - 1;
         return Read_Failed;
   end Read_Push_Default;

   function Delete_Push_Default
     (Repository_Root : String;
      Removed         : out Boolean)
      return Status
   is
   begin
      Removed := False;
      return Delete_Config_Value (Repository_Root, "push", "default", Removed);
   exception
      when Constraint_Error =>
         Removed := False;
         return Invalid_Command;
      when others =>
         Removed := False;
         return Write_Failed;
   end Delete_Push_Default;

   function Write_Pull_Rebase
     (Repository_Root : String;
      Mode            : String)
      return Status
   is
   begin
      if not Valid_Pull_Rebase_Mode (Mode) then
         return Invalid_Command;
      end if;
      return Write_Config_Value (Repository_Root, "pull", "rebase", Mode);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_Pull_Rebase;

   function Read_Pull_Rebase
     (Repository_Root : String;
      Mode            : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
   begin
      Found := False;
      Last := Mode'First - 1;
      return
        Read_Config_Value
          (Repository_Root, "pull", "rebase", Mode, Last, Found);
   exception
      when Constraint_Error =>
         Found := False;
         Last := Mode'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Last := Mode'First - 1;
         return Read_Failed;
   end Read_Pull_Rebase;

   function Delete_Pull_Rebase
     (Repository_Root : String;
      Removed         : out Boolean)
      return Status
   is
   begin
      Removed := False;
      return Delete_Config_Value (Repository_Root, "pull", "rebase", Removed);
   exception
      when Constraint_Error =>
         Removed := False;
         return Invalid_Command;
      when others =>
         Removed := False;
         return Write_Failed;
   end Delete_Pull_Rebase;

   function Write_Branch_Upstream
     (Repository_Root : String;
      Branch_Name     : String;
      Remote_Name     : String;
      Merge_Ref_Name  : String)
      return Status
   is
      Status_Value : Status;
   begin
      if not Valid_Branch_Name (Branch_Name)
        or else not Valid_Config_Component (Remote_Name)
        or else not Valid_Ref_Name (Merge_Ref_Name)
      then
         return Invalid_Command;
      end if;

      Status_Value :=
        Write_Config_Value
          (Repository_Root, "branch " & Branch_Name, "remote", Remote_Name);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      return
        Write_Config_Value
          (Repository_Root, "branch " & Branch_Name, "merge", Merge_Ref_Name);
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Write_Failed;
   end Write_Branch_Upstream;

   function Read_Branch_Upstream
     (Repository_Root : String;
      Branch_Name     : String;
      Remote_Name     : out Stream_Element_Array;
      Remote_Last     : out Stream_Element_Offset;
      Merge_Ref_Name  : out Stream_Element_Array;
      Merge_Last      : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
      Remote_Found : Boolean := False;
      Merge_Found  : Boolean := False;
      Status_Value : Status;
   begin
      Found := False;
      Remote_Last := Remote_Name'First - 1;
      Merge_Last := Merge_Ref_Name'First - 1;
      if not Valid_Branch_Name (Branch_Name) then
         return Invalid_Command;
      end if;

      Status_Value :=
        Read_Config_Value
          (Repository_Root,
           "branch " & Branch_Name,
           "remote",
           Remote_Name,
           Remote_Last,
           Remote_Found);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Read_Config_Value
          (Repository_Root,
           "branch " & Branch_Name,
           "merge",
           Merge_Ref_Name,
           Merge_Last,
           Merge_Found);
      if Status_Value /= Ok then
         Found := False;
         Remote_Last := Remote_Name'First - 1;
         Merge_Last := Merge_Ref_Name'First - 1;
         return Status_Value;
      end if;

      Found := Remote_Found and then Merge_Found;
      if not Found then
         Remote_Last := Remote_Name'First - 1;
         Merge_Last := Merge_Ref_Name'First - 1;
      end if;
      return Ok;
   exception
      when Constraint_Error =>
         Found := False;
         Remote_Last := Remote_Name'First - 1;
         Merge_Last := Merge_Ref_Name'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Remote_Last := Remote_Name'First - 1;
         Merge_Last := Merge_Ref_Name'First - 1;
         return Read_Failed;
   end Read_Branch_Upstream;

   function Delete_Branch_Upstream
     (Repository_Root : String;
      Branch_Name     : String;
      Removed         : out Boolean)
      return Status
   is
      Remote_Removed : Boolean := False;
      Merge_Removed  : Boolean := False;
      Status_Value   : Status;
   begin
      Removed := False;
      if not Valid_Branch_Name (Branch_Name) then
         return Invalid_Command;
      end if;

      Status_Value :=
        Delete_Config_Value
          (Repository_Root, "branch " & Branch_Name, "remote", Remote_Removed);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Delete_Config_Value
          (Repository_Root, "branch " & Branch_Name, "merge", Merge_Removed);
      if Status_Value /= Ok then
         Removed := False;
         return Status_Value;
      end if;
      Removed := Remote_Removed or else Merge_Removed;
      return Ok;
   exception
      when Constraint_Error =>
         Removed := False;
         return Invalid_Command;
      when others =>
         Removed := False;
         return Write_Failed;
   end Delete_Branch_Upstream;

   function Ref_Exists
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : out Stream_Element_Array;
      Last            : out Stream_Element_Offset;
      Found           : out Boolean)
      return Status
   is
      Status_Value : Status;
   begin
      Found := False;
      Last := Object_ID_Hex'First - 1;
      Status_Value :=
        Resolve_Ref (Repository_Root, Ref_Name, Object_ID_Hex, Last);
      if Status_Value = Ok then
         Found := True;
         return Ok;
      elsif Status_Value = Read_Failed then
         Found := False;
         Last := Object_ID_Hex'First - 1;
         return Ok;
      end if;
      return Status_Value;
   exception
      when Constraint_Error =>
         Found := False;
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Found := False;
         Last := Object_ID_Hex'First - 1;
         return Read_Failed;
   end Ref_Exists;

   function Write_Locked_Direct_Ref
     (Repository_Root        : String;
      Ref_Name               : String;
      Object_ID_Hex          : Stream_Element_Array;
      Expected_Object_ID_Hex : Stream_Element_Array;
      Check_Expected         : Boolean)
      return Status
   is
      Raw_ID       : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last     : Stream_Element_Offset;
      Current_Hex  : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Current_Last : Stream_Element_Offset;
      Status_Value : Status;
      File         : Stream_IO.File_Type;
      Path         : constant String := Ref_File_Path (Repository_Root, Ref_Name);
      Lock_Path    : constant String := Path & ".lock";
      Renamed      : Boolean := False;
      Data         : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length + 1));
      Lock_Created : Boolean := False;
   begin
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Ref_Name (Ref_Name)
      then
         return Invalid_Command;
      end if;

      Status_Value := Parse_Object_ID_Hex (Object_ID_Hex, Raw_ID, Raw_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if Check_Expected then
         Status_Value :=
           Parse_Object_ID_Hex (Expected_Object_ID_Hex, Raw_ID, Raw_Last);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end if;

      for Index in 0 .. Object_ID_SHA1_Hex_Length - 1 loop
         Data (Data'First + Stream_Element_Offset (Index)) :=
           Object_ID_Hex (Object_ID_Hex'First + Stream_Element_Offset (Index));
      end loop;
      Data (Data'Last) := Stream_Element (Character'Pos (Character'Val (10)));

      if Ref_Name /= "HEAD" then
         Ada.Directories.Create_Path (Ada.Directories.Containing_Directory (Path));
      end if;
      if Ada.Directories.Exists (Lock_Path) then
         return Write_Failed;
      end if;

      Stream_IO.Create (File, Stream_IO.Out_File, Lock_Path);
      Lock_Created := True;

      if Check_Expected then
         Status_Value :=
           Resolve_Ref (Repository_Root, Ref_Name, Current_Hex, Current_Last);
         if Status_Value /= Ok then
            Stream_IO.Close (File);
            if Ada.Directories.Exists (Lock_Path) then
               Ada.Directories.Delete_File (Lock_Path);
            end if;
            return Status_Value;
         elsif Current_Last /= Current_Hex'Last
           or else Current_Hex /= Expected_Object_ID_Hex
         then
            Stream_IO.Close (File);
            if Ada.Directories.Exists (Lock_Path) then
               Ada.Directories.Delete_File (Lock_Path);
            end if;
            return Invalid_Command;
         end if;
      end if;

      Stream_IO.Write (File, Data);
      Stream_IO.Close (File);
      GNAT.OS_Lib.Rename_File (Lock_Path, Path, Renamed);
      if not Renamed then
         if Ada.Directories.Exists (Lock_Path) then
            Ada.Directories.Delete_File (Lock_Path);
         end if;
         return Write_Failed;
      end if;
      Lock_Created := False;
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         if Lock_Created and then Ada.Directories.Exists (Lock_Path) then
            Ada.Directories.Delete_File (Lock_Path);
         end if;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         if Lock_Created and then Ada.Directories.Exists (Lock_Path) then
            Ada.Directories.Delete_File (Lock_Path);
         end if;
         return Write_Failed;
   end Write_Locked_Direct_Ref;

   function Delete_Locked_Direct_Ref
     (Repository_Root        : String;
      Ref_Name               : String;
      Expected_Object_ID_Hex : Stream_Element_Array;
      Check_Expected         : Boolean)
      return Status
   is
      Raw_ID       : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last     : Stream_Element_Offset;
      Current_Hex  : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Current_Last : Stream_Element_Offset;
      Status_Value : Status;
      Path         : constant String := Ref_File_Path (Repository_Root, Ref_Name);
      Lock_Path    : constant String := Path & ".lock";
      File         : Stream_IO.File_Type;
      Lock_Created : Boolean := False;
   begin
      if not Valid_Repository_Root (Repository_Root)
        or else not Valid_Ref_Name (Ref_Name)
      then
         return Invalid_Command;
      end if;

      if Check_Expected then
         Status_Value :=
           Parse_Object_ID_Hex (Expected_Object_ID_Hex, Raw_ID, Raw_Last);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end if;

      if Ref_Name /= "HEAD" then
         Ada.Directories.Create_Path (Ada.Directories.Containing_Directory (Path));
      end if;
      if Ada.Directories.Exists (Lock_Path) then
         return Write_Failed;
      end if;

      Stream_IO.Create (File, Stream_IO.Out_File, Lock_Path);
      Stream_IO.Close (File);
      Lock_Created := True;

      if Check_Expected then
         Status_Value :=
           Resolve_Ref (Repository_Root, Ref_Name, Current_Hex, Current_Last);
         if Status_Value /= Ok then
            if Ada.Directories.Exists (Lock_Path) then
               Ada.Directories.Delete_File (Lock_Path);
            end if;
            return Status_Value;
         elsif Current_Last /= Current_Hex'Last
           or else Current_Hex /= Expected_Object_ID_Hex
         then
            if Ada.Directories.Exists (Lock_Path) then
               Ada.Directories.Delete_File (Lock_Path);
            end if;
            return Invalid_Command;
         end if;
      end if;

      Status_Value := Delete_Direct_Ref (Repository_Root, Ref_Name);
      if Status_Value /= Ok then
         if Ada.Directories.Exists (Lock_Path) then
            Ada.Directories.Delete_File (Lock_Path);
         end if;
         return Status_Value;
      end if;

      if Ada.Directories.Exists (Lock_Path) then
         Ada.Directories.Delete_File (Lock_Path);
      end if;
      Lock_Created := False;
      return Ok;
   exception
      when Constraint_Error =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         if Lock_Created and then Ada.Directories.Exists (Lock_Path) then
            Ada.Directories.Delete_File (Lock_Path);
         end if;
         return Invalid_Command;
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         if Lock_Created and then Ada.Directories.Exists (Lock_Path) then
            Ada.Directories.Delete_File (Lock_Path);
         end if;
         return Write_Failed;
   end Delete_Locked_Direct_Ref;

   function Write_Direct_Ref_Atomic
     (Repository_Root : String;
      Ref_Name        : String;
      Object_ID_Hex   : Stream_Element_Array)
      return Status
   is
      Empty_Expected : Stream_Element_Array (1 .. 0);
   begin
      return Write_Locked_Direct_Ref
        (Repository_Root,
         Ref_Name,
         Object_ID_Hex,
         Empty_Expected,
         Check_Expected => False);
   end Write_Direct_Ref_Atomic;

   function Compare_And_Swap_Direct_Ref
     (Repository_Root        : String;
      Ref_Name               : String;
      Expected_Object_ID_Hex : Stream_Element_Array;
      New_Object_ID_Hex      : Stream_Element_Array)
      return Status
   is
   begin
      return Write_Locked_Direct_Ref
        (Repository_Root,
         Ref_Name,
         New_Object_ID_Hex,
         Expected_Object_ID_Hex,
         Check_Expected => True);
   end Compare_And_Swap_Direct_Ref;

   function Delete_Direct_Ref_Atomic
     (Repository_Root : String;
      Ref_Name        : String)
      return Status
   is
      Empty_Expected : Stream_Element_Array (1 .. 0);
   begin
      return Delete_Locked_Direct_Ref
        (Repository_Root,
         Ref_Name,
         Empty_Expected,
         Check_Expected => False);
   end Delete_Direct_Ref_Atomic;

   function Compare_And_Delete_Direct_Ref
     (Repository_Root        : String;
      Ref_Name               : String;
      Expected_Object_ID_Hex : Stream_Element_Array)
      return Status
   is
   begin
      return Delete_Locked_Direct_Ref
        (Repository_Root,
         Ref_Name,
         Expected_Object_ID_Hex,
         Check_Expected => True);
   end Compare_And_Delete_Direct_Ref;

   function Parse_Pkt_Line_Header
     (Data          : Stream_Element_Array;
      Kind          : out Pkt_Line_Kind;
      Packet_Length : out Natural)
      return Status
   is
      Length_Value : Natural := 0;
      Nibble       : Natural;
   begin
      Kind := Pkt_Data;
      Packet_Length := 0;

      if Data'Length < 4 then
         return Read_Failed;
      end if;

      for Offset in 0 .. 3 loop
         Nibble := Hex_Value (Data (Data'First + Stream_Element_Offset (Offset)));
         if Nibble > 15 then
            return Invalid_Command;
         end if;
         Length_Value := Length_Value * 16 + Nibble;
      end loop;

      Packet_Length := Length_Value;
      case Length_Value is
         when 0 =>
            Kind := Pkt_Flush;
            return Ok;
         when 1 =>
            Kind := Pkt_Delimiter;
            return Ok;
         when 2 =>
            Kind := Pkt_Response_End;
            return Ok;
         when 3 =>
            return Invalid_Command;
         when others =>
            Kind := Pkt_Data;
            if Length_Value > Maximum_Pkt_Line_Length then
               return Invalid_Command;
            elsif Data'Length < Stream_Element_Offset (Length_Value) then
               return Read_Failed;
            end if;
            return Ok;
      end case;
   exception
      when Constraint_Error =>
         Kind := Pkt_Data;
         Packet_Length := 0;
         return Read_Failed;
      when others =>
         Kind := Pkt_Data;
         Packet_Length := 0;
         return Internal_Error;
   end Parse_Pkt_Line_Header;

   function Copy_Pkt_Line_Payload
     (Data    : Stream_Element_Array;
      Payload : out Stream_Element_Array;
      Last    : out Stream_Element_Offset)
      return Status
   is
      Kind_Value    : Pkt_Line_Kind;
      Packet_Length : Natural;
      Payload_Length : Natural;
      Status_Value : Status;
   begin
      Last := Payload'First - 1;
      Status_Value :=
        Parse_Pkt_Line_Header (Data, Kind_Value, Packet_Length);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Kind_Value /= Pkt_Data then
         return Ok;
      end if;

      Payload_Length := Packet_Length - 4;
      if Payload_Length = 0 then
         return Ok;
      elsif Payload'Length < Stream_Element_Offset (Payload_Length) then
         return Read_Failed;
      end if;

      for Offset in 0 .. Payload_Length - 1 loop
         Payload (Payload'First + Stream_Element_Offset (Offset)) :=
           Data (Data'First + 4 + Stream_Element_Offset (Offset));
      end loop;
      Last := Payload'First + Stream_Element_Offset (Payload_Length) - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Payload'First - 1;
         return Read_Failed;
      when others =>
         Last := Payload'First - 1;
         return Internal_Error;
   end Copy_Pkt_Line_Payload;

   procedure Reset_Pkt_Line_Cursor
     (Data   : Stream_Element_Array;
      Cursor : out Pkt_Line_Cursor)
   is
   begin
      Cursor :=
        (Position           => Data'First,
         Packet_Count       => 0,
         Data_Count         => 0,
         Flush_Count        => 0,
         Delimiter_Count    => 0,
         Response_End_Count => 0,
         At_End             => Data'Length = 0);
   end Reset_Pkt_Line_Cursor;

   function Next_Pkt_Line
     (Data          : Stream_Element_Array;
      Cursor        : in out Pkt_Line_Cursor;
      Kind          : out Pkt_Line_Kind;
      Packet_First  : out Stream_Element_Offset;
      Packet_Last   : out Stream_Element_Offset;
      Payload_First : out Stream_Element_Offset;
      Payload_Last  : out Stream_Element_Offset)
      return Status
   is
      Packet_Length : Natural := 0;
      Status_Value  : Status;
      Next_Position : Stream_Element_Offset;
   begin
      Kind := Pkt_Data;
      Packet_First := Cursor.Position;
      Packet_Last := Cursor.Position - 1;
      Payload_First := Cursor.Position + 4;
      Payload_Last := Cursor.Position + 3;

      if Cursor.At_End
        or else Data'Length = 0
        or else Cursor.Position < Data'First
        or else Cursor.Position > Data'Last
      then
         Cursor.At_End := True;
         return End_Of_Stream;
      end if;

      Status_Value :=
        Parse_Pkt_Line_Header (Data (Cursor.Position .. Data'Last),
                               Kind,
                               Packet_Length);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Packet_First := Cursor.Position;
      case Kind is
         when Pkt_Data =>
            Packet_Last :=
              Cursor.Position + Stream_Element_Offset (Packet_Length) - 1;
            if Packet_Last > Data'Last then
               return Read_Failed;
            end if;
            Payload_First := Cursor.Position + 4;
            Payload_Last := Packet_Last;
            Next_Position := Packet_Last + 1;
            Cursor.Data_Count := Cursor.Data_Count + 1;
         when Pkt_Flush | Pkt_Delimiter | Pkt_Response_End =>
            Packet_Last := Cursor.Position + 3;
            if Packet_Last > Data'Last then
               return Read_Failed;
            end if;
            Payload_First := Cursor.Position + 4;
            Payload_Last := Payload_First - 1;
            Next_Position := Cursor.Position + 4;

            case Kind is
               when Pkt_Flush =>
                  Cursor.Flush_Count := Cursor.Flush_Count + 1;
               when Pkt_Delimiter =>
                  Cursor.Delimiter_Count := Cursor.Delimiter_Count + 1;
               when Pkt_Response_End =>
                  Cursor.Response_End_Count := Cursor.Response_End_Count + 1;
               when Pkt_Data =>
                  null;
            end case;
      end case;

      Cursor.Packet_Count := Cursor.Packet_Count + 1;
      Cursor.Position := Next_Position;
      Cursor.At_End := Cursor.Position > Data'Last;
      return Ok;
   exception
      when Constraint_Error =>
         return Read_Failed;
      when others =>
         return Internal_Error;
   end Next_Pkt_Line;

   function Pkt_Line_Cursor_Done
     (Cursor : Pkt_Line_Cursor)
      return Boolean
   is
   begin
      return Cursor.At_End;
   end Pkt_Line_Cursor_Done;

   function Encode_Pkt_Line
     (Payload : Stream_Element_Array)
      return Packet_Buffer
   is
      Result : Packet_Buffer;
      Packet_Length : constant Natural := Natural (Payload'Length) + 4;
      Status_Value : Status;
   begin
      if Payload'Length > Stream_Element_Offset (Maximum_Pkt_Line_Payload_Length)
      then
         return Result;
      end if;

      Status_Value := Append (Result, Encode_Header (Packet_Length));
      if Status_Value = Ok and then Payload'Length > 0 then
         Status_Value := Append (Result, Payload);
      end if;

      if Status_Value /= Ok then
         declare
            Empty_Result : Packet_Buffer;
         begin
            return Empty_Result;
         end;
      end if;
      return Result;
   exception
      when others =>
         declare
            Empty_Result : Packet_Buffer;
         begin
            return Empty_Result;
         end;
   end Encode_Pkt_Line;

   function Encode_Pkt_Flush
      return Packet_Buffer is
   begin
      return Encode_Special_Pkt_Line (0);
   end Encode_Pkt_Flush;

   function Encode_Pkt_Delimiter
      return Packet_Buffer is
   begin
      return Encode_Special_Pkt_Line (1);
   end Encode_Pkt_Delimiter;

   function Encode_Pkt_Response_End
      return Packet_Buffer is
   begin
      return Encode_Special_Pkt_Line (2);
   end Encode_Pkt_Response_End;

   function Empty_Buffer return Packet_Buffer is
      Result : Packet_Buffer;
   begin
      return Result;
   end Empty_Buffer;

   function Append_Text
     (Buffer : in out Packet_Buffer;
      Text   : String)
      return Status
   is
      Bytes : Stream_Element_Array (1 .. Stream_Element_Offset (Text'Length));
      Cursor : Stream_Element_Offset := Bytes'First;
   begin
      for Item of Text loop
         Bytes (Cursor) := Character'Pos (Item);
         Cursor := Cursor + 1;
      end loop;

      return Append (Buffer, Bytes);
   exception
      when others =>
         return Internal_Error;
   end Append_Text;

   function Safe_Filter_Byte (Item : Stream_Element) return Boolean is
   begin
      return Item >= 16#21# and then Item <= 16#7E#;
   exception
      when others =>
         return False;
   end Safe_Filter_Byte;

   function Validate_Capability_List
     (Capabilities : Stream_Element_Array;
      Summary      : in out Upload_Pack_Negotiation_Summary)
      return Status
   is
      Cursor    : Stream_Element_Offset := Capabilities'First;
      Token     : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Capability_Token_Length));
      Token_Last : Stream_Element_Offset;
      Has_Token : Boolean := False;
      Name      : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Capability_Token_Length));
      Name_Last : Stream_Element_Offset;
      Value     : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Capability_Token_Length));
      Value_Last : Stream_Element_Offset;
      Has_Value : Boolean := False;
      Status_Value : Status;

      function Name_Equals (Text : String) return Boolean is
      begin
         if Name_Last < Name'First
           or else Natural (Name_Last - Name'First + 1) /= Text'Length
         then
            return False;
         end if;

         for Offset in 0 .. Text'Length - 1 loop
            if Name (Name'First + Stream_Element_Offset (Offset))
              /= Character'Pos (Text (Text'First + Offset))
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Name_Equals;
   begin
      if Capabilities'Length = 0 then
         return Ok;
      end if;

      loop
         Status_Value :=
           Copy_Next_Capability_Token
             (Capabilities, Cursor, Token, Token_Last, Has_Token);
         if Status_Value /= Ok then
            return Status_Value;
         elsif not Has_Token then
            exit;
         end if;

         Status_Value :=
           Parse_Capability_Token
             (Token (Token'First .. Token_Last),
              Name, Name_Last, Value, Value_Last, Has_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         Summary.Uses_Capabilities := True;
         if Name_Equals ("multi_ack") then
            Summary.Uses_Multi_ACK := True;
         elsif Name_Equals ("multi_ack_detailed") then
            Summary.Uses_Multi_ACK_Detailed := True;
         elsif Name_Equals ("side-band") then
            Summary.Uses_Side_Band := True;
         elsif Name_Equals ("side-band-64k") then
            Summary.Uses_Side_Band_64K := True;
         elsif Name_Equals ("no-done") then
            Summary.Uses_No_Done := True;
         end if;
      end loop;

      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Validate_Capability_List;

   function Build_Upload_Pack_Line
     (Prefix        : String;
      Object_ID_Hex : Stream_Element_Array;
      Suffix        : Stream_Element_Array)
      return Packet_Buffer
   is
      Raw_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last : Stream_Element_Offset;
      Payload : Packet_Buffer;
      Status_Value : Status;
   begin
      Status_Value := Parse_Object_ID_Hex (Object_ID_Hex, Raw_ID, Raw_Last);
      if Status_Value /= Ok then
         return Empty_Buffer;
      end if;

      Status_Value := Append_Text (Payload, Prefix);
      if Status_Value = Ok then
         Status_Value := Append (Payload, Object_ID_Hex);
      end if;
      if Status_Value = Ok and then Suffix'Length > 0 then
         Status_Value := Append (Payload, Suffix);
      end if;
      if Status_Value = Ok then
         Status_Value := Append_Text (Payload, "" & Character'Val (10));
      end if;

      if Status_Value /= Ok then
         return Empty_Buffer;
      end if;
      return Encode_Pkt_Line (To_Array (Payload));
   exception
      when others =>
         return Empty_Buffer;
   end Build_Upload_Pack_Line;

   function Encode_Upload_Pack_Want_Line
     (Object_ID_Hex : Stream_Element_Array;
      Capabilities  : Stream_Element_Array)
      return Packet_Buffer
   is
      Summary : Upload_Pack_Negotiation_Summary;
      Space_And_Caps : Stream_Element_Array
        (1 .. Stream_Element_Offset (Capabilities'Length + 1));
      Status_Value : Status;
   begin
      if Capabilities'Length = 0 then
         return Build_Upload_Pack_Line ("want ", Object_ID_Hex,
                                        [1 .. 0 => 0]);
      end if;

      Status_Value := Validate_Capability_List (Capabilities, Summary);
      if Status_Value /= Ok then
         return Empty_Buffer;
      end if;

      Space_And_Caps (Space_And_Caps'First) := Character'Pos (' ');
      for Offset in 0 .. Capabilities'Length - 1 loop
         Space_And_Caps
           (Space_And_Caps'First + 1 + Stream_Element_Offset (Offset)) :=
             Capabilities (Capabilities'First + Stream_Element_Offset (Offset));
      end loop;

      return Build_Upload_Pack_Line
        ("want ", Object_ID_Hex, Space_And_Caps);
   exception
      when others =>
         return Empty_Buffer;
   end Encode_Upload_Pack_Want_Line;

   function Encode_Upload_Pack_Have_Line
     (Object_ID_Hex : Stream_Element_Array)
      return Packet_Buffer
   is
   begin
      return Build_Upload_Pack_Line ("have ", Object_ID_Hex, [1 .. 0 => 0]);
   end Encode_Upload_Pack_Have_Line;

   function Encode_Upload_Pack_Done_Line
      return Packet_Buffer
   is
   begin
      return Encode_Pkt_Line
        ([Character'Pos ('d'), Character'Pos ('o'), Character'Pos ('n'),
          Character'Pos ('e'), Character'Pos (Character'Val (10))]);
   end Encode_Upload_Pack_Done_Line;

   function Encode_Upload_Pack_Deepen_Line
     (Depth : Natural)
      return Packet_Buffer
   is
      Text : constant String := Natural'Image (Depth);
      Payload : Packet_Buffer;
      Status_Value : Status;
   begin
      if Depth = 0 then
         return Empty_Buffer;
      end if;

      Status_Value := Append_Text (Payload, "deepen ");
      if Status_Value = Ok then
         Status_Value := Append_Text (Payload, Text (Text'First + 1 .. Text'Last));
      end if;
      if Status_Value = Ok then
         Status_Value := Append_Text (Payload, "" & Character'Val (10));
      end if;

      if Status_Value /= Ok then
         return Empty_Buffer;
      end if;
      return Encode_Pkt_Line (To_Array (Payload));
   exception
      when others =>
         return Empty_Buffer;
   end Encode_Upload_Pack_Deepen_Line;

   function Encode_Upload_Pack_Shallow_Line
     (Object_ID_Hex : Stream_Element_Array)
      return Packet_Buffer
   is
   begin
      return Build_Upload_Pack_Line ("shallow ", Object_ID_Hex,
                                     [1 .. 0 => 0]);
   end Encode_Upload_Pack_Shallow_Line;

   function Encode_Upload_Pack_Filter_Line
     (Filter_Spec : Stream_Element_Array)
      return Packet_Buffer
   is
      Payload : Packet_Buffer;
      Status_Value : Status;
   begin
      if Filter_Spec'Length = 0
        or else Filter_Spec'Length >
          Stream_Element_Offset (Maximum_Pkt_Line_Payload_Length - 8)
      then
         return Empty_Buffer;
      end if;

      for Item of Filter_Spec loop
         if not Safe_Filter_Byte (Item) then
            return Empty_Buffer;
         end if;
      end loop;

      Status_Value := Append_Text (Payload, "filter ");
      if Status_Value = Ok then
         Status_Value := Append (Payload, Filter_Spec);
      end if;
      if Status_Value = Ok then
         Status_Value := Append_Text (Payload, "" & Character'Val (10));
      end if;

      if Status_Value /= Ok then
         return Empty_Buffer;
      end if;
      return Encode_Pkt_Line (To_Array (Payload));
   exception
      when others =>
         return Empty_Buffer;
   end Encode_Upload_Pack_Filter_Line;

   function Parse_Upload_Pack_ACK_Packet
     (Data          : Stream_Element_Array;
      Kind          : out Upload_Pack_ACK_Kind;
      Object_ID_Hex : out Stream_Element_Array;
      Last          : out Stream_Element_Offset)
      return Status
   is
      Pkt_Kind      : Pkt_Line_Kind;
      Packet_Length : Natural := 0;
      Payload_First : Stream_Element_Offset;
      Payload_Last  : Stream_Element_Offset;

      function Payload_Equals (Text : String) return Boolean is
      begin
         if Natural (Payload_Last - Payload_First + 1) /= Text'Length then
            return False;
         end if;

         for Offset in 0 .. Text'Length - 1 loop
            if Data (Payload_First + Stream_Element_Offset (Offset))
              /= Character'Pos (Text (Text'First + Offset))
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Payload_Equals;

      function Has_Status (Text : String) return Boolean is
         Status_First : constant Stream_Element_Offset := Payload_First + 44;
      begin
         if Natural (Payload_Last - Status_First + 1) /= Text'Length + 2 then
            return False;
         elsif Data (Status_First) /= Character'Pos (' ') then
            return False;
         elsif Data (Payload_Last) /= Character'Pos (Character'Val (10)) then
            return False;
         end if;

         for Offset in 0 .. Text'Length - 1 loop
            if Data (Status_First + 1 + Stream_Element_Offset (Offset))
              /= Character'Pos (Text (Text'First + Offset))
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Has_Status;
   begin
      Kind := Upload_Pack_NAK;
      Last := Object_ID_Hex'First - 1;

      declare
         Status_Value : constant Status :=
           Parse_Pkt_Line_Header (Data, Pkt_Kind, Packet_Length);
      begin
         if Status_Value /= Ok then
            return Status_Value;
         elsif Pkt_Kind /= Pkt_Data then
            return Invalid_Command;
         end if;
      end;

      Payload_First := Data'First + 4;
      Payload_Last :=
        Data'First + Stream_Element_Offset (Packet_Length) - 1;
      if Payload_Equals ("NAK" & Character'Val (10)) then
         Kind := Upload_Pack_NAK;
         return Ok;
      end if;

      if Packet_Length < 49
        or else Data (Payload_First) /= Character'Pos ('A')
        or else Data (Payload_First + 1) /= Character'Pos ('C')
        or else Data (Payload_First + 2) /= Character'Pos ('K')
        or else Data (Payload_First + 3) /= Character'Pos (' ')
      then
         return Invalid_Command;
      elsif Object_ID_Hex'Length
        < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Read_Failed;
      end if;

      declare
         Raw_ID : Stream_Element_Array
           (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
         Raw_Last : Stream_Element_Offset;
         Status_Value : Status;
      begin
         Status_Value :=
           Parse_Object_ID_Hex
             (Data (Payload_First + 4 .. Payload_First + 43),
              Raw_ID, Raw_Last);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end;

      for Offset in 0 .. Object_ID_SHA1_Hex_Length - 1 loop
         Object_ID_Hex (Object_ID_Hex'First + Stream_Element_Offset (Offset)) :=
           Data (Payload_First + 4 + Stream_Element_Offset (Offset));
      end loop;
      Last :=
        Object_ID_Hex'First
        + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
        - 1;

      if Data (Payload_First + 44) = Character'Pos (Character'Val (10))
        and then Payload_First + 44 = Payload_Last
      then
         Kind := Upload_Pack_ACK;
      elsif Has_Status ("continue") then
         Kind := Upload_Pack_ACK_Continue;
      elsif Has_Status ("common") then
         Kind := Upload_Pack_ACK_Common;
      elsif Has_Status ("ready") then
         Kind := Upload_Pack_ACK_Ready;
      else
         Last := Object_ID_Hex'First - 1;
         return Invalid_Command;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Last := Object_ID_Hex'First - 1;
         Kind := Upload_Pack_NAK;
         return Read_Failed;
      when others =>
         Last := Object_ID_Hex'First - 1;
         Kind := Upload_Pack_NAK;
         return Internal_Error;
   end Parse_Upload_Pack_ACK_Packet;

   function Validate_Upload_Pack_ACK_Stream
     (Data    : Stream_Element_Array;
      Summary : out Upload_Pack_ACK_Stream_Summary)
      return Status
   is
      Cursor        : Pkt_Line_Cursor;
      Pkt_Kind      : Pkt_Line_Kind := Pkt_Data;
      ACK_Kind      : Upload_Pack_ACK_Kind := Upload_Pack_NAK;
      Packet_First  : Stream_Element_Offset;
      Packet_Last   : Stream_Element_Offset;
      Payload_First : Stream_Element_Offset;
      Payload_Last  : Stream_Element_Offset;
      Object_Buffer : Stream_Element_Array
        (Stream_Element_Offset'(1)
         .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Object_Last   : Stream_Element_Offset;
      Status_Value  : Status;
   begin
      Summary := (others => <>);
      if Data'Length = 0 then
         return Invalid_Command;
      end if;

      Reset_Pkt_Line_Cursor (Data, Cursor);
      loop
         Status_Value :=
           Next_Pkt_Line
             (Data,
              Cursor,
              Pkt_Kind,
              Packet_First,
              Packet_Last,
              Payload_First,
              Payload_Last);
         exit when Status_Value = End_Of_Stream;
         if Status_Value /= Ok then
            Summary := (others => <>);
            return Status_Value;
         end if;

         case Pkt_Kind is
            when Pkt_Data =>
               Status_Value :=
                 Parse_Upload_Pack_ACK_Packet
                   (Data (Packet_First .. Packet_Last),
                    ACK_Kind,
                    Object_Buffer,
                    Object_Last);
               if Status_Value /= Ok then
                  Summary := (others => <>);
                  return Status_Value;
               end if;

               case ACK_Kind is
                  when Upload_Pack_NAK =>
                     Summary.NAK_Count := Summary.NAK_Count + 1;
                  when Upload_Pack_ACK =>
                     Summary.ACK_Count := Summary.ACK_Count + 1;
                  when Upload_Pack_ACK_Continue =>
                     Summary.Continue_Count := Summary.Continue_Count + 1;
                  when Upload_Pack_ACK_Common =>
                     Summary.Common_Count := Summary.Common_Count + 1;
                  when Upload_Pack_ACK_Ready =>
                     Summary.Ready_Count := Summary.Ready_Count + 1;
               end case;
            when Pkt_Flush =>
               Summary.Has_Flush := True;
               if not Pkt_Line_Cursor_Done (Cursor) then
                  Summary := (others => <>);
                  return Invalid_Command;
               end if;
            when Pkt_Delimiter | Pkt_Response_End =>
               Summary := (others => <>);
               return Invalid_Command;
         end case;
      end loop;

      if Summary.NAK_Count = 0
        and then Summary.ACK_Count = 0
        and then Summary.Continue_Count = 0
        and then Summary.Common_Count = 0
        and then Summary.Ready_Count = 0
      then
         Summary := (others => <>);
         return Invalid_Command;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Summary := (others => <>);
         return Read_Failed;
      when others =>
         Summary := (others => <>);
         return Internal_Error;
   end Validate_Upload_Pack_ACK_Stream;

   function Validate_Upload_Pack_Negotiation_Request
     (Data    : Stream_Element_Array;
      Summary : out Upload_Pack_Negotiation_Summary)
      return Status
   is
      Cursor : Stream_Element_Offset := Data'First;
      Saw_First_Want : Boolean := False;
      Saw_Flush : Boolean := False;

      function Starts_With
        (First : Stream_Element_Offset;
         Last  : Stream_Element_Offset;
         Text  : String)
         return Boolean
      is
      begin
         if Last < First
           or else Natural (Last - First + 1) < Text'Length
         then
            return False;
         end if;

         for Offset in 0 .. Text'Length - 1 loop
            if Data (First + Stream_Element_Offset (Offset))
              /= Character'Pos (Text (Text'First + Offset))
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Starts_With;

      function Validate_Hex_At
        (First : Stream_Element_Offset)
         return Status
      is
         Raw_ID : Stream_Element_Array
           (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
         Raw_Last : Stream_Element_Offset;
      begin
         if First + Stream_Element_Offset (Object_ID_SHA1_Hex_Length) - 1
           > Data'Last
         then
            return Read_Failed;
         end if;

         return Parse_Object_ID_Hex
           (Data
              (First
               .. First
                 + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                 - 1),
            Raw_ID, Raw_Last);
      end Validate_Hex_At;

      function Parse_Depth
        (First : Stream_Element_Offset;
         Last  : Stream_Element_Offset)
         return Status
      is
         Value : Natural := 0;
      begin
         if Last < First then
            return Invalid_Command;
         end if;

         for Index in First .. Last loop
            if Data (Index) < Character'Pos ('0')
              or else Data (Index) > Character'Pos ('9')
            then
               return Invalid_Command;
            elsif Value
              > (Natural'Last - Natural (Data (Index) - Character'Pos ('0'))) / 10
            then
               return Unsupported_Feature;
            end if;
            Value := Value * 10
              + Natural (Data (Index) - Character'Pos ('0'));
         end loop;

         if Value = 0 then
            return Invalid_Command;
         end if;
         return Ok;
      exception
         when others =>
            return Internal_Error;
      end Parse_Depth;

      function Validate_Filter
        (First : Stream_Element_Offset;
         Last  : Stream_Element_Offset)
         return Status
      is
      begin
         if Last < First then
            return Invalid_Command;
         end if;
         for Index in First .. Last loop
            if not Safe_Filter_Byte (Data (Index)) then
               return Invalid_Command;
            end if;
         end loop;
         return Ok;
      exception
         when others =>
            return Internal_Error;
      end Validate_Filter;
   begin
      Summary := (others => <>);

      if Data'Length = 0 then
         return Invalid_Command;
      end if;

      while Cursor <= Data'Last loop
         declare
            Packet : constant Stream_Element_Array :=
              Data (Cursor .. Data'Last);
            Pkt_Kind : Pkt_Line_Kind;
            Packet_Length : Natural := 0;
            Status_Value : Status;
            Payload_First : Stream_Element_Offset;
            Payload_Last  : Stream_Element_Offset;
            Line_Last     : Stream_Element_Offset;
         begin
            Status_Value :=
              Parse_Pkt_Line_Header (Packet, Pkt_Kind, Packet_Length);
            if Status_Value /= Ok then
               Summary := (others => <>);
               return Status_Value;
            end if;

            if Pkt_Kind = Pkt_Flush then
               Summary.Has_Flush := True;
               Saw_Flush := True;
               Cursor := Cursor + 4;
               if Cursor <= Data'Last then
                  Summary := (others => <>);
                  return Invalid_Command;
               end if;
               exit;
            elsif Pkt_Kind /= Pkt_Data then
               Summary := (others => <>);
               return Invalid_Command;
            elsif Saw_Flush then
               Summary := (others => <>);
               return Invalid_Command;
            end if;

            Payload_First := Cursor + 4;
            Payload_Last :=
              Cursor + Stream_Element_Offset (Packet_Length) - 1;
            if Payload_Last < Payload_First
              or else Data (Payload_Last) /= Character'Pos (Character'Val (10))
            then
               Summary := (others => <>);
               return Invalid_Command;
            end if;
            Line_Last := Payload_Last - 1;

            if Summary.Has_Done then
               Summary := (others => <>);
               return Invalid_Command;
            end if;

            if Starts_With (Payload_First, Line_Last, "want ") then
               if Summary.Have_Count > 0
                 or else Summary.Has_Done
                 or else Summary.Deepen_Count > 0
                 or else Summary.Shallow_Count > 0
                 or else Summary.Filter_Count > 0
               then
                  Summary := (others => <>);
                  return Invalid_Command;
               end if;

               Status_Value := Validate_Hex_At (Payload_First + 5);
               if Status_Value /= Ok then
                  Summary := (others => <>);
                  return Status_Value;
               end if;

               declare
                  After_ID : constant Stream_Element_Offset :=
                    Payload_First + 5
                    + Stream_Element_Offset (Object_ID_SHA1_Hex_Length);
               begin
                  if After_ID <= Line_Last then
                     if Data (After_ID) /= Character'Pos (' ') then
                        Summary := (others => <>);
                        return Invalid_Command;
                     elsif After_ID = Line_Last then
                        Summary := (others => <>);
                        return Invalid_Command;
                     elsif Saw_First_Want then
                        Summary := (others => <>);
                        return Invalid_Command;
                     end if;
                     Status_Value :=
                       Validate_Capability_List
                         (Data (After_ID + 1 .. Line_Last), Summary);
                     if Status_Value /= Ok then
                        Summary := (others => <>);
                        return Status_Value;
                     end if;
                  end if;
               end;
               Saw_First_Want := True;
               Summary.Want_Count := Summary.Want_Count + 1;
            elsif Starts_With (Payload_First, Line_Last, "have ") then
               if Summary.Want_Count = 0 or else Summary.Has_Done then
                  Summary := (others => <>);
                  return Invalid_Command;
               end if;

               if Line_Last /= Payload_First + 4
                 + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
               then
                  Summary := (others => <>);
                  return Invalid_Command;
               end if;
               Status_Value := Validate_Hex_At (Payload_First + 5);
               if Status_Value /= Ok then
                  Summary := (others => <>);
                  return Status_Value;
               end if;
               Summary.Have_Count := Summary.Have_Count + 1;
            elsif Starts_With (Payload_First, Line_Last, "deepen ") then
               if Summary.Want_Count = 0 or else Summary.Have_Count > 0 then
                  Summary := (others => <>);
                  return Invalid_Command;
               end if;
               Status_Value := Parse_Depth (Payload_First + 7, Line_Last);
               if Status_Value /= Ok then
                  Summary := (others => <>);
                  return Status_Value;
               end if;
               Summary.Deepen_Count := Summary.Deepen_Count + 1;
            elsif Starts_With (Payload_First, Line_Last, "shallow ") then
               if Summary.Want_Count = 0 or else Summary.Have_Count > 0 then
                  Summary := (others => <>);
                  return Invalid_Command;
               end if;
               if Line_Last /= Payload_First + 7
                 + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
               then
                  Summary := (others => <>);
                  return Invalid_Command;
               end if;
               Status_Value := Validate_Hex_At (Payload_First + 8);
               if Status_Value /= Ok then
                  Summary := (others => <>);
                  return Status_Value;
               end if;
               Summary.Shallow_Count := Summary.Shallow_Count + 1;
            elsif Starts_With (Payload_First, Line_Last, "filter ") then
               if Summary.Want_Count = 0 or else Summary.Have_Count > 0 then
                  Summary := (others => <>);
                  return Invalid_Command;
               end if;
               Status_Value := Validate_Filter (Payload_First + 7, Line_Last);
               if Status_Value /= Ok then
                  Summary := (others => <>);
                  return Status_Value;
               end if;
               Summary.Filter_Count := Summary.Filter_Count + 1;
            elsif Starts_With (Payload_First, Line_Last, "done") then
               if Line_Last /= Payload_First + 3
                 or else Summary.Want_Count = 0
               then
                  Summary := (others => <>);
                  return Invalid_Command;
               end if;
               Summary.Has_Done := True;
            else
               Summary := (others => <>);
               return Invalid_Command;
            end if;

            Cursor := Cursor + Stream_Element_Offset (Packet_Length);
         end;
      end loop;

      if Summary.Want_Count = 0
        or else (not Summary.Has_Done and then not Summary.Has_Flush)
      then
         Summary := (others => <>);
         return Invalid_Command;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Summary := (others => <>);
         return Read_Failed;
      when others =>
         Summary := (others => <>);
         return Internal_Error;
   end Validate_Upload_Pack_Negotiation_Request;

   function Object_ID_To_Array
     (Object_ID_Hex : Object_ID_Hex_Text)
      return Stream_Element_Array
   is
      Result : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
   begin
      for Index in Object_ID_Hex'Range loop
         Result (Stream_Element_Offset (Index)) := Object_ID_Hex (Index);
      end loop;
      return Result;
   end Object_ID_To_Array;

   function Object_ID_Is_Zero
     (Object_ID_Hex : Stream_Element_Array)
      return Boolean
   is
   begin
      if Object_ID_Hex'Length
        /= Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return False;
      end if;

      for Item of Object_ID_Hex loop
         if Item /= Character'Pos ('0') then
            return False;
         end if;
      end loop;
      return True;
   exception
      when others =>
         return False;
   end Object_ID_Is_Zero;

   function Safe_Command_Byte (Item : Stream_Element) return Boolean is
   begin
      return
        (Item >= Character'Pos ('a') and then Item <= Character'Pos ('z'))
        or else (Item >= Character'Pos ('0') and then Item <= Character'Pos ('9'))
        or else Item = Character'Pos ('-');
   exception
      when others =>
         return False;
   end Safe_Command_Byte;

   function Safe_Text_Line_Byte (Item : Stream_Element) return Boolean is
   begin
      return Item >= 16#20# and then Item <= 16#7E#;
   exception
      when others =>
         return False;
   end Safe_Text_Line_Byte;

   function Append_Buffer
     (Target : in out Packet_Buffer;
      Source : Packet_Buffer)
      return Status
   is
   begin
      return Append (Target, To_Array (Source));
   exception
      when others =>
         return Internal_Error;
   end Append_Buffer;

   function Append_Pkt_Text_Line
     (Target : in out Packet_Buffer;
      Prefix : String;
      Line   : Stream_Element_Array)
      return Status
   is
      Payload : Packet_Buffer;
      Status_Value : Status;
   begin
      for Item of Line loop
         if not Safe_Text_Line_Byte (Item) then
            return Invalid_Command;
         end if;
      end loop;

      Status_Value := Append_Text (Payload, Prefix);
      if Status_Value = Ok and then Line'Length > 0 then
         Status_Value := Append (Payload, Line);
      end if;
      if Status_Value = Ok then
         Status_Value := Append_Text (Payload, "" & Character'Val (10));
      end if;
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return Append_Buffer (Target, Encode_Pkt_Line (To_Array (Payload)));
   exception
      when others =>
         return Internal_Error;
   end Append_Pkt_Text_Line;

   function Append_Newline_Delimited_Pkt_Lines
     (Target : in out Packet_Buffer;
      Lines  : Stream_Element_Array)
      return Status
   is
      Cursor : Stream_Element_Offset := Lines'First;
      Line_First : Stream_Element_Offset;
      Status_Value : Status;
   begin
      if Lines'Length = 0 then
         return Ok;
      end if;

      while Cursor <= Lines'Last loop
         Line_First := Cursor;
         while Cursor <= Lines'Last
           and then Lines (Cursor) /= Character'Pos (Character'Val (10))
         loop
            Cursor := Cursor + 1;
         end loop;

         if Cursor = Line_First then
            return Invalid_Command;
         end if;

         Status_Value :=
           Append_Pkt_Text_Line (Target, "", Lines (Line_First .. Cursor - 1));
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         if Cursor <= Lines'Last then
            Cursor := Cursor + 1;
            if Cursor > Lines'Last then
               exit;
            end if;
         end if;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         return Read_Failed;
      when others =>
         return Internal_Error;
   end Append_Newline_Delimited_Pkt_Lines;

   function Encode_Upload_Pack_Fetch_Request
     (Wants        : Object_ID_Hex_Array;
      Haves        : Object_ID_Hex_Array;
      Shallows     : Object_ID_Hex_Array;
      Capabilities : Stream_Element_Array;
      Depth        : Natural;
      Filter_Spec  : Stream_Element_Array;
      Include_Done : Boolean)
      return Packet_Buffer
   is
      Result : Packet_Buffer;
      Status_Value : Status := Ok;
   begin
      if Wants'Length = 0 then
         return Empty_Buffer;
      end if;

      for Index in Wants'Range loop
         declare
            Caps : constant Stream_Element_Array :=
              (if Index = Wants'First then Capabilities else [1 .. 0 => 0]);
         begin
            Status_Value :=
              Append_Buffer
                (Result,
                 Encode_Upload_Pack_Want_Line
                   (Object_ID_To_Array (Wants (Index)), Caps));
         end;
         if Status_Value /= Ok then
            return Empty_Buffer;
         end if;
      end loop;

      for Index in Shallows'Range loop
         Status_Value :=
           Append_Buffer
             (Result,
              Encode_Upload_Pack_Shallow_Line
                (Object_ID_To_Array (Shallows (Index))));
         if Status_Value /= Ok then
            return Empty_Buffer;
         end if;
      end loop;

      if Depth > 0 then
         Status_Value :=
           Append_Buffer (Result, Encode_Upload_Pack_Deepen_Line (Depth));
         if Status_Value /= Ok then
            return Empty_Buffer;
         end if;
      end if;

      if Filter_Spec'Length > 0 then
         Status_Value :=
           Append_Buffer
             (Result, Encode_Upload_Pack_Filter_Line (Filter_Spec));
         if Status_Value /= Ok then
            return Empty_Buffer;
         end if;
      end if;

      for Index in Haves'Range loop
         Status_Value :=
           Append_Buffer
             (Result,
              Encode_Upload_Pack_Have_Line (Object_ID_To_Array (Haves (Index))));
         if Status_Value /= Ok then
            return Empty_Buffer;
         end if;
      end loop;

      if Include_Done then
         Status_Value :=
           Append_Buffer (Result, Encode_Upload_Pack_Done_Line);
      else
         Status_Value :=
           Append_Buffer (Result, Encode_Pkt_Flush);
      end if;

      if Status_Value /= Ok then
         return Empty_Buffer;
      end if;
      return Result;
   exception
      when others =>
         return Empty_Buffer;
   end Encode_Upload_Pack_Fetch_Request;

   function Encode_Receive_Pack_Update_Line
     (Old_ID_Hex   : Object_ID_Hex_Text;
      New_ID_Hex   : Object_ID_Hex_Text;
      Ref_Name     : Stream_Element_Array;
      Capabilities : Stream_Element_Array)
      return Packet_Buffer
   is
      Old_ID : constant Stream_Element_Array := Object_ID_To_Array (Old_ID_Hex);
      New_ID : constant Stream_Element_Array := Object_ID_To_Array (New_ID_Hex);
      Raw_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last : Stream_Element_Offset;
      Summary : Upload_Pack_Negotiation_Summary;
      Payload : Packet_Buffer;
      Status_Value : Status;
   begin
      Status_Value := Parse_Object_ID_Hex (Old_ID, Raw_ID, Raw_Last);
      if Status_Value = Ok then
         Status_Value := Parse_Object_ID_Hex (New_ID, Raw_ID, Raw_Last);
      end if;
      if Status_Value /= Ok then
         return Empty_Buffer;
      elsif Ref_Name'Length = 0
        or else Ref_Name'Length > Stream_Element_Offset (Maximum_Ref_Name_Length)
      then
         return Empty_Buffer;
      end if;

      declare
         Text : String (1 .. Natural (Ref_Name'Length));
         Cursor : Natural := Text'First;
      begin
         for Item of Ref_Name loop
            if Item > 127 then
               return Empty_Buffer;
            end if;
            Text (Cursor) := Character'Val (Item);
            Cursor := Cursor + 1;
         end loop;
         if not Valid_Ref_Name (Text) then
            return Empty_Buffer;
         end if;
      end;

      if Capabilities'Length > 0 then
         Status_Value := Validate_Capability_List (Capabilities, Summary);
         if Status_Value /= Ok then
            return Empty_Buffer;
         end if;
      end if;

      Status_Value := Append (Payload, Old_ID);
      if Status_Value = Ok then
         Status_Value := Append_Text (Payload, " ");
      end if;
      if Status_Value = Ok then
         Status_Value := Append (Payload, New_ID);
      end if;
      if Status_Value = Ok then
         Status_Value := Append_Text (Payload, " ");
      end if;
      if Status_Value = Ok then
         Status_Value := Append (Payload, Ref_Name);
      end if;
      if Status_Value = Ok and then Capabilities'Length > 0 then
         Status_Value := Append_Text (Payload, " ");
      end if;
      if Status_Value = Ok and then Capabilities'Length > 0 then
         Status_Value := Append (Payload, Capabilities);
      end if;
      if Status_Value = Ok then
         Status_Value := Append_Text (Payload, "" & Character'Val (10));
      end if;

      if Status_Value /= Ok then
         return Empty_Buffer;
      end if;
      return Encode_Pkt_Line (To_Array (Payload));
   exception
      when others =>
         return Empty_Buffer;
   end Encode_Receive_Pack_Update_Line;

   function Validate_Receive_Pack_Request
     (Data    : Stream_Element_Array;
      Summary : out Receive_Pack_Request_Summary)
      return Status
   is
      Cursor : Stream_Element_Offset := Data'First;
      Saw_First_Update : Boolean := False;

      function Validate_Update_Line
        (First : Stream_Element_Offset;
         Last  : Stream_Element_Offset)
         return Status
      is
         Old_First : constant Stream_Element_Offset := First;
         New_First : constant Stream_Element_Offset :=
           First + Stream_Element_Offset (Object_ID_SHA1_Hex_Length) + 1;
         Ref_First : constant Stream_Element_Offset :=
           New_First + Stream_Element_Offset (Object_ID_SHA1_Hex_Length) + 1;
         Ref_Last : Stream_Element_Offset := Last;
         Capability_First : Stream_Element_Offset := Last + 1;
         Raw_ID : Stream_Element_Array
           (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
         Raw_Last : Stream_Element_Offset;
         Status_Value : Status;
         Dummy : Upload_Pack_Negotiation_Summary;
      begin
         if Last < First
           or else Last - First + 1
             < Stream_Element_Offset (Object_ID_SHA1_Hex_Length * 2 + 3)
           or else Data (First + Stream_Element_Offset (Object_ID_SHA1_Hex_Length))
             /= Character'Pos (' ')
           or else Data (New_First + Stream_Element_Offset (Object_ID_SHA1_Hex_Length))
             /= Character'Pos (' ')
         then
            return Invalid_Command;
         end if;

         Status_Value :=
           Parse_Object_ID_Hex
             (Data
                (Old_First
                 .. Old_First
                   + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                   - 1),
              Raw_ID, Raw_Last);
         if Status_Value = Ok then
            Status_Value :=
              Parse_Object_ID_Hex
                (Data
                   (New_First
                    .. New_First
                      + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                      - 1),
                 Raw_ID, Raw_Last);
         end if;
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         for Index in Ref_First .. Last loop
            if Data (Index) = Character'Pos (' ') then
               Ref_Last := Index - 1;
               Capability_First := Index + 1;
               exit;
            end if;
         end loop;

         if Ref_Last < Ref_First then
            return Invalid_Command;
         end if;

         declare
            Text : String (1 .. Natural (Ref_Last - Ref_First + 1));
            Text_Cursor : Natural := Text'First;
         begin
            for Index in Ref_First .. Ref_Last loop
               if Data (Index) > 127 then
                  return Invalid_Command;
               end if;
               Text (Text_Cursor) := Character'Val (Data (Index));
               Text_Cursor := Text_Cursor + 1;
            end loop;
            if not Valid_Ref_Name (Text) then
               return Invalid_Command;
            end if;
         end;

         if Capability_First <= Last then
            if Saw_First_Update then
               return Invalid_Command;
            end if;
            Status_Value :=
              Validate_Capability_List
                (Data (Capability_First .. Last), Dummy);
            if Status_Value /= Ok then
               return Status_Value;
            end if;
            Summary.Has_Capabilities := True;
         end if;

         if Object_ID_Is_Zero
           (Data
              (New_First
               .. New_First
                 + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                 - 1))
         then
            Summary.Has_Delete := True;
         elsif Object_ID_Is_Zero
           (Data
              (Old_First
               .. Old_First
                 + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                 - 1))
         then
            Summary.Has_Create := True;
         else
            Summary.Has_Update := True;
         end if;

         Summary.Update_Count := Summary.Update_Count + 1;
         Saw_First_Update := True;
         return Ok;
      end Validate_Update_Line;
   begin
      Summary := (others => <>);
      if Data'Length = 0 then
         return Invalid_Command;
      end if;

      while Cursor <= Data'Last loop
         declare
            Packet : constant Stream_Element_Array := Data (Cursor .. Data'Last);
            Pkt_Kind : Pkt_Line_Kind;
            Packet_Length : Natural := 0;
            Status_Value : Status;
            Payload_First : Stream_Element_Offset;
            Payload_Last : Stream_Element_Offset;
         begin
            Status_Value :=
              Parse_Pkt_Line_Header (Packet, Pkt_Kind, Packet_Length);
            if Status_Value /= Ok then
               Summary := (others => <>);
               return Status_Value;
            end if;

            if Pkt_Kind = Pkt_Flush then
               Summary.Has_Flush := True;
               Cursor := Cursor + 4;
               exit;
            elsif Pkt_Kind /= Pkt_Data then
               Summary := (others => <>);
               return Invalid_Command;
            end if;

            Payload_First := Cursor + 4;
            Payload_Last := Cursor + Stream_Element_Offset (Packet_Length) - 1;
            if Payload_Last < Payload_First
              or else Data (Payload_Last) /= Character'Pos (Character'Val (10))
            then
               Summary := (others => <>);
               return Invalid_Command;
            end if;

            Status_Value :=
              Validate_Update_Line (Payload_First, Payload_Last - 1);
            if Status_Value /= Ok then
               Summary := (others => <>);
               return Status_Value;
            end if;
            Cursor := Cursor + Stream_Element_Offset (Packet_Length);
         end;
      end loop;

      if Summary.Update_Count = 0 or else not Summary.Has_Flush then
         Summary := (others => <>);
         return Invalid_Command;
      end if;

      if Cursor <= Data'Last then
         Summary.Has_Pack_Data := True;
         declare
            Version : Natural := 0;
            Count   : Natural := 0;
            Status_Value : constant Status :=
              Parse_Pack_Header (Data (Cursor .. Data'Last), Version, Count);
         begin
            if Status_Value /= Ok then
               Summary := (others => <>);
               return Status_Value;
            end if;
            Summary.Pack_Object_Count := Count;
         end;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Summary := (others => <>);
         return Read_Failed;
      when others =>
         Summary := (others => <>);
         return Internal_Error;
   end Validate_Receive_Pack_Request;

   function Validate_Upload_Pack_Response
     (Data    : Stream_Element_Array;
      Summary : out Upload_Pack_Response_Summary)
      return Status
   is
      Cursor : Stream_Element_Offset := Data'First;
      Object_Buffer : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Object_Last : Stream_Element_Offset;
      Side_Buffer : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Pkt_Line_Payload_Length));
      Side_Last : Stream_Element_Offset;
      Version : Natural := 0;
      Count   : Natural := 0;
   begin
      Summary := (others => <>);
      if Data'Length = 0 then
         return Invalid_Command;
      end if;

      while Cursor <= Data'Last loop
         declare
            Packet : constant Stream_Element_Array := Data (Cursor .. Data'Last);
            Pkt_Kind : Pkt_Line_Kind;
            Packet_Length : Natural := 0;
            Status_Value : Status;
         begin
            Status_Value :=
              Parse_Pkt_Line_Header (Packet, Pkt_Kind, Packet_Length);
            if Status_Value /= Ok then
               Summary := (others => <>);
               return Status_Value;
            end if;

            if Pkt_Kind = Pkt_Flush then
               Summary.Has_Flush := True;
               Cursor := Cursor + 4;
               if Cursor <= Data'Last then
                  Summary := (others => <>);
                  return Invalid_Command;
               end if;
               exit;
            elsif Pkt_Kind /= Pkt_Data then
               Summary := (others => <>);
               return Invalid_Command;
            end if;

            declare
               ACK_Kind : Upload_Pack_ACK_Kind := Upload_Pack_NAK;
            begin
               Status_Value :=
                 Parse_Upload_Pack_ACK_Packet
                   (Data (Cursor .. Cursor + Stream_Element_Offset (Packet_Length) - 1),
                    ACK_Kind, Object_Buffer, Object_Last);
               if Status_Value = Ok then
                  if ACK_Kind = Upload_Pack_NAK then
                     Summary.Has_NAK := True;
                  else
                     Summary.ACK_Count := Summary.ACK_Count + 1;
                     if ACK_Kind = Upload_Pack_ACK_Ready then
                        Summary.Has_Ready_ACK := True;
                     end if;
                  end if;
               end if;
            end;

            if Status_Value /= Ok then
               Status_Value := Invalid_Command;
            end if;

            if Status_Value = Ok then
               null;
            else
               declare
                  Side_Kind : Side_Band_Kind := Side_Band_Data;
               begin
                  Status_Value :=
                    Parse_Side_Band_Packet
                      (Data (Cursor .. Cursor + Stream_Element_Offset (Packet_Length) - 1),
                       Side_Kind, Side_Buffer, Side_Last);
                  if Status_Value /= Ok then
                     declare
                        Payload_First : constant Stream_Element_Offset := Cursor + 4;
                     begin
                        Status_Value :=
                          Parse_Pack_Header
                            (Data
                               (Payload_First
                                .. Cursor + Stream_Element_Offset (Packet_Length) - 1),
                             Version, Count);
                        if Status_Value /= Ok then
                           Summary := (others => <>);
                           return Status_Value;
                        end if;
                        Summary.Has_Pack_Data := True;
                        Summary.Pack_Object_Count := Count;
                     end;
                  else
                     case Side_Kind is
                        when Side_Band_Data =>
                           Summary.Side_Data_Count := Summary.Side_Data_Count + 1;
                           if Side_Last >= Side_Buffer'First then
                              Status_Value :=
                                Parse_Pack_Header
                                  (Side_Buffer (Side_Buffer'First .. Side_Last),
                                   Version, Count);
                              if Status_Value = Ok then
                                 Summary.Has_Pack_Data := True;
                                 Summary.Pack_Object_Count := Count;
                              end if;
                           end if;
                        when Side_Band_Progress =>
                           Summary.Side_Progress_Count :=
                             Summary.Side_Progress_Count + 1;
                        when Side_Band_Error =>
                           Summary.Side_Error_Count := Summary.Side_Error_Count + 1;
                     end case;
                  end if;
               end;
            end if;

            Cursor := Cursor + Stream_Element_Offset (Packet_Length);
         end;
      end loop;

      if not Summary.Has_NAK
        and then Summary.ACK_Count = 0
        and then not Summary.Has_Pack_Data
        and then Summary.Side_Data_Count = 0
        and then Summary.Side_Progress_Count = 0
        and then Summary.Side_Error_Count = 0
      then
         Summary := (others => <>);
         return Invalid_Command;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Summary := (others => <>);
         return Read_Failed;
      when others =>
         Summary := (others => <>);
         return Internal_Error;
   end Validate_Upload_Pack_Response;

   function Validate_Receive_Pack_Report
     (Data    : Stream_Element_Array;
      Summary : out Receive_Pack_Report_Summary)
      return Status
   is
      Cursor : Stream_Element_Offset := Data'First;
      Ref_Buffer : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Ref_Last : Stream_Element_Offset;
      Message_Buffer : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Pkt_Line_Payload_Length));
      Message_Last : Stream_Element_Offset;
   begin
      Summary := (others => <>);
      if Data'Length = 0 then
         return Invalid_Command;
      end if;

      while Cursor <= Data'Last loop
         declare
            Packet : constant Stream_Element_Array := Data (Cursor .. Data'Last);
            Pkt_Kind : Pkt_Line_Kind;
            Packet_Length : Natural := 0;
            Report_Kind : Status_Report_Kind := Status_Unpack_Error;
            Status_Value : Status;
         begin
            Status_Value := Parse_Pkt_Line_Header (Packet, Pkt_Kind, Packet_Length);
            if Status_Value /= Ok then
               Summary := (others => <>);
               return Status_Value;
            end if;
            if Pkt_Kind = Pkt_Flush then
               Summary.Has_Flush := True;
               Cursor := Cursor + 4;
               if Cursor <= Data'Last then
                  Summary := (others => <>);
                  return Invalid_Command;
               end if;
               exit;
            elsif Pkt_Kind /= Pkt_Data then
               Summary := (others => <>);
               return Invalid_Command;
            end if;

            Status_Value :=
              Parse_Status_Report_Packet
                (Data (Cursor .. Cursor + Stream_Element_Offset (Packet_Length) - 1),
                 Report_Kind, Ref_Buffer, Ref_Last, Message_Buffer, Message_Last);
            if Status_Value /= Ok then
               Summary := (others => <>);
               return Status_Value;
            end if;

            case Report_Kind is
               when Status_Unpack_Ok =>
                  Summary.Has_Unpack_OK := True;
               when Status_Unpack_Error =>
                  Summary.Has_Unpack_Error := True;
               when Status_Ref_Ok =>
                  Summary.Ref_OK_Count := Summary.Ref_OK_Count + 1;
               when Status_Ref_Error =>
                  Summary.Ref_Error_Count := Summary.Ref_Error_Count + 1;
            end case;

            Cursor := Cursor + Stream_Element_Offset (Packet_Length);
         end;
      end loop;

      if not Summary.Has_Unpack_OK and then not Summary.Has_Unpack_Error then
         Summary := (others => <>);
         return Invalid_Command;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Summary := (others => <>);
         return Read_Failed;
      when others =>
         Summary := (others => <>);
         return Internal_Error;
   end Validate_Receive_Pack_Report;

   procedure Reset_Fetch_Workflow (Workflow : out Fetch_Workflow) is
   begin
      Workflow := (others => <>);
   end Reset_Fetch_Workflow;

   function Fetch_Build_Request
     (Workflow     : in out Fetch_Workflow;
      Wants        : Object_ID_Hex_Array;
      Haves        : Object_ID_Hex_Array;
      Shallows     : Object_ID_Hex_Array;
      Capabilities : Stream_Element_Array;
      Depth        : Natural;
      Filter_Spec  : Stream_Element_Array;
      Include_Done : Boolean;
      Request      : out Packet_Buffer)
      return Status
   is
      Status_Value : Status;
   begin
      Clear (Request);
      if Workflow.State /= Fetch_Not_Started then
         Workflow.State := Fetch_Failed;
         return Invalid_Command;
      end if;

      Request :=
        Encode_Upload_Pack_Fetch_Request
          (Wants, Haves, Shallows, Capabilities, Depth, Filter_Spec,
           Include_Done);
      Status_Value :=
        Validate_Upload_Pack_Negotiation_Request
          (To_Array (Request), Workflow.Request_Summary);
      if Status_Value /= Ok then
         Clear (Request);
         Workflow.State := Fetch_Failed;
         return Status_Value;
      end if;

      Workflow.State := Fetch_Request_Built;
      return Ok;
   exception
      when others =>
         Clear (Request);
         Workflow.State := Fetch_Failed;
         return Internal_Error;
   end Fetch_Build_Request;

   function Fetch_Accept_Response
     (Workflow : in out Fetch_Workflow;
      Response : Stream_Element_Array)
      return Status
   is
      Status_Value : Status;
   begin
      if Workflow.State /= Fetch_Request_Built then
         Workflow.State := Fetch_Failed;
         return Invalid_Command;
      end if;

      Status_Value :=
        Validate_Upload_Pack_Response (Response, Workflow.Response_Summary);
      if Status_Value /= Ok then
         Workflow.State := Fetch_Failed;
         return Status_Value;
      end if;

      Workflow.State := Fetch_Response_Accepted;
      return Ok;
   exception
      when others =>
         Workflow.State := Fetch_Failed;
         return Internal_Error;
   end Fetch_Accept_Response;

   function Fetch_Apply_Remote_Tracking_Update
     (Workflow               : in out Fetch_Workflow;
      Repository_Root        : String;
      Remote_Name            : String;
      Branch_Name            : String;
      New_Commit_Hex         : Stream_Element_Array;
      Allow_Non_Fast_Forward : Boolean;
      Updated                : out Boolean)
      return Status
   is
      Status_Value : Status;
   begin
      Updated := False;
      if Workflow.State /= Fetch_Response_Accepted
        and then Workflow.State /= Fetch_Refs_Applied
      then
         Workflow.State := Fetch_Failed;
         return Invalid_Command;
      end if;

      Status_Value :=
        Apply_Fetch_Ref_Update
          (Repository_Root, Remote_Name, Branch_Name, New_Commit_Hex,
           Allow_Non_Fast_Forward, Updated);
      if Status_Value /= Ok then
         Workflow.State := Fetch_Failed;
         return Status_Value;
      end if;

      if Updated then
         Workflow.Applied_Count := Workflow.Applied_Count + 1;
      end if;
      Workflow.State := Fetch_Refs_Applied;
      return Ok;
   exception
      when others =>
         Updated := False;
         Workflow.State := Fetch_Failed;
         return Internal_Error;
   end Fetch_Apply_Remote_Tracking_Update;

   function Fetch_Finish
     (Workflow : in out Fetch_Workflow)
      return Status
   is
   begin
      if Workflow.State = Fetch_Response_Accepted
        or else Workflow.State = Fetch_Refs_Applied
      then
         Workflow.State := Fetch_Finished;
         return Ok;
      else
         Workflow.State := Fetch_Failed;
         return Invalid_Command;
      end if;
   exception
      when others =>
         Workflow.State := Fetch_Failed;
         return Internal_Error;
   end Fetch_Finish;

   procedure Reset_Push_Workflow (Workflow : out Push_Workflow) is
   begin
      Workflow := (others => <>);
   end Reset_Push_Workflow;

   function Push_Build_Request
     (Workflow     : in out Push_Workflow;
      Updates      : Stream_Element_Array;
      Pack_Data    : Stream_Element_Array;
      Request      : out Packet_Buffer)
      return Status
   is
      Status_Value : Status;
   begin
      Clear (Request);
      if Workflow.State /= Push_Not_Started or else Updates'Length = 0 then
         Workflow.State := Push_Failed;
         return Invalid_Command;
      end if;

      Status_Value := Append (Request, Updates);
      if Status_Value = Ok then
         Status_Value := Append_Buffer (Request, Encode_Pkt_Flush);
      end if;
      if Status_Value = Ok and then Pack_Data'Length > 0 then
         Status_Value := Append (Request, Pack_Data);
      end if;
      if Status_Value /= Ok then
         Clear (Request);
         Workflow.State := Push_Failed;
         return Status_Value;
      end if;

      Status_Value :=
        Validate_Receive_Pack_Request
          (To_Array (Request), Workflow.Request_Summary);
      if Status_Value /= Ok then
         Clear (Request);
         Workflow.State := Push_Failed;
         return Status_Value;
      end if;

      Workflow.State := Push_Request_Built;
      return Ok;
   exception
      when others =>
         Clear (Request);
         Workflow.State := Push_Failed;
         return Internal_Error;
   end Push_Build_Request;

   function Push_Accept_Report
     (Workflow : in out Push_Workflow;
      Report   : Stream_Element_Array)
      return Status
   is
      Status_Value : Status;
   begin
      if Workflow.State /= Push_Request_Built then
         Workflow.State := Push_Failed;
         return Invalid_Command;
      end if;

      Status_Value :=
        Validate_Receive_Pack_Report (Report, Workflow.Report_Summary);
      if Status_Value /= Ok then
         Workflow.State := Push_Failed;
         return Status_Value;
      elsif Workflow.Report_Summary.Has_Unpack_Error
        or else Workflow.Report_Summary.Ref_Error_Count > 0
      then
         Workflow.State := Push_Failed;
         return Remote_Failure;
      end if;

      Workflow.State := Push_Report_Accepted;
      return Ok;
   exception
      when others =>
         Workflow.State := Push_Failed;
         return Internal_Error;
   end Push_Accept_Report;

   function Push_Apply_Branch_Update
     (Workflow               : in out Push_Workflow;
      Repository_Root        : String;
      Branch_Name            : String;
      Expected_Old_Hex       : Stream_Element_Array;
      New_Commit_Hex         : Stream_Element_Array;
      Allow_Non_Fast_Forward : Boolean;
      Updated                : out Boolean)
      return Status
   is
      Status_Value : Status;
   begin
      Updated := False;
      if Workflow.State /= Push_Report_Accepted
        and then Workflow.State /= Push_Refs_Applied
      then
         Workflow.State := Push_Failed;
         return Invalid_Command;
      end if;

      Status_Value :=
        Apply_Push_Branch_Update
          (Repository_Root, Branch_Name, Expected_Old_Hex, New_Commit_Hex,
           Allow_Non_Fast_Forward, Updated);
      if Status_Value /= Ok then
         Workflow.State := Push_Failed;
         return Status_Value;
      end if;

      if Updated then
         Workflow.Applied_Count := Workflow.Applied_Count + 1;
      end if;
      Workflow.State := Push_Refs_Applied;
      return Ok;
   exception
      when others =>
         Updated := False;
         Workflow.State := Push_Failed;
         return Internal_Error;
   end Push_Apply_Branch_Update;

   function Push_Finish
     (Workflow : in out Push_Workflow)
      return Status
   is
   begin
      if Workflow.State = Push_Report_Accepted
        or else Workflow.State = Push_Refs_Applied
      then
         Workflow.State := Push_Finished;
         return Ok;
      else
         Workflow.State := Push_Failed;
         return Invalid_Command;
      end if;
   exception
      when others =>
         Workflow.State := Push_Failed;
         return Internal_Error;
   end Push_Finish;

   function Decide_Fetch_Policy
     (Workflow         : Fetch_Workflow;
      Attempt          : Natural;
      Max_Attempts     : Natural;
      Local_Have_Count : Natural;
      Decision         : out Fetch_Policy_Decision)
      return Status
   is
   begin
      Decision := Fetch_Policy_Stop;
      if Max_Attempts = 0 or else Attempt > Max_Attempts then
         return Invalid_Command;
      end if;

      case Workflow.State is
         when Fetch_Failed =>
            if Attempt < Max_Attempts then
               Decision := Fetch_Policy_Retry;
            else
               Decision := Fetch_Policy_Stop;
            end if;

         when Fetch_Request_Built =>
            if Workflow.Request_Summary.Have_Count = 0
              and then Local_Have_Count > 0
              and then not Workflow.Request_Summary.Has_Done
            then
               Decision := Fetch_Policy_Request_More_Haves;
            else
               Decision := Fetch_Policy_Stop;
            end if;

         when Fetch_Response_Accepted | Fetch_Refs_Applied =>
            if Workflow.Response_Summary.Has_Pack_Data then
               Decision := Fetch_Policy_Accept_Pack;
            elsif Workflow.Response_Summary.Has_Ready_ACK
              or else Workflow.Response_Summary.Has_NAK
            then
               Decision := Fetch_Policy_Stop;
            elsif Local_Have_Count > Workflow.Request_Summary.Have_Count then
               Decision := Fetch_Policy_Request_More_Haves;
            else
               Decision := Fetch_Policy_Stop;
            end if;

         when Fetch_Not_Started | Fetch_Finished =>
            Decision := Fetch_Policy_Stop;
      end case;

      return Ok;
   exception
      when others =>
         Decision := Fetch_Policy_Stop;
         return Internal_Error;
   end Decide_Fetch_Policy;

   function Decide_Push_Policy
     (Workflow     : Push_Workflow;
      Attempt      : Natural;
      Max_Attempts : Natural;
      Decision     : out Push_Policy_Decision)
      return Status
   is
   begin
      Decision := Push_Policy_Stop;
      if Max_Attempts = 0 or else Attempt > Max_Attempts then
         return Invalid_Command;
      end if;

      case Workflow.State is
         when Push_Failed =>
            if Attempt < Max_Attempts then
               Decision := Push_Policy_Retry;
            else
               Decision := Push_Policy_Stop;
            end if;

         when Push_Request_Built =>
            if not Workflow.Request_Summary.Has_Pack_Data
              and then
                (Workflow.Request_Summary.Has_Create
                 or else Workflow.Request_Summary.Has_Update)
            then
               Decision := Push_Policy_Rebuild_With_Pack;
            else
               Decision := Push_Policy_Stop;
            end if;

         when Push_Not_Started
            | Push_Report_Accepted
            | Push_Refs_Applied
            | Push_Finished =>
            Decision := Push_Policy_Stop;
      end case;

      return Ok;
   exception
      when others =>
         Decision := Push_Policy_Stop;
         return Internal_Error;
   end Decide_Push_Policy;

   function Encode_Protocol_V2_Command_Request
     (Command_Name : Stream_Element_Array;
      Capabilities : Stream_Element_Array;
      Arguments    : Stream_Element_Array)
      return Packet_Buffer
   is
      Result : Packet_Buffer;
      Status_Value : Status;
   begin
      if Command_Name'Length = 0 then
         return Empty_Buffer;
      end if;
      for Item of Command_Name loop
         if not Safe_Command_Byte (Item) then
            return Empty_Buffer;
         end if;
      end loop;

      Status_Value := Append_Pkt_Text_Line (Result, "command=", Command_Name);
      if Status_Value = Ok then
         Status_Value :=
           Append_Newline_Delimited_Pkt_Lines (Result, Capabilities);
      end if;
      if Status_Value = Ok then
         Status_Value := Append_Buffer (Result, Encode_Pkt_Delimiter);
      end if;
      if Status_Value = Ok then
         Status_Value :=
           Append_Newline_Delimited_Pkt_Lines (Result, Arguments);
      end if;
      if Status_Value = Ok then
         Status_Value := Append_Buffer (Result, Encode_Pkt_Flush);
      end if;

      if Status_Value /= Ok then
         return Empty_Buffer;
      end if;
      return Result;
   exception
      when others =>
         return Empty_Buffer;
   end Encode_Protocol_V2_Command_Request;

   function Validate_Protocol_V2_Command_Request
     (Data    : Stream_Element_Array;
      Summary : out Protocol_V2_Request_Summary)
      return Status
   is
      Cursor : Stream_Element_Offset := Data'First;
      Saw_Command : Boolean := False;
      Saw_Delimiter : Boolean := False;

      function Payload_Starts_With
        (First : Stream_Element_Offset;
         Last  : Stream_Element_Offset;
         Text  : String)
         return Boolean
      is
      begin
         if Last < First
           or else Natural (Last - First + 1) < Text'Length
         then
            return False;
         end if;
         for Offset in 0 .. Text'Length - 1 loop
            if Data (First + Stream_Element_Offset (Offset))
              /= Character'Pos (Text (Text'First + Offset))
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Payload_Starts_With;

      function Validate_Line
        (First : Stream_Element_Offset;
         Last  : Stream_Element_Offset)
         return Status
      is
      begin
         if Last < First then
            return Invalid_Command;
         end if;
         for Index in First .. Last loop
            if not Safe_Text_Line_Byte (Data (Index)) then
               return Invalid_Command;
            end if;
         end loop;
         return Ok;
      end Validate_Line;

      function Line_Equals
        (First : Stream_Element_Offset;
         Last  : Stream_Element_Offset;
         Text  : String)
         return Boolean
      is
      begin
         if Last < First
           or else Natural (Last - First + 1) /= Text'Length
         then
            return False;
         end if;
         for Offset in 0 .. Text'Length - 1 loop
            if Data (First + Stream_Element_Offset (Offset))
              /= Character'Pos (Text (Text'First + Offset))
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Line_Equals;

      function Capability_Name_Equals
        (First : Stream_Element_Offset;
         Last  : Stream_Element_Offset;
         Text  : String)
         return Boolean
      is
         After_Name : constant Stream_Element_Offset :=
           First + Stream_Element_Offset (Text'Length);
      begin
         if Last < First
           or else Natural (Last - First + 1) < Text'Length
         then
            return False;
         end if;
         for Offset in 0 .. Text'Length - 1 loop
            if Data (First + Stream_Element_Offset (Offset))
              /= Character'Pos (Text (Text'First + Offset))
            then
               return False;
            end if;
         end loop;
         return After_Name > Last
           or else Data (After_Name) = Character'Pos ('=');
      exception
         when others =>
            return False;
      end Capability_Name_Equals;

      function Line_Starts_With
        (First : Stream_Element_Offset;
         Last  : Stream_Element_Offset;
         Text  : String)
         return Boolean
      is
      begin
         if Last < First
           or else Natural (Last - First + 1) < Text'Length
         then
            return False;
         end if;
         for Offset in 0 .. Text'Length - 1 loop
            if Data (First + Stream_Element_Offset (Offset))
              /= Character'Pos (Text (Text'First + Offset))
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Line_Starts_With;
   begin
      Summary := (others => <>);
      if Data'Length = 0 then
         return Invalid_Command;
      end if;

      while Cursor <= Data'Last loop
         declare
            Packet : constant Stream_Element_Array := Data (Cursor .. Data'Last);
            Pkt_Kind : Pkt_Line_Kind;
            Packet_Length : Natural := 0;
            Status_Value : Status;
            Payload_First : Stream_Element_Offset;
            Payload_Last : Stream_Element_Offset;
            Line_Last : Stream_Element_Offset;
         begin
            Status_Value :=
              Parse_Pkt_Line_Header (Packet, Pkt_Kind, Packet_Length);
            if Status_Value /= Ok then
               Summary := (others => <>);
               return Status_Value;
            end if;

            if Pkt_Kind = Pkt_Delimiter then
               if not Saw_Command or else Saw_Delimiter then
                  Summary := (others => <>);
                  return Invalid_Command;
               end if;
               Summary.Has_Delimiter := True;
               Saw_Delimiter := True;
               Cursor := Cursor + 4;
            elsif Pkt_Kind = Pkt_Flush then
               Summary.Has_Flush := True;
               Cursor := Cursor + 4;
               if Cursor <= Data'Last then
                  Summary := (others => <>);
                  return Invalid_Command;
               end if;
               exit;
            elsif Pkt_Kind /= Pkt_Data then
               Summary := (others => <>);
               return Invalid_Command;
            else
               Payload_First := Cursor + 4;
               Payload_Last :=
                 Cursor + Stream_Element_Offset (Packet_Length) - 1;
               if Payload_Last < Payload_First
                 or else Data (Payload_Last) /= Character'Pos (Character'Val (10))
               then
                  Summary := (others => <>);
                  return Invalid_Command;
               end if;
               Line_Last := Payload_Last - 1;

               if not Saw_Command then
                  if not Payload_Starts_With
                    (Payload_First, Line_Last, "command=")
                  then
                     Summary := (others => <>);
                     return Invalid_Command;
                  end if;
                  Status_Value :=
                    Validate_Line (Payload_First + 8, Line_Last);
                  if Status_Value /= Ok then
                     Summary := (others => <>);
                     return Status_Value;
                  end if;
                  Summary.Command_Count := 1;
                  if Line_Equals (Payload_First + 8, Line_Last, "ls-refs") then
                     Summary.Has_Ls_Refs := True;
                  elsif Line_Equals (Payload_First + 8, Line_Last, "fetch") then
                     Summary.Has_Fetch := True;
                  elsif Line_Equals
                    (Payload_First + 8, Line_Last, "server-option")
                  then
                     Summary.Has_Server_Option := True;
                  elsif Line_Equals
                    (Payload_First + 8, Line_Last, "object-info")
                  then
                     Summary.Has_Object_Info := True;
                  end if;
                  Saw_Command := True;
               elsif not Saw_Delimiter then
                  Status_Value := Validate_Line (Payload_First, Line_Last);
                  if Status_Value /= Ok then
                     Summary := (others => <>);
                     return Status_Value;
                  end if;
                  Summary.Capability_Count := Summary.Capability_Count + 1;
                  if Capability_Name_Equals
                    (Payload_First, Line_Last, "server-option")
                  then
                     Summary.Has_Server_Option := True;
                  elsif Capability_Name_Equals
                    (Payload_First, Line_Last, "object-format")
                  then
                     Summary.Has_Object_Format := True;
                  elsif Capability_Name_Equals
                    (Payload_First, Line_Last, "agent")
                  then
                     Summary.Has_Agent := True;
                  elsif Capability_Name_Equals
                    (Payload_First, Line_Last, "session-id")
                  then
                     Summary.Has_Session_ID := True;
                  end if;
               else
                  Status_Value := Validate_Line (Payload_First, Line_Last);
                  if Status_Value /= Ok then
                     Summary := (others => <>);
                     return Status_Value;
                  end if;
                  Summary.Argument_Count := Summary.Argument_Count + 1;
                  if Line_Equals (Payload_First, Line_Last, "symrefs") then
                     Summary.Has_Symrefs := True;
                  elsif Line_Equals (Payload_First, Line_Last, "peel") then
                     Summary.Has_Peel := True;
                  elsif Line_Starts_With
                    (Payload_First, Line_Last, "ref-prefix ")
                  then
                     Summary.Has_Ref_Prefix := True;
                  elsif Line_Starts_With (Payload_First, Line_Last, "want ") then
                     Summary.Has_Want := True;
                  elsif Line_Starts_With (Payload_First, Line_Last, "have ") then
                     Summary.Has_Have := True;
                  elsif Line_Equals (Payload_First, Line_Last, "done") then
                     Summary.Has_Done := True;
                  elsif Line_Starts_With (Payload_First, Line_Last, "filter ") then
                     Summary.Has_Filter := True;
                  end if;
               end if;

               Cursor := Cursor + Stream_Element_Offset (Packet_Length);
            end if;
         end;
      end loop;

      if Summary.Command_Count /= 1
        or else not Summary.Has_Delimiter
        or else not Summary.Has_Flush
      then
         Summary := (others => <>);
         return Invalid_Command;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Summary := (others => <>);
         return Read_Failed;
      when others =>
         Summary := (others => <>);
         return Internal_Error;
   end Validate_Protocol_V2_Command_Request;

   function Validate_Protocol_V2_Capability_Advertisement
     (Data    : Stream_Element_Array;
      Summary : out Protocol_V2_Capability_Summary)
      return Status
   is
      Cursor : Stream_Element_Offset := Data'First;

      function Capability_Name_Last
        (First : Stream_Element_Offset;
         Last  : Stream_Element_Offset)
         return Stream_Element_Offset
      is
         Result : Stream_Element_Offset := Last;
      begin
         for Index in First .. Last loop
            if Data (Index) = Character'Pos ('=') then
               Result := Index - 1;
               exit;
            end if;
         end loop;
         return Result;
      exception
         when others =>
            return First - 1;
      end Capability_Name_Last;

      function Has_Value
        (Name_Last : Stream_Element_Offset;
         Line_Last : Stream_Element_Offset)
         return Boolean
      is
      begin
         return Name_Last < Line_Last;
      end Has_Value;

      function Name_Equals
        (First : Stream_Element_Offset;
         Last  : Stream_Element_Offset;
         Text  : String)
         return Boolean
      is
      begin
         if Last < First
           or else Natural (Last - First + 1) /= Text'Length
         then
            return False;
         end if;
         for Offset in 0 .. Text'Length - 1 loop
            if Data (First + Stream_Element_Offset (Offset))
              /= Character'Pos (Text (Text'First + Offset))
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Name_Equals;

      function Validate_Capability_Line
        (First : Stream_Element_Offset;
         Last  : Stream_Element_Offset;
         Name_Last : out Stream_Element_Offset)
         return Status
      is
      begin
         Name_Last := Capability_Name_Last (First, Last);
         if Last < First or else Name_Last < First then
            return Invalid_Command;
         end if;

         for Index in First .. Name_Last loop
            if not Safe_Command_Byte (Data (Index)) then
               return Invalid_Command;
            end if;
         end loop;

         if Has_Value (Name_Last, Last) then
            if Data (Name_Last + 1) /= Character'Pos ('=')
              or else Name_Last + 2 > Last
            then
               return Invalid_Command;
            end if;
            for Index in Name_Last + 2 .. Last loop
               if not Safe_Text_Line_Byte (Data (Index)) then
                  return Invalid_Command;
               end if;
            end loop;
         end if;
         return Ok;
      exception
         when Constraint_Error =>
            return Read_Failed;
         when others =>
            return Internal_Error;
      end Validate_Capability_Line;
   begin
      Summary := (others => <>);
      if Data'Length = 0 then
         return Invalid_Command;
      end if;

      while Cursor <= Data'Last loop
         declare
            Packet : constant Stream_Element_Array := Data (Cursor .. Data'Last);
            Pkt_Kind : Pkt_Line_Kind;
            Packet_Length : Natural := 0;
            Status_Value : Status;
            Payload_First : Stream_Element_Offset;
            Payload_Last : Stream_Element_Offset;
            Line_Last : Stream_Element_Offset;
            Name_Last : Stream_Element_Offset;
         begin
            Status_Value :=
              Parse_Pkt_Line_Header (Packet, Pkt_Kind, Packet_Length);
            if Status_Value /= Ok then
               Summary := (others => <>);
               return Status_Value;
            end if;

            case Pkt_Kind is
               when Pkt_Data =>
                  Payload_First := Cursor + 4;
                  Payload_Last :=
                    Cursor + Stream_Element_Offset (Packet_Length) - 1;
                  if Payload_Last < Payload_First
                    or else Data (Payload_Last) /=
                      Character'Pos (Character'Val (10))
                  then
                     Summary := (others => <>);
                     return Invalid_Command;
                  end if;
                  Line_Last := Payload_Last - 1;

                  Status_Value :=
                    Validate_Capability_Line
                      (Payload_First, Line_Last, Name_Last);
                  if Status_Value /= Ok then
                     Summary := (others => <>);
                     return Status_Value;
                  end if;

                  Summary.Capability_Count := Summary.Capability_Count + 1;
                  if Name_Equals (Payload_First, Name_Last, "ls-refs") then
                     Summary.Has_Ls_Refs := True;
                  elsif Name_Equals (Payload_First, Name_Last, "fetch") then
                     Summary.Has_Fetch := True;
                  elsif Name_Equals
                    (Payload_First, Name_Last, "server-option")
                  then
                     Summary.Has_Server_Option := True;
                  elsif Name_Equals
                    (Payload_First, Name_Last, "object-format")
                  then
                     Summary.Has_Object_Format := True;
                  elsif Name_Equals (Payload_First, Name_Last, "agent") then
                     Summary.Has_Agent := True;
                  elsif Name_Equals
                    (Payload_First, Name_Last, "session-id")
                  then
                     Summary.Has_Session_ID := True;
                  end if;

                  Cursor := Cursor + Stream_Element_Offset (Packet_Length);
               when Pkt_Flush =>
                  Summary.Has_Flush := True;
                  Cursor := Cursor + 4;
                  if Cursor <= Data'Last then
                     Summary := (others => <>);
                     return Invalid_Command;
                  end if;
                  exit;
               when Pkt_Delimiter | Pkt_Response_End =>
                  Summary := (others => <>);
                  return Invalid_Command;
            end case;
         end;
      end loop;

      if Summary.Capability_Count = 0 or else not Summary.Has_Flush then
         Summary := (others => <>);
         return Invalid_Command;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Summary := (others => <>);
         return Read_Failed;
      when others =>
         Summary := (others => <>);
         return Internal_Error;
   end Validate_Protocol_V2_Capability_Advertisement;

   function Validate_Protocol_V2_Response
     (Data    : Stream_Element_Array;
      Summary : out Protocol_V2_Response_Summary)
      return Status
   is
      Cursor : Stream_Element_Offset := Data'First;

      function Response_Line_Starts_With
        (First : Stream_Element_Offset;
         Last  : Stream_Element_Offset;
         Text  : String)
         return Boolean
      is
      begin
         if Last < First
           or else Natural (Last - First + 1) < Text'Length
         then
            return False;
         end if;
         for Offset in 0 .. Text'Length - 1 loop
            if Data (First + Stream_Element_Offset (Offset))
              /= Character'Pos (Text (Text'First + Offset))
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Response_Line_Starts_With;
   begin
      Summary := (others => <>);
      if Data'Length = 0 then
         return Invalid_Command;
      end if;

      while Cursor <= Data'Last loop
         declare
            Packet : constant Stream_Element_Array := Data (Cursor .. Data'Last);
            Pkt_Kind : Pkt_Line_Kind;
            Packet_Length : Natural := 0;
            Status_Value : Status;
            Payload_First : Stream_Element_Offset;
            Payload_Last : Stream_Element_Offset;
         begin
            Status_Value := Parse_Pkt_Line_Header (Packet, Pkt_Kind, Packet_Length);
            if Status_Value /= Ok then
               Summary := (others => <>);
               return Status_Value;
            end if;

            case Pkt_Kind is
               when Pkt_Data =>
                  Payload_First := Cursor + 4;
                  Payload_Last :=
                    Cursor + Stream_Element_Offset (Packet_Length) - 1;
                  if Payload_Last < Payload_First
                    or else Data (Payload_Last)
                      /= Character'Pos (Character'Val (10))
                  then
                     Summary := (others => <>);
                     return Invalid_Command;
                  end if;
                  for Index in Payload_First .. Payload_Last - 1 loop
                     if not Safe_Text_Line_Byte (Data (Index)) then
                        Summary := (others => <>);
                        return Invalid_Command;
                     end if;
                  end loop;
                  Summary.Data_Count := Summary.Data_Count + 1;
                  if Response_Line_Starts_With
                    (Payload_First, Payload_Last - 1, "ERR ")
                  then
                     Summary.Has_Error_Line := True;
                  end if;
                  Cursor := Cursor + Stream_Element_Offset (Packet_Length);
               when Pkt_Delimiter =>
                  Summary.Delimiter_Count := Summary.Delimiter_Count + 1;
                  Summary.Has_Delimiter := True;
                  Cursor := Cursor + 4;
               when Pkt_Response_End =>
                  Summary.Has_Response_End := True;
                  Cursor := Cursor + 4;
                  if Cursor <= Data'Last then
                     Summary := (others => <>);
                     return Invalid_Command;
                  end if;
                  exit;
               when Pkt_Flush =>
                  Summary.Has_Flush := True;
                  Cursor := Cursor + 4;
                  if Cursor <= Data'Last then
                     Summary := (others => <>);
                     return Invalid_Command;
                  end if;
                  exit;
            end case;
         end;
      end loop;

      if Summary.Data_Count = 0
        or else (not Summary.Has_Response_End and then not Summary.Has_Flush)
      then
         Summary := (others => <>);
         return Invalid_Command;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Summary := (others => <>);
         return Read_Failed;
      when others =>
         Summary := (others => <>);
         return Internal_Error;
   end Validate_Protocol_V2_Response;

   function Copy_Slice
     (Source : Stream_Element_Array;
      First  : Stream_Element_Offset;
      Last   : Stream_Element_Offset;
      Target : out Stream_Element_Array;
      Out_Last : out Stream_Element_Offset)
      return Status
   is
      Cursor : Stream_Element_Offset := Target'First;
   begin
      Out_Last := Target'First - 1;
      if Last < First then
         return Ok;
      elsif Target'Length < Natural (Last - First + 1) then
         return Read_Failed;
      end if;

      for Index in First .. Last loop
         Target (Cursor) := Source (Index);
         Cursor := Cursor + 1;
      end loop;
      Out_Last := Cursor - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Out_Last := Target'First - 1;
         return Read_Failed;
      when others =>
         Out_Last := Target'First - 1;
         return Internal_Error;
   end Copy_Slice;

   function Slice_Equals
     (Data  : Stream_Element_Array;
      First : Stream_Element_Offset;
      Text  : String)
      return Boolean
   is
   begin
      if First < Data'First
        or else First + Stream_Element_Offset (Text'Length) - 1 > Data'Last
      then
         return False;
      end if;

      for Offset in 0 .. Text'Length - 1 loop
         if Data (First + Stream_Element_Offset (Offset))
           /= Character'Pos (Text (Text'First + Offset))
         then
            return False;
         end if;
      end loop;
      return True;
   exception
      when others =>
         return False;
   end Slice_Equals;

   function Slice_Contains
     (Data  : Stream_Element_Array;
      First : Stream_Element_Offset;
      Last  : Stream_Element_Offset;
      Text  : String)
      return Boolean
   is
   begin
      if Last < First or else Text'Length = 0 then
         return False;
      end if;

      for Index in First .. Last loop
         exit when Index + Stream_Element_Offset (Text'Length) - 1 > Last;
         if Slice_Equals (Data, Index, Text) then
            return True;
         end if;
      end loop;
      return False;
   exception
      when others =>
         return False;
   end Slice_Contains;

   function Capability_Token_Count
     (Data  : Stream_Element_Array;
      First : Stream_Element_Offset;
      Last  : Stream_Element_Offset)
      return Natural
   is
      Count : Natural := 0;
      In_Token : Boolean := False;
   begin
      if Last < First then
         return 0;
      end if;

      for Index in First .. Last loop
         if Data (Index) = Character'Pos (' ') then
            In_Token := False;
         elsif not In_Token then
            Count := Count + 1;
            In_Token := True;
         end if;
      end loop;
      return Count;
   exception
      when others =>
         return 0;
   end Capability_Token_Count;

   function Ref_Name_Slice_Valid
     (Data  : Stream_Element_Array;
      First : Stream_Element_Offset;
      Last  : Stream_Element_Offset;
      Is_Peeled : out Boolean)
      return Boolean
   is
      Effective_Last : Stream_Element_Offset := Last;
   begin
      Is_Peeled := False;
      if Last < First
        or else Natural (Last - First + 1) > Maximum_Ref_Name_Length + 3
      then
         return False;
      end if;

      if Last - First + 1 > 3
        and then Data (Last - 2) = Character'Pos ('^')
        and then Data (Last - 1) = Character'Pos ('{')
        and then Data (Last) = Character'Pos ('}')
      then
         Is_Peeled := True;
         Effective_Last := Last - 3;
         if Effective_Last < First then
            return False;
         end if;
      end if;

      declare
         Text : String (1 .. Natural (Effective_Last - First + 1));
         Cursor : Natural := Text'First;
      begin
         for Index in First .. Effective_Last loop
            if Data (Index) < 16#21# or else Data (Index) > 16#7E# then
               return False;
            end if;
            Text (Cursor) := Character'Val (Data (Index));
            Cursor := Cursor + 1;
         end loop;
         return Valid_Ref_Name (Text);
      end;
   exception
      when others =>
         Is_Peeled := False;
         return False;
   end Ref_Name_Slice_Valid;

   function Parse_Ref_Advertisement_Packet
     (Data          : Stream_Element_Array;
      Object_ID_Hex : out Stream_Element_Array;
      Object_Last   : out Stream_Element_Offset;
      Ref_Name      : out Stream_Element_Array;
      Ref_Last      : out Stream_Element_Offset;
      Capabilities  : out Stream_Element_Array;
      Cap_Last      : out Stream_Element_Offset;
      Has_Caps      : out Boolean;
      Is_Peeled     : out Boolean;
      Is_Symref     : out Boolean)
      return Status
   is
      Pkt_Kind      : Pkt_Line_Kind;
      Packet_Length : Natural := 0;
      Payload_First : Stream_Element_Offset;
      Payload_Last  : Stream_Element_Offset;
      Ref_First     : Stream_Element_Offset;
      Ref_End       : Stream_Element_Offset;
      Attr_First    : Stream_Element_Offset;
      Caps_First    : Stream_Element_Offset := 0;
      Caps_End      : Stream_Element_Offset := 0;
      Raw_ID        : Stream_Element_Array (1 .. 20);
      Raw_Last      : Stream_Element_Offset;
      Status_Value  : Status;
   begin
      Object_Last := Object_ID_Hex'First - 1;
      Ref_Last := Ref_Name'First - 1;
      Cap_Last := Capabilities'First - 1;
      Has_Caps := False;
      Is_Peeled := False;
      Is_Symref := False;

      Status_Value := Parse_Pkt_Line_Header (Data, Pkt_Kind, Packet_Length);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Pkt_Kind /= Pkt_Data
        or else Packet_Length /= Data'Length
        or else Packet_Length < Object_ID_SHA1_Hex_Length + 6
      then
         return Invalid_Command;
      end if;

      Payload_First := Data'First + 4;
      Payload_Last := Data'First + Stream_Element_Offset (Packet_Length) - 1;
      if Data (Payload_Last) /= Character'Pos (Character'Val (10)) then
         return Invalid_Command;
      end if;

      if Data (Payload_First + Stream_Element_Offset (Object_ID_SHA1_Hex_Length))
        /= Character'Pos (' ')
      then
         return Invalid_Command;
      end if;

      Status_Value := Parse_Object_ID_Hex
        (Data
           (Payload_First
            .. Payload_First
              + Stream_Element_Offset (Object_ID_SHA1_Hex_Length) - 1),
         Raw_ID,
         Raw_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value := Copy_Slice
        (Data,
         Payload_First,
         Payload_First + Stream_Element_Offset (Object_ID_SHA1_Hex_Length) - 1,
         Object_ID_Hex,
         Object_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Ref_First :=
        Payload_First + Stream_Element_Offset (Object_ID_SHA1_Hex_Length) + 1;
      Ref_End := Ref_First;
      while Ref_End <= Payload_Last - 1
        and then Data (Ref_End) /= Character'Pos (' ')
        and then Data (Ref_End) /= 0
      loop
         Ref_End := Ref_End + 1;
      end loop;
      Ref_End := Ref_End - 1;

      if not Ref_Name_Slice_Valid (Data, Ref_First, Ref_End, Is_Peeled) then
         return Invalid_Command;
      end if;

      Status_Value := Copy_Slice (Data, Ref_First, Ref_End, Ref_Name, Ref_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Attr_First := Ref_End + 1;
      while Attr_First <= Payload_Last - 1 loop
         if Data (Attr_First) = 0 then
            Has_Caps := True;
            Caps_First := Attr_First + 1;
            Caps_End := Payload_Last - 1;
            exit;
         end if;
         Attr_First := Attr_First + 1;
      end loop;

      if Has_Caps then
         Status_Value := Copy_Slice
           (Data, Caps_First, Caps_End, Capabilities, Cap_Last);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end if;

      if Slice_Contains (Data, Ref_End + 1, Payload_Last - 1, " peeled:") then
         Is_Peeled := True;
      end if;

      Is_Symref :=
        Slice_Contains (Data, Ref_End + 1, Payload_Last - 1, " symref-target:")
        or else
        (Has_Caps and then
           (Slice_Contains (Data, Caps_First, Caps_End, "symref=")
            or else Slice_Contains (Data, Caps_First, Caps_End, " symref=")));

      return Ok;
   exception
      when Constraint_Error =>
         Object_Last := Object_ID_Hex'First - 1;
         Ref_Last := Ref_Name'First - 1;
         Cap_Last := Capabilities'First - 1;
         Has_Caps := False;
         Is_Peeled := False;
         Is_Symref := False;
         return Read_Failed;
      when others =>
         Object_Last := Object_ID_Hex'First - 1;
         Ref_Last := Ref_Name'First - 1;
         Cap_Last := Capabilities'First - 1;
         Has_Caps := False;
         Is_Peeled := False;
         Is_Symref := False;
         return Internal_Error;
   end Parse_Ref_Advertisement_Packet;

   function Validate_Ref_Advertisement_Stream
     (Data    : Stream_Element_Array;
      Summary : out Ref_Advertisement_Summary)
      return Status
   is
      Cursor : Stream_Element_Offset := Data'First;
      Object_Buffer : Stream_Element_Array
        (Stream_Element_Offset'(1) .. Stream_Element_Offset'(40));
      Object_Last   : Stream_Element_Offset;
      Ref_Buffer    : Stream_Element_Array
        (Stream_Element_Offset'(1)
         .. Stream_Element_Offset (Maximum_Ref_Name_Length + 3));
      Ref_Last      : Stream_Element_Offset;
      Cap_Buffer    : Stream_Element_Array
        (Stream_Element_Offset'(1)
         .. Stream_Element_Offset (Maximum_Pkt_Line_Payload_Length));
      Cap_Last      : Stream_Element_Offset;
      Has_Caps      : Boolean := False;
      Is_Peeled     : Boolean := False;
      Is_Symref     : Boolean := False;
   begin
      Summary := (others => <>);
      if Data'Length = 0 then
         return Invalid_Command;
      end if;

      while Cursor <= Data'Last loop
         declare
            Packet : constant Stream_Element_Array := Data (Cursor .. Data'Last);
            Pkt_Kind : Pkt_Line_Kind;
            Packet_Length : Natural := 0;
            Status_Value : Status;
         begin
            Status_Value := Parse_Pkt_Line_Header
              (Packet, Pkt_Kind, Packet_Length);
            if Status_Value /= Ok then
               Summary := (others => <>);
               return Status_Value;
            end if;

            case Pkt_Kind is
               when Pkt_Data =>
                  if Cursor + Stream_Element_Offset (Packet_Length) - 1
                    > Data'Last
                  then
                     Summary := (others => <>);
                     return Read_Failed;
                  end if;
                  Status_Value := Parse_Ref_Advertisement_Packet
                    (Data (Cursor
                       .. Cursor + Stream_Element_Offset (Packet_Length) - 1),
                     Object_Buffer,
                     Object_Last,
                     Ref_Buffer,
                     Ref_Last,
                     Cap_Buffer,
                     Cap_Last,
                     Has_Caps,
                     Is_Peeled,
                     Is_Symref);
                  if Status_Value /= Ok then
                     Summary := (others => <>);
                     return Status_Value;
                  end if;

                  Summary.Ref_Count := Summary.Ref_Count + 1;
                  if Is_Peeled then
                     Summary.Peeled_Count := Summary.Peeled_Count + 1;
                  end if;
                  if Is_Symref then
                     Summary.Symref_Count := Summary.Symref_Count + 1;
                  end if;
                  if Ref_Last = Ref_Buffer'First + 3
                    and then Slice_Equals
                      (Ref_Buffer (Ref_Buffer'First .. Ref_Last),
                       Ref_Buffer'First,
                       "HEAD")
                  then
                     Summary.Has_HEAD := True;
                  end if;
                  if Has_Caps then
                     Summary.Has_Capabilities := True;
                     Summary.Capability_Count :=
                       Summary.Capability_Count
                       + Capability_Token_Count
                           (Cap_Buffer, Cap_Buffer'First, Cap_Last);
                  end if;
                  Cursor := Cursor + Stream_Element_Offset (Packet_Length);
               when Pkt_Flush =>
                  Summary.Has_Flush := True;
                  Cursor := Cursor + 4;
                  if Cursor <= Data'Last then
                     Summary := (others => <>);
                     return Invalid_Command;
                  end if;
                  exit;
               when Pkt_Response_End =>
                  Summary.Has_Response_End := True;
                  Cursor := Cursor + 4;
                  if Cursor <= Data'Last then
                     Summary := (others => <>);
                     return Invalid_Command;
                  end if;
                  exit;
               when Pkt_Delimiter =>
                  Summary := (others => <>);
                  return Invalid_Command;
            end case;
         end;
      end loop;

      if Summary.Ref_Count = 0
        or else (not Summary.Has_Flush and then not Summary.Has_Response_End)
      then
         Summary := (others => <>);
         return Invalid_Command;
      end if;
      return Ok;
   exception
      when Constraint_Error =>
         Summary := (others => <>);
         return Read_Failed;
      when others =>
         Summary := (others => <>);
         return Internal_Error;
   end Validate_Ref_Advertisement_Stream;

   function Parse_Pack_Header
     (Data         : Stream_Element_Array;
      Version      : out Natural;
      Object_Count : out Natural)
      return Status
   is
   begin
      Version := 0;
      Object_Count := 0;

      if Data'Length < 12 then
         return Read_Failed;
      elsif Data (Data'First) /= Character'Pos ('P')
        or else Data (Data'First + 1) /= Character'Pos ('A')
        or else Data (Data'First + 2) /= Character'Pos ('C')
        or else Data (Data'First + 3) /= Character'Pos ('K')
      then
         return Invalid_Command;
      end if;

      Version := U32_At (Data, Data'First + 4);
      Object_Count := U32_At (Data, Data'First + 8);
      if Version /= 2 and then Version /= 3 then
         Version := 0;
         Object_Count := 0;
         return Unsupported_Feature;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Version := 0;
         Object_Count := 0;
         return Invalid_Command;
      when others =>
         Version := 0;
         Object_Count := 0;
         return Internal_Error;
   end Parse_Pack_Header;

   function Parse_Pack_Index_Header
     (Data    : Stream_Element_Array;
      Version : out Natural)
      return Status
   is
   begin
      Version := 0;

      if Data'Length < 8 then
         return Read_Failed;
      elsif Data (Data'First) /= 16#FF#
        or else Data (Data'First + 1) /= Character'Pos ('t')
        or else Data (Data'First + 2) /= Character'Pos ('O')
        or else Data (Data'First + 3) /= Character'Pos ('c')
      then
         return Invalid_Command;
      end if;

      Version := U32_At (Data, Data'First + 4);
      if Version /= 2 then
         Version := 0;
         return Unsupported_Feature;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Version := 0;
         return Invalid_Command;
      when others =>
         Version := 0;
         return Internal_Error;
   end Parse_Pack_Index_Header;

   function Parse_Pack_Index_Fanout
     (Data         : Stream_Element_Array;
      Object_Count : out Natural)
      return Status
   is
      Previous_Count : Natural := 0;
      Current_Count  : Natural := 0;
      Entry_Offset   : Stream_Element_Offset;
   begin
      Object_Count := 0;

      if Data'Length < 256 * 4 then
         return Read_Failed;
      end if;

      for Entry_Index in 0 .. 255 loop
         Entry_Offset :=
           Data'First + Stream_Element_Offset (Entry_Index * 4);
         Current_Count := U32_At (Data, Entry_Offset);
         if Current_Count < Previous_Count then
            Object_Count := 0;
            return Invalid_Command;
         end if;

         Previous_Count := Current_Count;
      end loop;

      Object_Count := Current_Count;
      return Ok;
   exception
      when Constraint_Error =>
         Object_Count := 0;
         return Invalid_Command;
      when others =>
         Object_Count := 0;
         return Internal_Error;
   end Parse_Pack_Index_Fanout;

   function Copy_Pack_Index_Object_ID
     (Data         : Stream_Element_Array;
      Object_Index : Natural;
      Object_ID    : out Stream_Element_Array;
      Last         : out Stream_Element_Offset)
      return Status
   is
      Entry_Start     : Stream_Element_Offset;
      Required_Length : Natural;
   begin
      Last := Object_ID'First - 1;

      if Object_ID'Length < Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
      then
         return Read_Failed;
      elsif Object_Index > (Natural'Last / Object_ID_SHA1_Raw_Length) - 1
      then
         return Invalid_Command;
      end if;

      Required_Length := (Object_Index + 1) * Object_ID_SHA1_Raw_Length;
      if Data'Length < Stream_Element_Offset (Required_Length) then
         return Read_Failed;
      end if;

      Entry_Start :=
        Data'First
        + Stream_Element_Offset (Object_Index * Object_ID_SHA1_Raw_Length);
      for Offset in 0 .. Object_ID_SHA1_Raw_Length - 1 loop
         Object_ID
           (Object_ID'First + Stream_Element_Offset (Offset)) :=
             Data (Entry_Start + Stream_Element_Offset (Offset));
      end loop;

      Last :=
        Object_ID'First
        + Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
        - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Object_ID'First - 1;
         return Read_Failed;
      when others =>
         Last := Object_ID'First - 1;
         return Internal_Error;
   end Copy_Pack_Index_Object_ID;

   function Parse_Pack_Index_CRC
     (Data         : Stream_Element_Array;
      Object_Index : Natural;
      CRC_Value    : out Natural)
      return Status
   is
      Entry_Start     : Stream_Element_Offset;
      Required_Length : Natural;
   begin
      CRC_Value := 0;

      if Object_Index > (Natural'Last / 4) - 1 then
         return Invalid_Command;
      end if;

      Required_Length := (Object_Index + 1) * 4;
      if Data'Length < Stream_Element_Offset (Required_Length) then
         return Read_Failed;
      end if;

      Entry_Start := Data'First + Stream_Element_Offset (Object_Index * 4);
      CRC_Value := U32_At (Data, Entry_Start);
      return Ok;
   exception
      when Constraint_Error =>
         CRC_Value := 0;
         return Invalid_Command;
      when others =>
         CRC_Value := 0;
         return Internal_Error;
   end Parse_Pack_Index_CRC;

   function Parse_Pack_Index_Offset
     (Data               : Stream_Element_Array;
      Object_Index       : Natural;
      Pack_Offset        : out Natural;
      Large_Offset_Index : out Natural;
      Uses_Large_Offset  : out Boolean)
      return Status
   is
      Entry_Start     : Stream_Element_Offset;
      Required_Length : Natural;
      First_Byte      : Stream_Element;
      Value           : Natural := 0;
   begin
      Pack_Offset := 0;
      Large_Offset_Index := 0;
      Uses_Large_Offset := False;

      if Object_Index > (Natural'Last / 4) - 1 then
         return Invalid_Command;
      end if;

      Required_Length := (Object_Index + 1) * 4;
      if Data'Length < Stream_Element_Offset (Required_Length) then
         return Read_Failed;
      end if;

      Entry_Start := Data'First + Stream_Element_Offset (Object_Index * 4);
      First_Byte := Data (Entry_Start);
      Value := Natural (First_Byte mod 128);
      for Offset in 1 .. 3 loop
         Value :=
           Value * 256
           + Natural (Data (Entry_Start + Stream_Element_Offset (Offset)));
      end loop;

      if First_Byte >= 128 then
         Uses_Large_Offset := True;
         Large_Offset_Index := Value;
      else
         Pack_Offset := Value;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Pack_Offset := 0;
         Large_Offset_Index := 0;
         Uses_Large_Offset := False;
         return Invalid_Command;
      when others =>
         Pack_Offset := 0;
         Large_Offset_Index := 0;
         Uses_Large_Offset := False;
         return Internal_Error;
   end Parse_Pack_Index_Offset;

   function Parse_Pack_Index_Large_Offset
     (Data               : Stream_Element_Array;
      Large_Offset_Index : Natural;
      Pack_Offset        : out Natural)
      return Status
   is
      Entry_Start     : Stream_Element_Offset;
      Required_Length : Natural;
      Value           : Natural := 0;
      Byte_Value      : Natural;
   begin
      Pack_Offset := 0;

      if Large_Offset_Index > (Natural'Last / 8) - 1 then
         return Invalid_Command;
      end if;

      Required_Length := (Large_Offset_Index + 1) * 8;
      if Data'Length < Stream_Element_Offset (Required_Length) then
         return Read_Failed;
      end if;

      Entry_Start :=
        Data'First + Stream_Element_Offset (Large_Offset_Index * 8);
      for Offset in 0 .. 7 loop
         Byte_Value :=
           Natural (Data (Entry_Start + Stream_Element_Offset (Offset)));
         if Value > (Natural'Last - Byte_Value) / 256 then
            Pack_Offset := 0;
            return Unsupported_Feature;
         end if;

         Value := Value * 256 + Byte_Value;
      end loop;

      Pack_Offset := Value;
      return Ok;
   exception
      when Constraint_Error =>
         Pack_Offset := 0;
         return Invalid_Command;
      when others =>
         Pack_Offset := 0;
         return Internal_Error;
   end Parse_Pack_Index_Large_Offset;

   function Copy_Pack_Index_Checksum
     (Data     : Stream_Element_Array;
      Checksum : out Stream_Element_Array;
      Last     : out Stream_Element_Offset)
      return Status
   is
   begin
      Last := Checksum'First - 1;

      if Data'Length < Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
        or else Checksum'Length
          < Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
      then
         return Read_Failed;
      end if;

      for Offset in 0 .. Object_ID_SHA1_Raw_Length - 1 loop
         Checksum (Checksum'First + Stream_Element_Offset (Offset)) :=
           Data (Data'First + Stream_Element_Offset (Offset));
      end loop;

      Last :=
        Checksum'First
        + Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
        - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Checksum'First - 1;
         return Read_Failed;
      when others =>
         Last := Checksum'First - 1;
         return Internal_Error;
   end Copy_Pack_Index_Checksum;

   function Compute_Pack_Index_Layout
     (Object_Count       : Natural;
      Large_Offset_Count : Natural;
      Layout             : out Pack_Index_Layout)
      return Status
   is
      Cursor : Natural := 0;

      function Add
        (Left  : Natural;
         Right : Natural)
         return Natural
      is
      begin
         if Left > Natural'Last - Right then
            raise Constraint_Error;
         end if;

         return Left + Right;
      end Add;

      function Mul
        (Left  : Natural;
         Right : Natural)
         return Natural
      is
      begin
         if Left /= 0 and then Right > Natural'Last / Left then
            raise Constraint_Error;
         end if;

         return Left * Right;
      end Mul;
   begin
      Layout := (others => 0);

      Layout.Header_Offset := 0;
      Cursor := 8;

      Layout.Fanout_Offset := Cursor;
      Cursor := Add (Cursor, 256 * 4);

      Layout.Object_IDs_Offset := Cursor;
      Cursor := Add (Cursor, Mul (Object_Count, Object_ID_SHA1_Raw_Length));

      Layout.CRCs_Offset := Cursor;
      Cursor := Add (Cursor, Mul (Object_Count, 4));

      Layout.Offsets_Offset := Cursor;
      Cursor := Add (Cursor, Mul (Object_Count, 4));

      Layout.Large_Offsets_Offset := Cursor;
      Cursor := Add (Cursor, Mul (Large_Offset_Count, 8));

      Layout.Pack_Checksum_Offset := Cursor;
      Cursor := Add (Cursor, Object_ID_SHA1_Raw_Length);

      Layout.Index_Checksum_Offset := Cursor;
      Cursor := Add (Cursor, Object_ID_SHA1_Raw_Length);

      Layout.Total_Length := Cursor;
      return Ok;
   exception
      when Constraint_Error =>
         Layout := (others => 0);
         return Unsupported_Feature;
      when others =>
      Layout := (others => 0);
      return Internal_Error;
   end Compute_Pack_Index_Layout;

   function Build_Pack_Index
     (Pack_Data      : Stream_Element_Array;
      Object_Scratch : out Stream_Element_Array;
      Index_Data     : out Stream_Element_Array;
      Last           : out Stream_Element_Offset)
      return Status
   is
      subtype Raw_Object_ID is Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));

      type Index_Record is record
         ID     : Raw_Object_ID := [others => 0];
         CRC    : Natural := 0;
         Offset : Natural := 0;
      end record;

      function CRC32 (Data : Stream_Element_Array) return Interfaces.Unsigned_32 is
         use type Interfaces.Unsigned_32;
         CRC : Interfaces.Unsigned_32 := 16#FFFF_FFFF#;
      begin
         for B of Data loop
            CRC := CRC xor Interfaces.Unsigned_32 (B);
            for Bit in 1 .. 8 loop
               if (CRC and 1) = 1 then
                  CRC := Interfaces.Shift_Right (CRC, 1) xor 16#EDB8_8320#;
               else
                  CRC := Interfaces.Shift_Right (CRC, 1);
               end if;
            end loop;
         end loop;
         return not CRC;
      end CRC32;

      procedure Store_U32
        (Value : Natural;
         Data  : in out Stream_Element_Array;
         First : Stream_Element_Offset)
      is
      begin
         Data (First) := Stream_Element ((Value / 16#01_00_00_00#) mod 256);
         Data (First + 1) := Stream_Element ((Value / 16#00_01_00_00#) mod 256);
         Data (First + 2) := Stream_Element ((Value / 16#00_00_01_00#) mod 256);
         Data (First + 3) := Stream_Element (Value mod 256);
      end Store_U32;

      function ID_Less (Left, Right : Raw_Object_ID) return Boolean is
      begin
         for Index in Left'Range loop
            if Left (Index) < Right (Index) then
               return True;
            elsif Left (Index) > Right (Index) then
               return False;
            end if;
         end loop;
         return False;
      end ID_Less;

      Pack_Version   : Natural := 0;
      Object_Count   : Natural := 0;
      Layout         : Pack_Index_Layout;
      Status_Value   : Status;
      Trailer_Offset : Natural := 0;
      Cursor         : Natural := 12;
      Digest_Value   : CryptoLib.Hashes.SHA1_Digest;

      function Index_At (Offset : Natural) return Stream_Element_Offset is
      begin
         return Index_Data'First + Stream_Element_Offset (Offset);
      end Index_At;
   begin
      Last := Index_Data'First - 1;

      Status_Value := Verify_Pack_Trailer_Checksum (Pack_Data);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Parse_Pack_Header (Pack_Data, Pack_Version, Object_Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Compute_Pack_Index_Layout (Object_Count, 0, Layout);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Index_Data'Length < Stream_Element_Offset (Layout.Total_Length) then
         return Read_Failed;
      end if;

      Trailer_Offset :=
        Natural (Pack_Data'Length) - Object_ID_SHA1_Raw_Length;

      if Object_Count = 0 then
         if Cursor /= Trailer_Offset then
            return Invalid_Command;
         end if;

         Index_Data
           (Index_Data'First
            .. Index_Data'First + Stream_Element_Offset (Layout.Total_Length) - 1) :=
              [others => 0];
         Index_Data (Index_At (0)) := 16#FF#;
         Index_Data (Index_At (1)) := Character'Pos ('t');
         Index_Data (Index_At (2)) := Character'Pos ('O');
         Index_Data (Index_At (3)) := Character'Pos ('c');
         Store_U32 (2, Index_Data, Index_At (4));
         Index_Data
           (Index_At (Layout.Pack_Checksum_Offset)
            .. Index_At (Layout.Pack_Checksum_Offset)
               + Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
               - 1) :=
             Pack_Data
               (Pack_Data'Last
                - Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
                + 1
                .. Pack_Data'Last);
         Digest_Value :=
           CryptoLib.Hashes.SHA1
                (Index_Data
                (Index_Data'First
                 .. Index_At (Layout.Index_Checksum_Offset) - 1));
         declare
            Cursor_Out : Stream_Element_Offset :=
              Index_At (Layout.Index_Checksum_Offset);
         begin
            for Digest_Index in Digest_Value'Range loop
               Index_Data (Cursor_Out) := Digest_Value (Digest_Index);
               Cursor_Out := Cursor_Out + 1;
            end loop;
         end;
         Last :=
           Index_Data'First + Stream_Element_Offset (Layout.Total_Length) - 1;
         return Ok;
      elsif Object_Scratch'Length = 0 then
         return Read_Failed;
      end if;

      declare
         Records : array (Natural range 0 .. Object_Count - 1) of Index_Record;
      begin
         if Object_Count > 0 then
            for Object_Index in 0 .. Object_Count - 1 loop
               declare
                  Kind        : Pack_Object_Kind := Pack_Blob;
                  Size        : Natural := 0;
                  Header_Size : Natural := 0;
                  Payload_Offset : Natural := 0;
                  Object_Last : Stream_Element_Offset;
                  Next_Offset : Natural := 0;
                  Raw_Last    : Stream_Element_Offset;
                  Object_First : constant Stream_Element_Offset :=
                    Pack_Data'First + Stream_Element_Offset (Cursor);
               begin
                  Status_Value :=
                    Inflate_Pack_Object_At_Offset
                      (Pack_Data,
                       Cursor,
                       Kind,
                       Size,
                       Header_Size,
                       Payload_Offset,
                       Object_Scratch,
                       Object_Last,
                       Next_Offset);
                  if Status_Value /= Ok then
                     return Status_Value;
                  elsif Header_Size = 0
                    or else Payload_Offset <= Cursor
                    or else Size > Natural (Object_Scratch'Length)
                  then
                     return Invalid_Command;
                  elsif Kind in Pack_OFS_Delta | Pack_REF_Delta then
                     return Unsupported_Feature;
                  elsif Next_Offset <= Cursor
                    or else Next_Offset > Trailer_Offset
                  then
                     return Invalid_Command;
                  end if;

                  Status_Value :=
                    Compute_Object_ID
                      (Kind,
                       Object_Scratch (Object_Scratch'First .. Object_Last),
                       Records (Object_Index).ID,
                       Raw_Last);
                  if Status_Value /= Ok then
                     return Status_Value;
                  elsif Raw_Last /= Records (Object_Index).ID'Last then
                     return Invalid_Command;
                  end if;
                  Records (Object_Index).CRC :=
                    Natural
                      (CRC32
                         (Pack_Data
                            (Object_First
                             .. Pack_Data'First
                                + Stream_Element_Offset (Next_Offset)
                                - 1)));
                  Records (Object_Index).Offset := Cursor;
                  Cursor := Next_Offset;
               end;
            end loop;
         end if;

         if Cursor /= Trailer_Offset then
            return Invalid_Command;
         end if;

         if Object_Count > 1 then
            for I in 0 .. Object_Count - 2 loop
               for J in I + 1 .. Object_Count - 1 loop
                  if ID_Less (Records (J).ID, Records (I).ID) then
                     declare
                        Temp : constant Index_Record := Records (I);
                     begin
                        Records (I) := Records (J);
                        Records (J) := Temp;
                     end;
                  end if;
               end loop;
            end loop;
         end if;

         Index_Data
           (Index_Data'First
            .. Index_Data'First + Stream_Element_Offset (Layout.Total_Length) - 1) :=
              [others => 0];
         Index_Data (Index_At (0)) := 16#FF#;
         Index_Data (Index_At (1)) := Character'Pos ('t');
         Index_Data (Index_At (2)) := Character'Pos ('O');
         Index_Data (Index_At (3)) := Character'Pos ('c');
         Store_U32 (2, Index_Data, Index_At (4));

         declare
            Running : Natural := 0;
            Object_Pos : Natural := 0;
         begin
            for Bucket in 0 .. 255 loop
               while Object_Pos < Object_Count
                 and then Natural (Records (Object_Pos).ID (Records (Object_Pos).ID'First))
                   = Bucket
               loop
                  Running := Running + 1;
                  Object_Pos := Object_Pos + 1;
               end loop;
               Store_U32
                 (Running,
                  Index_Data,
                  Index_At (Layout.Fanout_Offset + Bucket * 4));
            end loop;
         end;

         if Object_Count > 0 then
            for Object_Index in 0 .. Object_Count - 1 loop
               declare
                  ID_First : constant Stream_Element_Offset :=
                    Index_At
                      (Layout.Object_IDs_Offset
                       + Object_Index * Object_ID_SHA1_Raw_Length);
               begin
                  Index_Data
                    (ID_First
                     .. ID_First
                        + Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
                        - 1) := Records (Object_Index).ID;
                  Store_U32
                    (Records (Object_Index).CRC,
                     Index_Data,
                     Index_At (Layout.CRCs_Offset + Object_Index * 4));
                  Store_U32
                    (Records (Object_Index).Offset,
                     Index_Data,
                     Index_At (Layout.Offsets_Offset + Object_Index * 4));
               end;
            end loop;
         end if;

         Index_Data
           (Index_At (Layout.Pack_Checksum_Offset)
            .. Index_At (Layout.Pack_Checksum_Offset)
               + Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
               - 1) :=
             Pack_Data
               (Pack_Data'Last
                - Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
                + 1
                .. Pack_Data'Last);

         Digest_Value :=
           CryptoLib.Hashes.SHA1
                (Index_Data
                (Index_Data'First
                 .. Index_At (Layout.Index_Checksum_Offset) - 1));
         declare
            Cursor_Out : Stream_Element_Offset :=
              Index_At (Layout.Index_Checksum_Offset);
         begin
            for Digest_Index in Digest_Value'Range loop
               Index_Data (Cursor_Out) := Digest_Value (Digest_Index);
               Cursor_Out := Cursor_Out + 1;
            end loop;
         end;
      end;

      Last :=
        Index_Data'First + Stream_Element_Offset (Layout.Total_Length) - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Index_Data'First - 1;
         return Invalid_Command;
      when others =>
         Last := Index_Data'First - 1;
         return Internal_Error;
   end Build_Pack_Index;

   function Validate_Pack_Index_Object_ID_Order
     (Data         : Stream_Element_Array;
      Object_Count : Natural)
      return Status
   is
      Required_Length : Natural;

      function Entry_Start
        (Index : Natural)
         return Stream_Element_Offset
      is
      begin
         return
           Data'First
           + Stream_Element_Offset (Index * Object_ID_SHA1_Raw_Length);
      end Entry_Start;

      function Entry_Less
        (Left_Index  : Natural;
         Right_Index : Natural)
         return Boolean
      is
         Left_Start  : constant Stream_Element_Offset :=
           Entry_Start (Left_Index);
         Right_Start : constant Stream_Element_Offset :=
           Entry_Start (Right_Index);
      begin
         for Offset in 0 .. Object_ID_SHA1_Raw_Length - 1 loop
            declare
               Left_Byte : constant Stream_Element :=
                 Data (Left_Start + Stream_Element_Offset (Offset));
               Right_Byte : constant Stream_Element :=
                 Data (Right_Start + Stream_Element_Offset (Offset));
            begin
               if Left_Byte < Right_Byte then
                  return True;
               elsif Left_Byte > Right_Byte then
                  return False;
               end if;
            end;
         end loop;

         return False;
      end Entry_Less;
   begin
      if Object_Count <= 1 then
         return Ok;
      elsif Object_Count > Natural'Last / Object_ID_SHA1_Raw_Length then
         return Invalid_Command;
      end if;

      Required_Length := Object_Count * Object_ID_SHA1_Raw_Length;
      if Data'Length < Stream_Element_Offset (Required_Length) then
         return Read_Failed;
      end if;

      for Index in 1 .. Object_Count - 1 loop
         if not Entry_Less (Index - 1, Index) then
            return Invalid_Command;
         end if;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Internal_Error;
   end Validate_Pack_Index_Object_ID_Order;

   function Validate_Pack_Index_Fanout_Matches_Object_IDs
     (Fanout       : Stream_Element_Array;
      Object_IDs   : Stream_Element_Array;
      Object_Count : Natural)
      return Status
   is
      type Bucket_Counts is array (Natural range 0 .. 255) of Natural;

      Buckets : Bucket_Counts := [others => 0];
      Required_Length : Natural;
      Running_Count   : Natural := 0;
      Fanout_Value    : Natural;
      Bucket_Index    : Natural;
   begin
      if Fanout'Length < 256 * 4 then
         return Read_Failed;
      elsif Object_Count > Natural'Last / Object_ID_SHA1_Raw_Length then
         return Invalid_Command;
      end if;

      Required_Length := Object_Count * Object_ID_SHA1_Raw_Length;
      if Object_IDs'Length < Stream_Element_Offset (Required_Length) then
         return Read_Failed;
      end if;

      if Object_Count > 0 then
         for Object_Index in 0 .. Object_Count - 1 loop
            Bucket_Index :=
              Natural
                (Object_IDs
                   (Object_IDs'First
                    + Stream_Element_Offset
                      (Object_Index * Object_ID_SHA1_Raw_Length)));
            Buckets (Bucket_Index) := Buckets (Bucket_Index) + 1;
         end loop;
      end if;

      for Index in 0 .. 255 loop
         Running_Count := Running_Count + Buckets (Index);
         Fanout_Value :=
           U32_At
             (Fanout, Fanout'First + Stream_Element_Offset (Index * 4));
         if Fanout_Value /= Running_Count then
            return Invalid_Command;
         end if;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Internal_Error;
   end Validate_Pack_Index_Fanout_Matches_Object_IDs;

   function Validate_Pack_Index_Large_Offset_Count
     (Offsets_Table      : Stream_Element_Array;
      Object_Count       : Natural;
      Large_Offset_Count : Natural)
      return Status
   is
      Required_Length : Natural;
      Marker_Count    : Natural := 0;
      Entry_Start     : Stream_Element_Offset;
   begin
      if Object_Count > Natural'Last / 4 then
         return Invalid_Command;
      end if;

      Required_Length := Object_Count * 4;
      if Offsets_Table'Length < Stream_Element_Offset (Required_Length) then
         return Read_Failed;
      end if;

      if Object_Count > 0 then
         for Object_Index in 0 .. Object_Count - 1 loop
            Entry_Start :=
              Offsets_Table'First + Stream_Element_Offset (Object_Index * 4);
            if Offsets_Table (Entry_Start) >= 128 then
               if Marker_Count = Natural'Last then
                  return Unsupported_Feature;
               end if;

               Marker_Count := Marker_Count + 1;
            end if;
         end loop;
      end if;

      if Marker_Count /= Large_Offset_Count then
         return Invalid_Command;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Internal_Error;
   end Validate_Pack_Index_Large_Offset_Count;

   function Validate_Pack_Index
     (Data               : Stream_Element_Array;
      Object_Count       : out Natural;
      Large_Offset_Count : out Natural;
      Layout             : out Pack_Index_Layout)
      return Status
   is
      Version_Value : Natural := 0;
      Count_Value   : Natural := 0;
      Minimum_Layout : Pack_Index_Layout;
      Status_Value  : Status;
      Extra_Length  : Natural;
      First         : constant Stream_Element_Offset := Data'First;

      function Offset_At (Offset : Natural) return Stream_Element_Offset is
      begin
         return First + Stream_Element_Offset (Offset);
      end Offset_At;
   begin
      Object_Count := 0;
      Large_Offset_Count := 0;
      Layout := (others => 0);

      Status_Value := Parse_Pack_Index_Header (Data, Version_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Data'Length < Stream_Element_Offset (8 + 256 * 4) then
         return Read_Failed;
      end if;

      Status_Value :=
        Parse_Pack_Index_Fanout
          (Data (Offset_At (8) .. Data'Last),
           Count_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Compute_Pack_Index_Layout (Count_Value, 0, Minimum_Layout);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Data'Length < Stream_Element_Offset (Minimum_Layout.Total_Length) then
         return Read_Failed;
      end if;

      Extra_Length := Natural (Data'Length)
        - Minimum_Layout.Total_Length;
      if Extra_Length mod 8 /= 0 then
         return Invalid_Command;
      end if;

      Large_Offset_Count := Extra_Length / 8;
      Status_Value :=
        Compute_Pack_Index_Layout
          (Count_Value, Large_Offset_Count, Layout);
      if Status_Value /= Ok then
         Object_Count := 0;
         Large_Offset_Count := 0;
         return Status_Value;
      end if;

      if Data'Length /= Stream_Element_Offset (Layout.Total_Length) then
         Object_Count := 0;
         Large_Offset_Count := 0;
         Layout := (others => 0);
         return Invalid_Command;
      end if;

      Status_Value :=
        Validate_Pack_Index_Object_ID_Order
          (Data (Offset_At (Layout.Object_IDs_Offset) .. Data'Last),
           Count_Value);
      if Status_Value /= Ok then
         Object_Count := 0;
         Large_Offset_Count := 0;
         Layout := (others => 0);
         return Status_Value;
      end if;

      Status_Value :=
        Validate_Pack_Index_Fanout_Matches_Object_IDs
          (Data (Offset_At (Layout.Fanout_Offset) .. Data'Last),
           Data (Offset_At (Layout.Object_IDs_Offset) .. Data'Last),
           Count_Value);
      if Status_Value /= Ok then
         Object_Count := 0;
         Large_Offset_Count := 0;
         Layout := (others => 0);
         return Status_Value;
      end if;

      Status_Value :=
        Validate_Pack_Index_Large_Offset_Count
          (Data (Offset_At (Layout.Offsets_Offset) .. Data'Last),
           Count_Value,
           Large_Offset_Count);
      if Status_Value /= Ok then
         Object_Count := 0;
         Large_Offset_Count := 0;
         Layout := (others => 0);
         return Status_Value;
      end if;

      Object_Count := Count_Value;
      return Ok;
   exception
      when Constraint_Error =>
         Object_Count := 0;
         Large_Offset_Count := 0;
         Layout := (others => 0);
         return Invalid_Command;
      when others =>
         Object_Count := 0;
         Large_Offset_Count := 0;
         Layout := (others => 0);
         return Internal_Error;
   end Validate_Pack_Index;

   function Verify_Pack_Trailer_Checksum
     (Pack_Data : Stream_Element_Array)
      return Status
   is
      Version_Value : Natural := 0;
      Count_Value   : Natural := 0;
      Digest_Value  : CryptoLib.Hashes.SHA1_Digest;
      Trailer_First : Stream_Element_Offset;
      Status_Value  : Status;
   begin
      if Pack_Data'Length
        < Stream_Element_Offset (12 + Object_ID_SHA1_Raw_Length)
      then
         return Read_Failed;
      end if;

      Status_Value := Parse_Pack_Header (Pack_Data, Version_Value, Count_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Trailer_First :=
        Pack_Data'Last - Stream_Element_Offset (Object_ID_SHA1_Raw_Length) + 1;
      Digest_Value := CryptoLib.Hashes.SHA1
        (Pack_Data (Pack_Data'First .. Trailer_First - 1));

      if SHA1_Digest_Matches
        (Digest_Value, Pack_Data (Trailer_First .. Pack_Data'Last))
      then
         return Ok;
      end if;

      return Invalid_Command;
   exception
      when Constraint_Error =>
         return Read_Failed;
      when others =>
         return Internal_Error;
   end Verify_Pack_Trailer_Checksum;

   function Verify_Pack_Index_Checksum
     (Index_Data : Stream_Element_Array)
      return Status
   is
      Object_Count       : Natural := 0;
      Large_Offset_Count : Natural := 0;
      Layout             : Pack_Index_Layout;
      Digest_Value       : CryptoLib.Hashes.SHA1_Digest;
      Status_Value       : Status;

      function Offset_At (Offset : Natural) return Stream_Element_Offset is
      begin
         return Index_Data'First + Stream_Element_Offset (Offset);
      end Offset_At;
   begin
      Status_Value :=
        Validate_Pack_Index
          (Index_Data, Object_Count, Large_Offset_Count, Layout);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Digest_Value := CryptoLib.Hashes.SHA1
        (Index_Data
           (Index_Data'First .. Offset_At (Layout.Index_Checksum_Offset) - 1));

      if SHA1_Digest_Matches
        (Digest_Value,
         Index_Data
           (Offset_At (Layout.Index_Checksum_Offset) .. Index_Data'Last))
      then
         return Ok;
      end if;

      return Invalid_Command;
   exception
      when Constraint_Error =>
         return Read_Failed;
      when others =>
         return Internal_Error;
   end Verify_Pack_Index_Checksum;

   function Verify_Pack_Index_Pack_Checksum
     (Index_Data              : Stream_Element_Array;
      Expected_Pack_Checksum  : Stream_Element_Array)
      return Status
   is
      Object_Count       : Natural := 0;
      Large_Offset_Count : Natural := 0;
      Layout             : Pack_Index_Layout;
      Status_Value       : Status;

      function Offset_At (Offset : Natural) return Stream_Element_Offset is
      begin
         return Index_Data'First + Stream_Element_Offset (Offset);
      end Offset_At;
   begin
      if Expected_Pack_Checksum'Length
        /= Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
      then
         return Read_Failed;
      end if;

      Status_Value :=
        Validate_Pack_Index
          (Index_Data, Object_Count, Large_Offset_Count, Layout);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      for Offset in 0 .. Object_ID_SHA1_Raw_Length - 1 loop
         if Index_Data
              (Offset_At (Layout.Pack_Checksum_Offset)
               + Stream_Element_Offset (Offset))
           /= Expected_Pack_Checksum
              (Expected_Pack_Checksum'First + Stream_Element_Offset (Offset))
         then
            return Invalid_Command;
         end if;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         return Read_Failed;
      when others =>
         return Internal_Error;
   end Verify_Pack_Index_Pack_Checksum;

   function Find_Pack_Index_Object
     (Index_Data        : Stream_Element_Array;
      Object_ID         : Stream_Element_Array;
      Object_Index      : out Natural;
      Pack_Offset       : out Natural)
      return Status
   is
      Object_Count       : Natural := 0;
      Large_Offset_Count : Natural := 0;
      Layout             : Pack_Index_Layout;
      Status_Value       : Status;

      function Offset_At (Offset : Natural) return Stream_Element_Offset is
      begin
         return Index_Data'First + Stream_Element_Offset (Offset);
      end Offset_At;

      function Compare_Object_ID
        (Index : Natural)
         return Integer
      is
         Entry_First : constant Stream_Element_Offset :=
           Offset_At
             (Layout.Object_IDs_Offset
              + Index * Object_ID_SHA1_Raw_Length);
      begin
         for Offset in 0 .. Object_ID_SHA1_Raw_Length - 1 loop
            declare
               Left_Byte : constant Stream_Element :=
                 Index_Data (Entry_First + Stream_Element_Offset (Offset));
               Right_Byte : constant Stream_Element :=
                 Object_ID
                   (Object_ID'First + Stream_Element_Offset (Offset));
            begin
               if Left_Byte < Right_Byte then
                  return -1;
               elsif Left_Byte > Right_Byte then
                  return 1;
               end if;
            end;
         end loop;

         return 0;
      end Compare_Object_ID;
   begin
      Object_Index := 0;
      Pack_Offset := 0;

      if Object_ID'Length /= Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
      then
         return Read_Failed;
      end if;

      Status_Value :=
        Validate_Pack_Index
          (Index_Data, Object_Count, Large_Offset_Count, Layout);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Object_Count = 0 then
         return Invalid_Command;
      end if;

      declare
         Low  : Natural := 0;
         High : Natural := Object_Count - 1;
      begin
         loop
            declare
               Mid        : constant Natural := Low + (High - Low) / 2;
               Comparison : constant Integer := Compare_Object_ID (Mid);
            begin
               if Comparison = 0 then
                  declare
                     Large_Offset_Index : Natural := 0;
                     Uses_Large_Offset  : Boolean := False;
                  begin
                     Status_Value :=
                       Parse_Pack_Index_Offset
                         (Index_Data
                            (Offset_At (Layout.Offsets_Offset)
                             .. Index_Data'Last),
                          Mid,
                          Pack_Offset,
                          Large_Offset_Index,
                          Uses_Large_Offset);
                     if Status_Value /= Ok then
                        Object_Index := 0;
                        Pack_Offset := 0;
                        return Status_Value;
                     end if;

                     if Uses_Large_Offset then
                        Status_Value :=
                          Parse_Pack_Index_Large_Offset
                            (Index_Data
                               (Offset_At (Layout.Large_Offsets_Offset)
                                .. Index_Data'Last),
                             Large_Offset_Index,
                             Pack_Offset);
                        if Status_Value /= Ok then
                           Object_Index := 0;
                           Pack_Offset := 0;
                           return Status_Value;
                        end if;
                     end if;

                     Object_Index := Mid;
                     return Ok;
                  end;
               elsif Comparison < 0 then
                  exit when Mid = Natural'Last;
                  Low := Mid + 1;
               else
                  exit when Mid = 0;
                  High := Mid - 1;
               end if;

               exit when Low > High;
            end;
         end loop;
      end;

      Object_Index := 0;
      Pack_Offset := 0;
      return Invalid_Command;
   exception
      when Constraint_Error =>
         Object_Index := 0;
         Pack_Offset := 0;
         return Invalid_Command;
      when others =>
         Object_Index := 0;
         Pack_Offset := 0;
         return Internal_Error;
   end Find_Pack_Index_Object;

   function Find_Pack_Index_Object_Hex
     (Index_Data        : Stream_Element_Array;
      Object_ID_Hex     : Stream_Element_Array;
      Object_Index      : out Natural;
      Pack_Offset       : out Natural)
      return Status
   is
      Object_ID :
        Stream_Element_Array
          (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Last_Value : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Object_Index := 0;
      Pack_Offset := 0;

      Status_Value :=
        Parse_Object_ID_Hex (Object_ID_Hex, Object_ID, Last_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return
        Find_Pack_Index_Object
          (Index_Data, Object_ID, Object_Index, Pack_Offset);
   exception
      when Constraint_Error =>
         Object_Index := 0;
         Pack_Offset := 0;
         return Invalid_Command;
      when others =>
         Object_Index := 0;
         Pack_Offset := 0;
         return Internal_Error;
   end Find_Pack_Index_Object_Hex;

   function List_Pack_Index_Object_IDs
     (Index_Data     : Stream_Element_Array;
      Object_IDs_Hex : out Object_ID_Hex_Array;
      Count          : out Natural)
      return Status
   is
      Object_Count       : Natural := 0;
      Large_Offset_Count : Natural := 0;
      Layout             : Pack_Index_Layout;
      Status_Value       : Status;
      Raw_ID             :
        Stream_Element_Array
          (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last           : Stream_Element_Offset;
      Hex_ID             :
        Stream_Element_Array
          (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Hex_Last           : Stream_Element_Offset;
      First              : constant Stream_Element_Offset := Index_Data'First;

      function Offset_At (Offset : Natural) return Stream_Element_Offset is
      begin
         return First + Stream_Element_Offset (Offset);
      end Offset_At;
   begin
      Count := 0;
      Status_Value :=
        Validate_Pack_Index
          (Index_Data, Object_Count, Large_Offset_Count, Layout);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Object_Count > Object_IDs_Hex'Length then
         return Read_Failed;
      end if;

      for Index in 0 .. Object_Count - 1 loop
         Status_Value :=
           Copy_Pack_Index_Object_ID
             (Index_Data (Offset_At (Layout.Object_IDs_Offset) .. Index_Data'Last),
              Index,
              Raw_ID,
              Raw_Last);
         if Status_Value /= Ok then
            Count := 0;
            return Status_Value;
         elsif Raw_Last /= Raw_ID'Last then
            Count := 0;
            return Invalid_Command;
         end if;

         Status_Value := Encode_Object_ID_Hex (Raw_ID, Hex_ID, Hex_Last);
         if Status_Value /= Ok then
            Count := 0;
            return Status_Value;
         elsif Hex_Last /= Hex_ID'Last then
            Count := 0;
            return Invalid_Command;
         end if;

         Count := Count + 1;
         declare
            Target_Index : constant Positive := Object_IDs_Hex'First + Count - 1;
         begin
            for Offset in 0 .. Object_ID_SHA1_Hex_Length - 1 loop
               Object_IDs_Hex (Target_Index) (Offset + 1) :=
                 Hex_ID (Hex_ID'First + Stream_Element_Offset (Offset));
            end loop;
         end;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         Count := 0;
         return Invalid_Command;
      when others =>
         Count := 0;
         return Internal_Error;
   end List_Pack_Index_Object_IDs;

   function Validate_Pack_Index_Offsets
     (Index_Data     : Stream_Element_Array;
      Pack_Data      : Stream_Element_Array;
      Scratch        : out Stream_Element_Array;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return Status
   is
      Index_Count        : Natural := 0;
      Large_Count        : Natural := 0;
      Pack_Count         : Natural := 0;
      Pack_Trailer       : Natural := 0;
      Layout             : Pack_Index_Layout;
      Status_Value       : Status;
      First              : constant Stream_Element_Offset := Index_Data'First;

      function Offset_At (Offset : Natural) return Stream_Element_Offset is
      begin
         return First + Stream_Element_Offset (Offset);
      end Offset_At;

      function Resolve_Index_Offset
        (Index       : Natural;
         Pack_Offset : out Natural)
         return Status
      is
         Large_Index : Natural := 0;
         Uses_Large  : Boolean := False;
         Local_Status : Status;
      begin
         Pack_Offset := 0;
         Local_Status :=
           Parse_Pack_Index_Offset
             (Index_Data (Offset_At (Layout.Offsets_Offset)
              .. Index_Data'Last),
              Index,
              Pack_Offset,
              Large_Index,
              Uses_Large);
         if Local_Status /= Ok then
            Pack_Offset := 0;
            return Local_Status;
         elsif Uses_Large then
            Local_Status :=
              Parse_Pack_Index_Large_Offset
                (Index_Data (Offset_At (Layout.Large_Offsets_Offset)
                 .. Index_Data'Last),
                 Large_Index,
                 Pack_Offset);
            if Local_Status /= Ok then
               Pack_Offset := 0;
            end if;
            return Local_Status;
         end if;

         return Ok;
      end Resolve_Index_Offset;

      function Offset_Is_Object_Start (Target : Natural) return Boolean is
         Cursor         : Natural := 12;
         Kind_Value     : Pack_Object_Kind := Pack_Blob;
         Size_Value     : Natural := 0;
         Header_Length  : Natural := 0;
         Payload_Offset : Natural := 0;
         Last_Value     : Stream_Element_Offset;
         Next_Value     : Natural := 0;
         Local_Status   : Status;
      begin
         for Object_Number in 1 .. Pack_Count loop
            if Cursor = Target then
               return True;
            elsif Cursor >= Pack_Trailer then
               return False;
            end if;

            Local_Status :=
              Inflate_Pack_Object_At_Offset
                (Pack_Data,
                 Cursor,
                 Kind_Value,
                 Size_Value,
                 Header_Length,
                 Payload_Offset,
                 Scratch,
                 Last_Value,
                 Next_Value);
            if Local_Status /= Ok
              or else Next_Value <= Cursor
              or else Next_Value > Pack_Trailer
            then
               return False;
            elsif Object_Number < Pack_Count
              and then Next_Value = Pack_Trailer
            then
               return False;
            end if;

            Cursor := Next_Value;
         end loop;

         return False;
      end Offset_Is_Object_Start;
   begin
      Object_Count := 0;
      Trailer_Offset := 0;

      Status_Value :=
        Validate_Pack_Index (Index_Data, Index_Count, Large_Count, Layout);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Validate_Pack_Object_Sequence
          (Pack_Data, Scratch, Pack_Count, Pack_Trailer);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Index_Count /= Pack_Count then
         return Invalid_Command;
      end if;

      if Index_Count > 0 then
         for Index in 0 .. Index_Count - 1 loop
            declare
               Current_Offset : Natural := 0;
            begin
               Status_Value := Resolve_Index_Offset (Index, Current_Offset);
               if Status_Value /= Ok then
                  return Status_Value;
               elsif not Offset_Is_Object_Start (Current_Offset) then
                  return Invalid_Command;
               end if;

               if Index > 0 then
                  for Previous in 0 .. Index - 1 loop
                     declare
                        Previous_Offset : Natural := 0;
                     begin
                        Status_Value :=
                          Resolve_Index_Offset (Previous, Previous_Offset);
                        if Status_Value /= Ok then
                           return Status_Value;
                        elsif Previous_Offset = Current_Offset then
                           return Invalid_Command;
                        end if;
                     end;
                  end loop;
               end if;
            end;
         end loop;
      end if;

      Object_Count := Index_Count;
      Trailer_Offset := Pack_Trailer;
      return Ok;
   exception
      when Constraint_Error =>
         Object_Count := 0;
         Trailer_Offset := 0;
         return Invalid_Command;
      when others =>
         Object_Count := 0;
         Trailer_Offset := 0;
         return Internal_Error;
   end Validate_Pack_Index_Offsets;

   function Validate_Pack_Index_CRCs
     (Index_Data     : Stream_Element_Array;
      Pack_Data      : Stream_Element_Array;
      Scratch        : out Stream_Element_Array;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return Status
   is
      use type Interfaces.Unsigned_32;

      Index_Count  : Natural := 0;
      Large_Count  : Natural := 0;
      Pack_Trailer : Natural := 0;
      Layout       : Pack_Index_Layout;
      Status_Value : Status;
      First        : constant Stream_Element_Offset := Index_Data'First;

      function Offset_At (Offset : Natural) return Stream_Element_Offset is
      begin
         return First + Stream_Element_Offset (Offset);
      end Offset_At;

      function CRC32
        (Data : Stream_Element_Array)
         return Interfaces.Unsigned_32
      is
         CRC : Interfaces.Unsigned_32 := 16#FFFF_FFFF#;
      begin
         for B of Data loop
            CRC := CRC xor Interfaces.Unsigned_32 (B);
            for Bit in 1 .. 8 loop
               if (CRC and 1) = 1 then
                  CRC := Interfaces.Shift_Right (CRC, 1) xor 16#EDB8_8320#;
               else
                  CRC := Interfaces.Shift_Right (CRC, 1);
               end if;
            end loop;
         end loop;

         return not CRC;
      end CRC32;

      function Resolve_Index_Offset
        (Index       : Natural;
         Pack_Offset : out Natural)
         return Status
      is
         Large_Index  : Natural := 0;
         Uses_Large   : Boolean := False;
         Local_Status : Status;
      begin
         Pack_Offset := 0;
         Local_Status :=
           Parse_Pack_Index_Offset
             (Index_Data (Offset_At (Layout.Offsets_Offset)
              .. Index_Data'Last),
              Index,
              Pack_Offset,
              Large_Index,
              Uses_Large);
         if Local_Status /= Ok then
            Pack_Offset := 0;
            return Local_Status;
         elsif Uses_Large then
            Local_Status :=
              Parse_Pack_Index_Large_Offset
                (Index_Data (Offset_At (Layout.Large_Offsets_Offset)
                 .. Index_Data'Last),
                 Large_Index,
                 Pack_Offset);
            if Local_Status /= Ok then
               Pack_Offset := 0;
            end if;
            return Local_Status;
         end if;

         return Ok;
      end Resolve_Index_Offset;

      function Object_End_Offset (Start_Offset : Natural) return Natural is
         End_Offset : Natural := Pack_Trailer;
      begin
         if Index_Count > 0 then
            for Index in 0 .. Index_Count - 1 loop
               declare
                  Candidate : Natural := 0;
                  Local_Status : Status;
               begin
                  Local_Status := Resolve_Index_Offset (Index, Candidate);
                  if Local_Status /= Ok then
                     return 0;
                  elsif Candidate > Start_Offset
                    and then Candidate < End_Offset
                  then
                     End_Offset := Candidate;
                  end if;
               end;
            end loop;
         end if;

         return End_Offset;
      end Object_End_Offset;
   begin
      Object_Count := 0;
      Trailer_Offset := 0;

      Status_Value :=
        Validate_Pack_Index_Offsets
          (Index_Data, Pack_Data, Scratch, Index_Count, Pack_Trailer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Validate_Pack_Index (Index_Data, Index_Count, Large_Count, Layout);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Index_Count > 0 then
         for Index in 0 .. Index_Count - 1 loop
            declare
               Start_Offset : Natural := 0;
               End_Offset   : Natural := 0;
               Expected_CRC : Interfaces.Unsigned_32 := 0;
               Actual_CRC   : Interfaces.Unsigned_32 := 0;
            begin
               Status_Value := Resolve_Index_Offset (Index, Start_Offset);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;

               End_Offset := Object_End_Offset (Start_Offset);
               if End_Offset <= Start_Offset
                 or else End_Offset > Pack_Trailer
               then
                  return Invalid_Command;
               end if;

               Expected_CRC :=
                 U32_Raw_At
                   (Index_Data,
                    Offset_At (Layout.CRCs_Offset + Index * 4));

               Actual_CRC :=
                 CRC32
                   (Pack_Data
                      (Pack_Data'First + Stream_Element_Offset (Start_Offset)
                       .. Pack_Data'First
                         + Stream_Element_Offset (End_Offset - 1)));
               if Actual_CRC /= Expected_CRC then
                  return Invalid_Command;
               end if;
            end;
         end loop;
      end if;

      Object_Count := Index_Count;
      Trailer_Offset := Pack_Trailer;
      return Ok;
   exception
      when Constraint_Error =>
         Object_Count := 0;
         Trailer_Offset := 0;
         return Invalid_Command;
      when others =>
         Object_Count := 0;
         Trailer_Offset := 0;
         return Internal_Error;
   end Validate_Pack_Index_CRCs;

   function Validate_Pack_Delta_Bases
     (Index_Data     : Stream_Element_Array;
      Pack_Data      : Stream_Element_Array;
      Scratch        : out Stream_Element_Array;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return Status
   is
      Count_Value     : Natural := 0;
      Trailer_Value   : Natural := 0;
      Cursor          : Natural := 12;
      Status_Value    : Status;
      Kind_Value      : Pack_Object_Kind := Pack_Blob;
      Size_Value      : Natural := 0;
      Header_Length   : Natural := 0;
      Payload_Offset  : Natural := 0;
      Last_Value      : Stream_Element_Offset;
      Next_Value      : Natural := 0;
      Base_ID         :
        Stream_Element_Array
          (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Base_Last       : Stream_Element_Offset;
      Consumed        : Natural := 0;
      Base_Index      : Natural := 0;
      Base_Offset     : Natural := 0;

      function Object_Start_Exists (Target : Natural) return Boolean is
         Local_Cursor         : Natural := 12;
         Local_Kind           : Pack_Object_Kind := Pack_Blob;
         Local_Size           : Natural := 0;
         Local_Header_Length  : Natural := 0;
         Local_Payload_Offset : Natural := 0;
         Local_Last           : Stream_Element_Offset;
         Local_Next           : Natural := 0;
         Local_Status         : Status;
      begin
         for Object_Number in 1 .. Count_Value loop
            if Local_Cursor = Target then
               return True;
            elsif Local_Cursor >= Trailer_Value then
               return False;
            end if;

            Local_Status :=
              Inflate_Pack_Object_At_Offset
                (Pack_Data,
                 Local_Cursor,
                 Local_Kind,
                 Local_Size,
                 Local_Header_Length,
                 Local_Payload_Offset,
                 Scratch,
                 Local_Last,
                 Local_Next);
            if Local_Status /= Ok
              or else Local_Next <= Local_Cursor
              or else Local_Next > Trailer_Value
            then
               return False;
            elsif Object_Number < Count_Value
              and then Local_Next = Trailer_Value
            then
               return False;
            end if;

            Local_Cursor := Local_Next;
         end loop;

         return False;
      end Object_Start_Exists;
   begin
      Object_Count := 0;
      Trailer_Offset := 0;

      Status_Value :=
        Validate_Pack_Index_Offsets
          (Index_Data, Pack_Data, Scratch, Count_Value, Trailer_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      for Object_Number in 1 .. Count_Value loop
         Status_Value :=
           Inflate_Pack_Object_At_Offset
             (Pack_Data,
              Cursor,
              Kind_Value,
              Size_Value,
              Header_Length,
              Payload_Offset,
              Scratch,
              Last_Value,
              Next_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         case Kind_Value is
            when Pack_REF_Delta =>
               Status_Value :=
                 Parse_Pack_REF_Delta_Base
                   (Pack_Data
                      (Pack_Data'First
                       + Stream_Element_Offset (Cursor + Header_Length)
                       .. Pack_Data'Last),
                    Base_ID,
                    Base_Last,
                    Consumed);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;

               Status_Value :=
                 Find_Pack_Index_Object
                   (Index_Data, Base_ID, Base_Index, Base_Offset);
               if Status_Value /= Ok then
                  return Status_Value;
               elsif not Object_Start_Exists (Base_Offset) then
                  return Invalid_Command;
               end if;
            when Pack_OFS_Delta =>
               Status_Value :=
                 Parse_Pack_OFS_Delta_Base
                   (Pack_Data
                      (Pack_Data'First
                       + Stream_Element_Offset (Cursor + Header_Length)
                       .. Pack_Data'Last),
                    Base_Offset,
                    Consumed);
               if Status_Value /= Ok then
                  return Status_Value;
               elsif Base_Offset = 0
                 or else Base_Offset > Cursor
               then
                  return Invalid_Command;
               end if;

               Base_Offset := Cursor - Base_Offset;
               if Base_Offset >= Cursor
                 or else not Object_Start_Exists (Base_Offset)
               then
                  return Invalid_Command;
               end if;
            when others =>
               null;
         end case;

         Cursor := Next_Value;
      end loop;

      Object_Count := Count_Value;
      Trailer_Offset := Trailer_Value;
      return Ok;
   exception
      when Constraint_Error =>
         Object_Count := 0;
         Trailer_Offset := 0;
         return Invalid_Command;
      when others =>
         Object_Count := 0;
         Trailer_Offset := 0;
         return Internal_Error;
   end Validate_Pack_Delta_Bases;

   function Validate_Pack_Delta_Graph
     (Index_Data     : Stream_Element_Array;
      Pack_Data      : Stream_Element_Array;
      Scratch        : out Stream_Element_Array;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return Status
   is
      Count_Value   : Natural := 0;
      Trailer_Value : Natural := 0;
      Large_Count   : Natural := 0;
      Layout        : Pack_Index_Layout;
      Status_Value  : Status;
      First         : constant Stream_Element_Offset := Index_Data'First;

      function Offset_At (Offset : Natural) return Stream_Element_Offset is
      begin
         return First + Stream_Element_Offset (Offset);
      end Offset_At;

      function Resolve_Index_Offset
        (Index       : Natural;
         Pack_Offset : out Natural)
         return Status
      is
         Large_Index  : Natural := 0;
         Uses_Large   : Boolean := False;
         Local_Status : Status;
      begin
         Pack_Offset := 0;
         Local_Status :=
           Parse_Pack_Index_Offset
             (Index_Data (Offset_At (Layout.Offsets_Offset)
              .. Index_Data'Last),
              Index,
              Pack_Offset,
              Large_Index,
              Uses_Large);
         if Local_Status /= Ok then
            Pack_Offset := 0;
            return Local_Status;
         elsif Uses_Large then
            Local_Status :=
              Parse_Pack_Index_Large_Offset
                (Index_Data (Offset_At (Layout.Large_Offsets_Offset)
                 .. Index_Data'Last),
                 Large_Index,
                 Pack_Offset);
            if Local_Status /= Ok then
               Pack_Offset := 0;
            end if;
            return Local_Status;
         end if;

         return Ok;
      end Resolve_Index_Offset;

      function Find_Index_By_Offset
        (Target_Offset : Natural;
         Target_Index  : out Natural)
         return Status
      is
      begin
         Target_Index := 0;
         if Count_Value > 0 then
            for Index in 0 .. Count_Value - 1 loop
               declare
                  Candidate : Natural := 0;
               begin
                  Status_Value := Resolve_Index_Offset (Index, Candidate);
                  if Status_Value /= Ok then
                     return Status_Value;
                  elsif Candidate = Target_Offset then
                     Target_Index := Index;
                     return Ok;
                  end if;
               end;
            end loop;
         end if;

         return Invalid_Command;
      end Find_Index_By_Offset;
   begin
      Object_Count := 0;
      Trailer_Offset := 0;

      Status_Value :=
        Validate_Pack_Delta_Bases
          (Index_Data, Pack_Data, Scratch, Count_Value, Trailer_Value);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Count_Value > Maximum_Pack_Delta_Chain_Length then
         return Unsupported_Feature;
      end if;

      Status_Value :=
        Validate_Pack_Index (Index_Data, Count_Value, Large_Count, Layout);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Count_Value = 0 then
         Object_Count := 0;
         Trailer_Offset := Trailer_Value;
         return Ok;
      end if;

      declare
         subtype Object_Index_Range is Natural range 0 .. Count_Value - 1;
         type Base_Index_Array is array (Object_Index_Range) of Natural;
         type Has_Base_Array is array (Object_Index_Range) of Boolean;

         Base_Index : Base_Index_Array := [others => 0];
         Has_Base   : Has_Base_Array := [others => False];
      begin
         if Count_Value > 0 then
            for Index in Object_Index_Range loop
               declare
                  Pack_Offset    : Natural := 0;
                  Kind_Value     : Pack_Object_Kind := Pack_Blob;
                  Size_Value     : Natural := 0;
                  Header_Length  : Natural := 0;
                  Base_ID        :
                    Stream_Element_Array
                      (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
                  Base_Last      : Stream_Element_Offset;
                  Consumed       : Natural := 0;
                  Base_Object    : Natural := 0;
                  Negative_Offset : Natural := 0;
               begin
                  Status_Value := Resolve_Index_Offset (Index, Pack_Offset);
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;

                  Status_Value :=
                    Parse_Pack_Object_Header
                      (Pack_Data
                         (Pack_Data'First + Stream_Element_Offset (Pack_Offset)
                          .. Pack_Data'Last),
                       Kind_Value,
                       Size_Value,
                       Header_Length);
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;

                  case Kind_Value is
                     when Pack_REF_Delta =>
                        Status_Value :=
                          Parse_Pack_REF_Delta_Base
                            (Pack_Data
                               (Pack_Data'First
                                + Stream_Element_Offset
                                  (Pack_Offset + Header_Length)
                                .. Pack_Data'Last),
                             Base_ID,
                             Base_Last,
                             Consumed);
                        if Status_Value /= Ok then
                           return Status_Value;
                        end if;

                        Status_Value :=
                          Find_Pack_Index_Object
                            (Index_Data, Base_ID, Base_Object, Negative_Offset);
                        if Status_Value /= Ok then
                           return Status_Value;
                        end if;
                        Has_Base (Index) := True;
                        Base_Index (Index) := Base_Object;
                     when Pack_OFS_Delta =>
                        Status_Value :=
                          Parse_Pack_OFS_Delta_Base
                            (Pack_Data
                               (Pack_Data'First
                                + Stream_Element_Offset
                                  (Pack_Offset + Header_Length)
                                .. Pack_Data'Last),
                             Negative_Offset,
                             Consumed);
                        if Status_Value /= Ok then
                           return Status_Value;
                        elsif Negative_Offset = 0
                          or else Negative_Offset > Pack_Offset
                        then
                           return Invalid_Command;
                        end if;

                        Status_Value :=
                          Find_Index_By_Offset
                            (Pack_Offset - Negative_Offset, Base_Object);
                        if Status_Value /= Ok then
                           return Status_Value;
                        end if;
                        Has_Base (Index) := True;
                        Base_Index (Index) := Base_Object;
                     when others =>
                        null;
                  end case;
               end;
            end loop;

            for Start in Object_Index_Range loop
               declare
                  Current : Natural := Start;
                  Depth   : Natural := 0;
               begin
                  while Has_Base (Current) loop
                     Depth := Depth + 1;
                     if Depth > Maximum_Pack_Delta_Chain_Length
                       or else Depth > Count_Value
                     then
                        return Invalid_Command;
                     end if;

                     Current := Base_Index (Current);
                     if Current = Start then
                        return Invalid_Command;
                     end if;
                  end loop;
               end;
            end loop;
         end if;
      end;

      Object_Count := Count_Value;
      Trailer_Offset := Trailer_Value;
      return Ok;
   exception
      when Constraint_Error =>
         Object_Count := 0;
         Trailer_Offset := 0;
         return Invalid_Command;
      when others =>
         Object_Count := 0;
         Trailer_Offset := 0;
         return Internal_Error;
   end Validate_Pack_Delta_Graph;

   function Validate_Pack_Non_Delta_Object_IDs
     (Index_Data      : Stream_Element_Array;
      Pack_Data       : Stream_Element_Array;
      Scratch         : out Stream_Element_Array;
      Object_Count    : out Natural;
      Verified_Count  : out Natural;
      Trailer_Offset  : out Natural)
      return Status
   is
      Count_Value    : Natural := 0;
      Trailer_Value  : Natural := 0;
      Large_Count    : Natural := 0;
      Layout         : Pack_Index_Layout;
      Status_Value   : Status;
      First          : constant Stream_Element_Offset := Index_Data'First;

      function Offset_At (Offset : Natural) return Stream_Element_Offset is
      begin
         return First + Stream_Element_Offset (Offset);
      end Offset_At;

      function Kind_Name (Kind : Pack_Object_Kind) return String is
      begin
         case Kind is
            when Pack_Commit =>
               return "commit";
            when Pack_Tree =>
               return "tree";
            when Pack_Blob =>
               return "blob";
            when Pack_Tag =>
               return "tag";
            when others =>
               return "";
         end case;
      end Kind_Name;

      function Decimal_Length (Value : Natural) return Natural is
         Work   : Natural := Value;
         Count  : Natural := 1;
      begin
         while Work >= 10 loop
            Work := Work / 10;
            Count := Count + 1;
         end loop;
         return Count;
      end Decimal_Length;

      function Resolve_Index_Offset
        (Index       : Natural;
         Pack_Offset : out Natural)
         return Status
      is
         Large_Index  : Natural := 0;
         Uses_Large   : Boolean := False;
         Local_Status : Status;
      begin
         Pack_Offset := 0;
         Local_Status :=
           Parse_Pack_Index_Offset
             (Index_Data (Offset_At (Layout.Offsets_Offset)
              .. Index_Data'Last),
              Index,
              Pack_Offset,
              Large_Index,
              Uses_Large);
         if Local_Status /= Ok then
            Pack_Offset := 0;
            return Local_Status;
         elsif Uses_Large then
            Local_Status :=
              Parse_Pack_Index_Large_Offset
                (Index_Data (Offset_At (Layout.Large_Offsets_Offset)
                 .. Index_Data'Last),
                 Large_Index,
                 Pack_Offset);
            if Local_Status /= Ok then
               Pack_Offset := 0;
            end if;
            return Local_Status;
         end if;

         return Ok;
      end Resolve_Index_Offset;

      function Object_ID_Matches
        (Index      : Natural;
         Kind       : Pack_Object_Kind;
         Size_Value : Natural;
         Last_Value : Stream_Element_Offset)
         return Status
      is
         Name : constant String := Kind_Name (Kind);
         Size_Digits : constant Natural := Decimal_Length (Size_Value);
         Payload_Length : constant Natural := Size_Value;
         Header_Length : Natural := 0;
         Total_Length  : Natural := 0;
         Expected_ID :
           Stream_Element_Array
             (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
         Expected_Last : Stream_Element_Offset;
      begin
         if Name'Length = 0 then
            return Ok;
         elsif Name'Length > Natural'Last - 1
           or else Name'Length + 1 > Natural'Last - Size_Digits
           or else Name'Length + 1 + Size_Digits > Natural'Last - 1
         then
            return Unsupported_Feature;
         end if;

         Header_Length := Name'Length + 1 + Size_Digits + 1;
         if Payload_Length > Natural'Last - Header_Length then
            return Unsupported_Feature;
         end if;

         Total_Length := Header_Length + Payload_Length;
         if Payload_Length > Natural (Scratch'Length) then
            return Read_Failed;
         elsif Payload_Length = 0
           and then Last_Value /= Scratch'First - 1
         then
            return Invalid_Command;
         elsif Payload_Length > 0
           and then Last_Value /= Scratch'First
             + Stream_Element_Offset (Payload_Length)
             - 1
         then
            return Invalid_Command;
         end if;

         Status_Value :=
           Copy_Pack_Index_Object_ID
             (Index_Data (Offset_At (Layout.Object_IDs_Offset)
              .. Index_Data'Last),
              Index,
              Expected_ID,
              Expected_Last);
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         declare
            Data : Stream_Element_Array (1 .. Stream_Element_Offset (Total_Length));
            Cursor : Stream_Element_Offset := Data'First;
            Work_Size : Natural := Size_Value;
         begin
            for Ch of Name loop
               Data (Cursor) := Stream_Element (Character'Pos (Ch));
               Cursor := Cursor + 1;
            end loop;
            Data (Cursor) := Stream_Element (Character'Pos (' '));
            Cursor := Cursor + 1;

            for Position in reverse 0 .. Size_Digits - 1 loop
               declare
                  Divisor : Natural := 1;
               begin
                  for Step in 1 .. Position loop
                     Divisor := Divisor * 10;
                  end loop;
                  Data (Cursor) :=
                    Stream_Element
                      (Character'Pos ('0') + Work_Size / Divisor);
                  Work_Size := Work_Size mod Divisor;
                  Cursor := Cursor + 1;
               end;
            end loop;

            Data (Cursor) := 0;
            Cursor := Cursor + 1;

            if Payload_Length > 0 then
               Data (Cursor .. Data'Last) :=
                 Scratch
                   (Scratch'First
                    .. Scratch'First + Stream_Element_Offset (Payload_Length) - 1);
            end if;

            if SHA1_Digest_Matches (CryptoLib.Hashes.SHA1 (Data), Expected_ID) then
               return Ok;
            end if;
         end;

         return Invalid_Command;
      end Object_ID_Matches;
   begin
      Object_Count := 0;
      Verified_Count := 0;
      Trailer_Offset := 0;

      Status_Value :=
        Validate_Pack_Delta_Graph
          (Index_Data, Pack_Data, Scratch, Count_Value, Trailer_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Validate_Pack_Index (Index_Data, Count_Value, Large_Count, Layout);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Count_Value > 0 then
         for Index in 0 .. Count_Value - 1 loop
            declare
               Pack_Offset    : Natural := 0;
               Kind_Value     : Pack_Object_Kind := Pack_Blob;
               Size_Value     : Natural := 0;
               Header_Length  : Natural := 0;
               Payload_Offset : Natural := 0;
               Last_Value     : Stream_Element_Offset;
               Next_Offset    : Natural := 0;
            begin
               Status_Value := Resolve_Index_Offset (Index, Pack_Offset);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;

               Status_Value :=
                 Inflate_Pack_Object_At_Offset
                   (Pack_Data,
                    Pack_Offset,
                    Kind_Value,
                    Size_Value,
                    Header_Length,
                    Payload_Offset,
                    Scratch,
                    Last_Value,
                    Next_Offset);
               if Status_Value /= Ok then
                  return Status_Value;
               elsif Kind_Value in Pack_Commit | Pack_Tree | Pack_Blob | Pack_Tag
               then
                  Status_Value :=
                    Object_ID_Matches
                      (Index, Kind_Value, Size_Value, Last_Value);
                  if Status_Value /= Ok then
                     return Status_Value;
                  elsif Verified_Count = Natural'Last then
                     return Unsupported_Feature;
                  end if;

                  Verified_Count := Verified_Count + 1;
               end if;
            end;
         end loop;
      end if;

      Object_Count := Count_Value;
      Trailer_Offset := Trailer_Value;
      return Ok;
   exception
      when Constraint_Error =>
         Object_Count := 0;
         Verified_Count := 0;
         Trailer_Offset := 0;
         return Invalid_Command;
      when others =>
         Object_Count := 0;
         Verified_Count := 0;
         Trailer_Offset := 0;
         return Internal_Error;
   end Validate_Pack_Non_Delta_Object_IDs;

   function Validate_Pack_Immediate_Delta_Object_IDs
     (Index_Data      : Stream_Element_Array;
      Pack_Data       : Stream_Element_Array;
      Base_Scratch    : out Stream_Element_Array;
      Delta_Scratch   : out Stream_Element_Array;
      Result_Scratch  : out Stream_Element_Array;
      Object_Count    : out Natural;
      Resolved_Count  : out Natural;
      Trailer_Offset  : out Natural)
      return Status
   is
      Count_Value    : Natural := 0;
      Trailer_Value  : Natural := 0;
      Large_Count    : Natural := 0;
      Layout         : Pack_Index_Layout;
      Status_Value   : Status;
      First          : constant Stream_Element_Offset := Index_Data'First;

      function Offset_At (Offset : Natural) return Stream_Element_Offset is
      begin
         return First + Stream_Element_Offset (Offset);
      end Offset_At;

      function Kind_Name (Kind : Pack_Object_Kind) return String is
      begin
         case Kind is
            when Pack_Commit =>
               return "commit";
            when Pack_Tree =>
               return "tree";
            when Pack_Blob =>
               return "blob";
            when Pack_Tag =>
               return "tag";
            when others =>
               return "";
         end case;
      end Kind_Name;

      function Decimal_Length (Value : Natural) return Natural is
         Work  : Natural := Value;
         Count : Natural := 1;
      begin
         while Work >= 10 loop
            Work := Work / 10;
            Count := Count + 1;
         end loop;
         return Count;
      end Decimal_Length;

      function Resolve_Index_Offset
        (Index       : Natural;
         Pack_Offset : out Natural)
         return Status
      is
         Large_Index  : Natural := 0;
         Uses_Large   : Boolean := False;
         Local_Status : Status;
      begin
         Pack_Offset := 0;
         Local_Status :=
           Parse_Pack_Index_Offset
             (Index_Data (Offset_At (Layout.Offsets_Offset)
              .. Index_Data'Last),
              Index,
              Pack_Offset,
              Large_Index,
              Uses_Large);
         if Local_Status /= Ok then
            Pack_Offset := 0;
            return Local_Status;
         elsif Uses_Large then
            Local_Status :=
              Parse_Pack_Index_Large_Offset
                (Index_Data (Offset_At (Layout.Large_Offsets_Offset)
                 .. Index_Data'Last),
                 Large_Index,
                 Pack_Offset);
            if Local_Status /= Ok then
               Pack_Offset := 0;
            end if;
            return Local_Status;
         end if;

         return Ok;
      end Resolve_Index_Offset;

      function Find_Index_By_Offset
        (Target_Offset : Natural;
         Target_Index  : out Natural)
         return Status
      is
      begin
         Target_Index := 0;
         if Count_Value > 0 then
            for Index in 0 .. Count_Value - 1 loop
               declare
                  Candidate : Natural := 0;
                  Local_Status : constant Status :=
                    Resolve_Index_Offset (Index, Candidate);
               begin
                  if Local_Status /= Ok then
                     return Local_Status;
                  elsif Candidate = Target_Offset then
                     Target_Index := Index;
                     return Ok;
                  end if;
               end;
            end loop;
         end if;

         return Invalid_Command;
      end Find_Index_By_Offset;

      function Object_ID_Matches
        (Index      : Natural;
         Kind       : Pack_Object_Kind;
         Data       : Stream_Element_Array;
         Last_Value : Stream_Element_Offset)
         return Status
      is
         Name : constant String := Kind_Name (Kind);
         Payload_Length : Natural := 0;
         Size_Digits    : Natural := 1;
         Header_Length  : Natural := 0;
         Total_Length   : Natural := 0;
         Expected_ID :
           Stream_Element_Array
             (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
         Expected_Last : Stream_Element_Offset;
      begin
         if Name'Length = 0 then
            return Unsupported_Feature;
         elsif Last_Value < Data'First - 1 then
            return Invalid_Command;
         elsif Last_Value = Data'First - 1 then
            Payload_Length := 0;
         else
            Payload_Length := Natural (Last_Value - Data'First + 1);
         end if;

         Size_Digits := Decimal_Length (Payload_Length);
         if Name'Length > Natural'Last - 1
           or else Name'Length + 1 > Natural'Last - Size_Digits
           or else Name'Length + 1 + Size_Digits > Natural'Last - 1
         then
            return Unsupported_Feature;
         end if;

         Header_Length := Name'Length + 1 + Size_Digits + 1;
         if Payload_Length > Natural'Last - Header_Length then
            return Unsupported_Feature;
         end if;

         Total_Length := Header_Length + Payload_Length;

         Status_Value :=
           Copy_Pack_Index_Object_ID
             (Index_Data (Offset_At (Layout.Object_IDs_Offset)
              .. Index_Data'Last),
              Index,
              Expected_ID,
              Expected_Last);
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         declare
            Bytes : Stream_Element_Array
              (1 .. Stream_Element_Offset (Total_Length));
            Cursor    : Stream_Element_Offset := Bytes'First;
            Work_Size : Natural := Payload_Length;
         begin
            for Ch of Name loop
               Bytes (Cursor) := Stream_Element (Character'Pos (Ch));
               Cursor := Cursor + 1;
            end loop;
            Bytes (Cursor) := Stream_Element (Character'Pos (' '));
            Cursor := Cursor + 1;

            for Position in reverse 0 .. Size_Digits - 1 loop
               declare
                  Divisor : Natural := 1;
               begin
                  for Step in 1 .. Position loop
                     Divisor := Divisor * 10;
                  end loop;
                  Bytes (Cursor) :=
                    Stream_Element
                      (Character'Pos ('0') + Work_Size / Divisor);
                  Work_Size := Work_Size mod Divisor;
                  Cursor := Cursor + 1;
               end;
            end loop;

            Bytes (Cursor) := 0;
            Cursor := Cursor + 1;

            if Payload_Length > 0 then
               Bytes (Cursor .. Bytes'Last) :=
                 Data (Data'First .. Last_Value);
            end if;

            if SHA1_Digest_Matches (CryptoLib.Hashes.SHA1 (Bytes), Expected_ID) then
               return Ok;
            end if;
         end;

         return Invalid_Command;
      end Object_ID_Matches;

      function Resolve_Delta_Base_Offset
        (Pack_Offset     : Natural;
         Header_Length   : Natural;
         Kind            : Pack_Object_Kind;
         Base_Offset     : out Natural)
         return Status
      is
         Object_First : constant Stream_Element_Offset :=
           Pack_Data'First + Stream_Element_Offset (Pack_Offset);
         Base_First : Stream_Element_Offset;
         Ignored_Index : Natural := 0;
      begin
         Base_Offset := 0;

         if Header_Length > Natural (Pack_Data'Last - Object_First + 1) then
            return Read_Failed;
         end if;

         Base_First := Object_First + Stream_Element_Offset (Header_Length);
         if Base_First > Pack_Data'Last then
            return Read_Failed;
         end if;

         case Kind is
            when Pack_REF_Delta =>
               declare
                  Base_ID :
                    Stream_Element_Array
                      (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
                  Base_Last : Stream_Element_Offset;
                  Consumed  : Natural := 0;
               begin
                  Status_Value :=
                    Parse_Pack_REF_Delta_Base
                      (Pack_Data (Base_First .. Pack_Data'Last),
                       Base_ID,
                       Base_Last,
                       Consumed);
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;

                  Status_Value :=
                    Find_Pack_Index_Object
                      (Index_Data, Base_ID, Ignored_Index, Base_Offset);
                  if Status_Value /= Ok then
                     Base_Offset := 0;
                  end if;
                  return Status_Value;
               end;
            when Pack_OFS_Delta =>
               declare
                  Negative_Offset : Natural := 0;
                  Consumed        : Natural := 0;
               begin
                  Status_Value :=
                    Parse_Pack_OFS_Delta_Base
                      (Pack_Data (Base_First .. Pack_Data'Last),
                       Negative_Offset,
                       Consumed);
                  if Status_Value /= Ok then
                     return Status_Value;
                  elsif Negative_Offset > Pack_Offset then
                     return Invalid_Command;
                  end if;

                  Base_Offset := Pack_Offset - Negative_Offset;
                  return Find_Index_By_Offset (Base_Offset, Ignored_Index);
               end;
            when others =>
               return Invalid_Command;
         end case;
      end Resolve_Delta_Base_Offset;
   begin
      Object_Count := 0;
      Resolved_Count := 0;
      Trailer_Offset := 0;

      Status_Value :=
        Validate_Pack_Delta_Graph
          (Index_Data, Pack_Data, Delta_Scratch, Count_Value, Trailer_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Validate_Pack_Index (Index_Data, Count_Value, Large_Count, Layout);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Count_Value > 0 then
         for Index in 0 .. Count_Value - 1 loop
            declare
               Pack_Offset          : Natural := 0;
               Kind_Value           : Pack_Object_Kind := Pack_Blob;
               Size_Value           : Natural := 0;
               Header_Length        : Natural := 0;
               Payload_Offset       : Natural := 0;
               Delta_Last           : Stream_Element_Offset;
               Delta_Next_Offset    : Natural := 0;
               Base_Offset          : Natural := 0;
               Base_Kind            : Pack_Object_Kind := Pack_Blob;
               Base_Size            : Natural := 0;
               Base_Header_Length   : Natural := 0;
               Base_Payload_Offset  : Natural := 0;
               Base_Last            : Stream_Element_Offset;
               Base_Next_Offset     : Natural := 0;
               Result_Last          : Stream_Element_Offset;
            begin
               Status_Value := Resolve_Index_Offset (Index, Pack_Offset);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;

               Status_Value :=
                 Inflate_Pack_Object_At_Offset
                   (Pack_Data,
                    Pack_Offset,
                    Kind_Value,
                    Size_Value,
                    Header_Length,
                    Payload_Offset,
                    Delta_Scratch,
                    Delta_Last,
                    Delta_Next_Offset);
               if Status_Value /= Ok then
                  return Status_Value;
               elsif Kind_Value in Pack_REF_Delta | Pack_OFS_Delta then
                  Status_Value :=
                    Resolve_Delta_Base_Offset
                      (Pack_Offset,
                       Header_Length,
                       Kind_Value,
                       Base_Offset);
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;

                  Status_Value :=
                    Inflate_Pack_Object_At_Offset
                      (Pack_Data,
                       Base_Offset,
                       Base_Kind,
                       Base_Size,
                       Base_Header_Length,
                       Base_Payload_Offset,
                       Base_Scratch,
                       Base_Last,
                       Base_Next_Offset);
                  if Status_Value /= Ok then
                     return Status_Value;
                  elsif Base_Kind not in
                    Pack_Commit | Pack_Tree | Pack_Blob | Pack_Tag
                  then
                     return Unsupported_Feature;
                  end if;

                  Status_Value :=
                    Apply_Pack_Delta
                      (Base_Scratch (Base_Scratch'First .. Base_Last),
                       Delta_Scratch (Delta_Scratch'First .. Delta_Last),
                       Result_Scratch,
                       Result_Last);
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;

                  Status_Value :=
                    Object_ID_Matches
                      (Index, Base_Kind, Result_Scratch, Result_Last);
                  if Status_Value /= Ok then
                     return Status_Value;
                  elsif Resolved_Count = Natural'Last then
                     return Unsupported_Feature;
                  end if;

                  Resolved_Count := Resolved_Count + 1;
               end if;
            end;
         end loop;
      end if;

      Object_Count := Count_Value;
      Trailer_Offset := Trailer_Value;
      return Ok;
   exception
      when Constraint_Error =>
         Object_Count := 0;
         Resolved_Count := 0;
         Trailer_Offset := 0;
         return Invalid_Command;
      when others =>
         Object_Count := 0;
         Resolved_Count := 0;
         Trailer_Offset := 0;
         return Internal_Error;
   end Validate_Pack_Immediate_Delta_Object_IDs;

   function Validate_Pack_Delta_Chain_Object_IDs
     (Index_Data      : Stream_Element_Array;
      Pack_Data       : Stream_Element_Array;
      Base_Scratch    : out Stream_Element_Array;
      Delta_Scratch   : out Stream_Element_Array;
      Workspace       : out Stream_Element_Array;
      Result_Scratch  : out Stream_Element_Array;
      Object_Count    : out Natural;
      Resolved_Count  : out Natural;
      Trailer_Offset  : out Natural)
      return Status
   is
      Count_Value   : Natural := 0;
      Trailer_Value : Natural := 0;
      Large_Count   : Natural := 0;
      Layout        : Pack_Index_Layout;
      Status_Value  : Status;
      First         : constant Stream_Element_Offset := Index_Data'First;

      function Offset_At (Offset : Natural) return Stream_Element_Offset is
      begin
         return First + Stream_Element_Offset (Offset);
      end Offset_At;

      function Kind_Name (Kind : Pack_Object_Kind) return String is
      begin
         case Kind is
            when Pack_Commit => return "commit";
            when Pack_Tree   => return "tree";
            when Pack_Blob   => return "blob";
            when Pack_Tag    => return "tag";
            when others      => return "";
         end case;
      end Kind_Name;

      function Decimal_Length (Value : Natural) return Natural is
         Work  : Natural := Value;
         Count : Natural := 1;
      begin
         while Work >= 10 loop
            Work := Work / 10;
            Count := Count + 1;
         end loop;
         return Count;
      end Decimal_Length;

      function Resolve_Index_Offset
        (Index       : Natural;
         Pack_Offset : out Natural)
         return Status
      is
         Large_Index : Natural := 0;
         Uses_Large  : Boolean := False;
      begin
         Pack_Offset := 0;
         Status_Value :=
           Parse_Pack_Index_Offset
             (Index_Data (Offset_At (Layout.Offsets_Offset)
              .. Index_Data'Last),
              Index,
              Pack_Offset,
              Large_Index,
              Uses_Large);
         if Status_Value /= Ok then
            return Status_Value;
         elsif Uses_Large then
            return
              Parse_Pack_Index_Large_Offset
                (Index_Data (Offset_At (Layout.Large_Offsets_Offset)
                 .. Index_Data'Last),
                 Large_Index,
                 Pack_Offset);
         end if;
         return Ok;
      end Resolve_Index_Offset;

      function Find_Index_By_Offset
        (Target_Offset : Natural;
         Target_Index  : out Natural)
         return Status
      is
      begin
         Target_Index := 0;
         if Count_Value > 0 then
            for Index in 0 .. Count_Value - 1 loop
               declare
                  Candidate : Natural := 0;
               begin
                  Status_Value := Resolve_Index_Offset (Index, Candidate);
                  if Status_Value /= Ok then
                     return Status_Value;
                  elsif Candidate = Target_Offset then
                     Target_Index := Index;
                     return Ok;
                  end if;
               end;
            end loop;
         end if;
         return Invalid_Command;
      end Find_Index_By_Offset;

      function Object_ID_Matches
        (Index      : Natural;
         Kind       : Pack_Object_Kind;
         Data       : Stream_Element_Array;
         Last_Value : Stream_Element_Offset)
         return Status
      is
         Name : constant String := Kind_Name (Kind);
         Payload_Length : Natural := 0;
         Size_Digits    : Natural := 1;
         Header_Length  : Natural := 0;
         Total_Length   : Natural := 0;
         Expected_ID :
           Stream_Element_Array
             (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
         Expected_Last : Stream_Element_Offset;
      begin
         if Name'Length = 0 then
            return Unsupported_Feature;
         elsif Last_Value < Data'First - 1 then
            return Invalid_Command;
         elsif Last_Value = Data'First - 1 then
            Payload_Length := 0;
         else
            Payload_Length := Natural (Last_Value - Data'First + 1);
         end if;

         Size_Digits := Decimal_Length (Payload_Length);
         if Name'Length + 1 > Natural'Last - Size_Digits
           or else Name'Length + 1 + Size_Digits > Natural'Last - 1
         then
            return Unsupported_Feature;
         end if;

         Header_Length := Name'Length + 1 + Size_Digits + 1;
         if Payload_Length > Natural'Last - Header_Length then
            return Unsupported_Feature;
         end if;
         Total_Length := Header_Length + Payload_Length;

         Status_Value :=
           Copy_Pack_Index_Object_ID
             (Index_Data (Offset_At (Layout.Object_IDs_Offset)
              .. Index_Data'Last),
              Index,
              Expected_ID,
              Expected_Last);
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         declare
            Bytes : Stream_Element_Array
              (1 .. Stream_Element_Offset (Total_Length));
            Cursor    : Stream_Element_Offset := Bytes'First;
            Work_Size : Natural := Payload_Length;
         begin
            for Ch of Name loop
               Bytes (Cursor) := Stream_Element (Character'Pos (Ch));
               Cursor := Cursor + 1;
            end loop;
            Bytes (Cursor) := Stream_Element (Character'Pos (' '));
            Cursor := Cursor + 1;
            for Position in reverse 0 .. Size_Digits - 1 loop
               declare
                  Divisor : Natural := 1;
               begin
                  for Step in 1 .. Position loop
                     Divisor := Divisor * 10;
                  end loop;
                  Bytes (Cursor) :=
                    Stream_Element
                      (Character'Pos ('0') + Work_Size / Divisor);
                  Work_Size := Work_Size mod Divisor;
                  Cursor := Cursor + 1;
               end;
            end loop;
            Bytes (Cursor) := 0;
            Cursor := Cursor + 1;
            if Payload_Length > 0 then
               Bytes (Cursor .. Bytes'Last) := Data (Data'First .. Last_Value);
            end if;

            if SHA1_Digest_Matches (CryptoLib.Hashes.SHA1 (Bytes), Expected_ID) then
               return Ok;
            end if;
         end;
         return Invalid_Command;
      end Object_ID_Matches;

      function Object_Kind_At
        (Index       : Natural;
         Kind        : out Pack_Object_Kind;
         Pack_Offset : out Natural;
         Header_Size : out Natural)
         return Status
      is
         Size_Value : Natural := 0;
      begin
         Status_Value := Resolve_Index_Offset (Index, Pack_Offset);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         return
           Parse_Pack_Object_Header
             (Pack_Data
                (Pack_Data'First + Stream_Element_Offset (Pack_Offset)
                 .. Pack_Data'Last),
              Kind,
              Size_Value,
              Header_Size);
      end Object_Kind_At;

      function Resolve_Delta_Base_Index
        (Pack_Offset : Natural;
         Header_Size : Natural;
         Kind        : Pack_Object_Kind;
         Base_Index  : out Natural)
         return Status
      is
         Base_First : constant Stream_Element_Offset :=
           Pack_Data'First
           + Stream_Element_Offset (Pack_Offset + Header_Size);
      begin
         Base_Index := 0;
         if Base_First > Pack_Data'Last then
            return Read_Failed;
         end if;
         case Kind is
            when Pack_REF_Delta =>
               declare
                  Base_ID :
                    Stream_Element_Array
                      (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
                  Base_Last : Stream_Element_Offset;
                  Consumed  : Natural := 0;
                  Ignored_Offset : Natural := 0;
               begin
                  Status_Value :=
                    Parse_Pack_REF_Delta_Base
                      (Pack_Data (Base_First .. Pack_Data'Last),
                       Base_ID,
                       Base_Last,
                       Consumed);
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;
                  return
                    Find_Pack_Index_Object
                      (Index_Data, Base_ID, Base_Index, Ignored_Offset);
               end;
            when Pack_OFS_Delta =>
               declare
                  Negative_Offset : Natural := 0;
                  Consumed        : Natural := 0;
               begin
                  Status_Value :=
                    Parse_Pack_OFS_Delta_Base
                      (Pack_Data (Base_First .. Pack_Data'Last),
                       Negative_Offset,
                       Consumed);
                  if Status_Value /= Ok then
                     return Status_Value;
                  elsif Negative_Offset = 0
                    or else Negative_Offset > Pack_Offset
                  then
                     return Invalid_Command;
                  end if;
                  return
                    Find_Index_By_Offset
                      (Pack_Offset - Negative_Offset, Base_Index);
               end;
            when others =>
               return Invalid_Command;
         end case;
      end Resolve_Delta_Base_Index;
   begin
      Object_Count := 0;
      Resolved_Count := 0;
      Trailer_Offset := 0;

      Status_Value :=
        Validate_Pack_Delta_Graph
          (Index_Data, Pack_Data, Delta_Scratch, Count_Value, Trailer_Value);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Count_Value > Maximum_Pack_Delta_Chain_Length then
         return Unsupported_Feature;
      end if;

      Status_Value :=
        Validate_Pack_Index (Index_Data, Count_Value, Large_Count, Layout);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Count_Value > 0 then
         declare
            subtype Object_Index_Range is Natural range 0 .. Count_Value - 1;
            type Chain_Array is array (Positive range <>) of Natural;
            Chain : Chain_Array (1 .. Count_Value);
         begin
            for Index in Object_Index_Range loop
               declare
                  Current      : Natural := Index;
                  Chain_Length : Natural := 0;
                  Kind_Value   : Pack_Object_Kind := Pack_Blob;
                  Pack_Offset  : Natural := 0;
                  Header_Size  : Natural := 0;
               begin
                  loop
                     Status_Value :=
                       Object_Kind_At
                         (Current, Kind_Value, Pack_Offset, Header_Size);
                     if Status_Value /= Ok then
                        return Status_Value;
                     end if;
                     exit when Kind_Value not in Pack_REF_Delta | Pack_OFS_Delta;

                     if Chain_Length = Chain'Length then
                        return Invalid_Command;
                     end if;
                     Chain_Length := Chain_Length + 1;
                     Chain (Chain_Length) := Current;

                     Status_Value :=
                       Resolve_Delta_Base_Index
                         (Pack_Offset, Header_Size, Kind_Value, Current);
                     if Status_Value /= Ok then
                        return Status_Value;
                     end if;
                  end loop;

                  if Chain_Length > 0 then
                     declare
                        Base_Kind           : Pack_Object_Kind := Pack_Blob;
                        Base_Size           : Natural := 0;
                        Base_Header_Length  : Natural := 0;
                        Base_Payload_Offset : Natural := 0;
                        Base_Last           : Stream_Element_Offset;
                        Base_Next_Offset    : Natural := 0;
                        Base_Offset         : Natural := 0;
                        Delta_Kind          : Pack_Object_Kind := Pack_Blob;
                        Delta_Size          : Natural := 0;
                        Delta_Header_Length : Natural := 0;
                        Delta_Payload_Offset : Natural := 0;
                        Delta_Last          : Stream_Element_Offset;
                        Delta_Next_Offset   : Natural := 0;
                        Current_Last        : Stream_Element_Offset;
                        Current_Buffer      : Natural := 0;
                     begin
                        Status_Value := Resolve_Index_Offset (Current, Base_Offset);
                        if Status_Value /= Ok then
                           return Status_Value;
                        end if;

                        Status_Value :=
                          Inflate_Pack_Object_At_Offset
                            (Pack_Data,
                             Base_Offset,
                             Base_Kind,
                             Base_Size,
                             Base_Header_Length,
                             Base_Payload_Offset,
                             Base_Scratch,
                             Base_Last,
                             Base_Next_Offset);
                        if Status_Value /= Ok then
                           return Status_Value;
                        elsif Base_Kind not in
                          Pack_Commit | Pack_Tree | Pack_Blob | Pack_Tag
                        then
                           return Unsupported_Feature;
                        end if;

                        Current_Last := Base_Last;
                        Current_Buffer := 0;

                        for Chain_Position in reverse 1 .. Chain_Length loop
                           declare
                              Delta_Offset : Natural := 0;
                           begin
                              Status_Value :=
                                Resolve_Index_Offset
                                  (Chain (Chain_Position), Delta_Offset);
                              if Status_Value /= Ok then
                                 return Status_Value;
                              end if;

                              Status_Value :=
                                Inflate_Pack_Object_At_Offset
                                  (Pack_Data,
                                   Delta_Offset,
                                   Delta_Kind,
                                   Delta_Size,
                                   Delta_Header_Length,
                                   Delta_Payload_Offset,
                                   Delta_Scratch,
                                   Delta_Last,
                                   Delta_Next_Offset);
                              if Status_Value /= Ok then
                                 return Status_Value;
                              end if;

                              case Current_Buffer is
                                 when 0 =>
                                    Status_Value :=
                                      Apply_Pack_Delta
                                        (Base_Scratch
                                           (Base_Scratch'First .. Current_Last),
                                         Delta_Scratch
                                           (Delta_Scratch'First .. Delta_Last),
                                         Result_Scratch,
                                         Current_Last);
                                    Current_Buffer := 1;
                                 when 1 =>
                                    Status_Value :=
                                      Apply_Pack_Delta
                                        (Result_Scratch
                                           (Result_Scratch'First .. Current_Last),
                                         Delta_Scratch
                                           (Delta_Scratch'First .. Delta_Last),
                                         Workspace,
                                         Current_Last);
                                    Current_Buffer := 2;
                                 when others =>
                                    Status_Value :=
                                      Apply_Pack_Delta
                                        (Workspace
                                           (Workspace'First .. Current_Last),
                                         Delta_Scratch
                                           (Delta_Scratch'First .. Delta_Last),
                                         Result_Scratch,
                                         Current_Last);
                                    Current_Buffer := 1;
                              end case;
                              if Status_Value /= Ok then
                                 return Status_Value;
                              end if;
                           end;
                        end loop;

                        if Current_Buffer = 2 then
                           Status_Value :=
                             Object_ID_Matches
                               (Index, Base_Kind, Workspace, Current_Last);
                        else
                           Status_Value :=
                             Object_ID_Matches
                               (Index, Base_Kind, Result_Scratch, Current_Last);
                        end if;
                        if Status_Value /= Ok then
                           return Status_Value;
                        elsif Resolved_Count = Natural'Last then
                           return Unsupported_Feature;
                        end if;
                        Resolved_Count := Resolved_Count + 1;
                     end;
                  end if;
               end;
            end loop;
         end;
      end if;

      Object_Count := Count_Value;
      Trailer_Offset := Trailer_Value;
      return Ok;
   exception
      when Constraint_Error =>
         Object_Count := 0;
         Resolved_Count := 0;
         Trailer_Offset := 0;
         return Invalid_Command;
      when others =>
         Object_Count := 0;
         Resolved_Count := 0;
         Trailer_Offset := 0;
         return Internal_Error;
   end Validate_Pack_Delta_Chain_Object_IDs;

   function Validate_Pack_Object_IDs
     (Index_Data      : Stream_Element_Array;
      Pack_Data       : Stream_Element_Array;
      Base_Scratch    : out Stream_Element_Array;
      Delta_Scratch   : out Stream_Element_Array;
      Workspace       : out Stream_Element_Array;
      Result_Scratch  : out Stream_Element_Array;
      Object_Count    : out Natural;
      Verified_Count  : out Natural;
      Resolved_Count  : out Natural;
      Trailer_Offset  : out Natural)
      return Status
   is
      Non_Delta_Count   : Natural := 0;
      Non_Delta_Trailer : Natural := 0;
      Delta_Count       : Natural := 0;
      Delta_Trailer     : Natural := 0;
      Status_Value      : Status;
   begin
      Object_Count := 0;
      Verified_Count := 0;
      Resolved_Count := 0;
      Trailer_Offset := 0;

      Status_Value :=
        Validate_Pack_Non_Delta_Object_IDs
          (Index_Data,
           Pack_Data,
           Base_Scratch,
           Non_Delta_Count,
           Verified_Count,
           Non_Delta_Trailer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Validate_Pack_Delta_Chain_Object_IDs
          (Index_Data,
           Pack_Data,
           Base_Scratch,
           Delta_Scratch,
           Workspace,
           Result_Scratch,
           Delta_Count,
           Resolved_Count,
           Delta_Trailer);
      if Status_Value /= Ok then
         Object_Count := 0;
         Verified_Count := 0;
         Resolved_Count := 0;
         Trailer_Offset := 0;
         return Status_Value;
      elsif Delta_Count /= Non_Delta_Count
        or else Delta_Trailer /= Non_Delta_Trailer
      then
         Object_Count := 0;
         Verified_Count := 0;
         Resolved_Count := 0;
         Trailer_Offset := 0;
         return Internal_Error;
      end if;

      Object_Count := Non_Delta_Count;
      Trailer_Offset := Non_Delta_Trailer;
      return Ok;
   exception
      when Constraint_Error =>
         Object_Count := 0;
         Verified_Count := 0;
         Resolved_Count := 0;
         Trailer_Offset := 0;
         return Invalid_Command;
      when others =>
         Object_Count := 0;
         Verified_Count := 0;
         Resolved_Count := 0;
         Trailer_Offset := 0;
         return Internal_Error;
   end Validate_Pack_Object_IDs;

   function Validate_Pack_Integrity
     (Index_Data      : Stream_Element_Array;
      Pack_Data       : Stream_Element_Array;
      Base_Scratch    : out Stream_Element_Array;
      Delta_Scratch   : out Stream_Element_Array;
      Workspace       : out Stream_Element_Array;
      Result_Scratch  : out Stream_Element_Array;
      Object_Count    : out Natural;
      Verified_Count  : out Natural;
      Resolved_Count  : out Natural;
      Trailer_Offset  : out Natural)
      return Status
   is
      CRC_Count      : Natural := 0;
      CRC_Trailer    : Natural := 0;
      ID_Count       : Natural := 0;
      ID_Trailer     : Natural := 0;
      Status_Value   : Status;
      Trailer_First  : Stream_Element_Offset;
   begin
      Object_Count := 0;
      Verified_Count := 0;
      Resolved_Count := 0;
      Trailer_Offset := 0;

      if Pack_Data'Length
        < Stream_Element_Offset (12 + Object_ID_SHA1_Raw_Length)
      then
         return Read_Failed;
      end if;

      Status_Value := Verify_Pack_Trailer_Checksum (Pack_Data);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value := Verify_Pack_Index_Checksum (Index_Data);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Trailer_First :=
        Pack_Data'Last
        - Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
        + 1;
      Status_Value :=
        Verify_Pack_Index_Pack_Checksum
          (Index_Data, Pack_Data (Trailer_First .. Pack_Data'Last));
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Validate_Pack_Index_CRCs
          (Index_Data, Pack_Data, Base_Scratch, CRC_Count, CRC_Trailer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Validate_Pack_Object_IDs
          (Index_Data,
           Pack_Data,
           Base_Scratch,
           Delta_Scratch,
           Workspace,
           Result_Scratch,
           ID_Count,
           Verified_Count,
           Resolved_Count,
           ID_Trailer);
      if Status_Value /= Ok then
         Object_Count := 0;
         Verified_Count := 0;
         Resolved_Count := 0;
         Trailer_Offset := 0;
         return Status_Value;
      elsif ID_Count /= CRC_Count
        or else ID_Trailer /= CRC_Trailer
      then
         Object_Count := 0;
         Verified_Count := 0;
         Resolved_Count := 0;
         Trailer_Offset := 0;
         return Internal_Error;
      end if;

      Object_Count := ID_Count;
      Trailer_Offset := ID_Trailer;
      return Ok;
   exception
      when Constraint_Error =>
         Object_Count := 0;
         Verified_Count := 0;
         Resolved_Count := 0;
         Trailer_Offset := 0;
         return Invalid_Command;
      when others =>
         Object_Count := 0;
         Verified_Count := 0;
         Resolved_Count := 0;
         Trailer_Offset := 0;
         return Internal_Error;
   end Validate_Pack_Integrity;

   function Inventory_Pack_Objects
     (Pack_Data      : Stream_Element_Array;
      Scratch        : out Stream_Element_Array;
      Counts         : out Pack_Object_Counts;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return Status
   is
      Status_Value   : Status;
      Count_Value    : Natural := 0;
      Trailer_Value  : Natural := 0;
      Cursor         : Natural := 12;
      Kind_Value     : Pack_Object_Kind := Pack_Blob;
      Size_Value     : Natural := 0;
      Header_Length  : Natural := 0;
      Payload_Offset : Natural := 0;
      Last_Value     : Stream_Element_Offset;
      Next_Value     : Natural := 0;
   begin
      Counts := (others => 0);
      Object_Count := 0;
      Trailer_Offset := 0;

      Status_Value :=
        Validate_Pack_Object_Sequence
          (Pack_Data, Scratch, Count_Value, Trailer_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      for Object_Number in 1 .. Count_Value loop
         Status_Value :=
           Inflate_Pack_Object_At_Offset
             (Pack_Data,
              Cursor,
              Kind_Value,
              Size_Value,
              Header_Length,
              Payload_Offset,
              Scratch,
              Last_Value,
              Next_Value);
         if Status_Value /= Ok then
            Counts := (others => 0);
            Object_Count := 0;
            Trailer_Offset := 0;
            return Status_Value;
         end if;

         case Kind_Value is
            when Pack_Commit =>
               Counts.Commits := Counts.Commits + 1;
            when Pack_Tree =>
               Counts.Trees := Counts.Trees + 1;
            when Pack_Blob =>
               Counts.Blobs := Counts.Blobs + 1;
            when Pack_Tag =>
               Counts.Tags := Counts.Tags + 1;
            when Pack_OFS_Delta =>
               Counts.OFS_Deltas := Counts.OFS_Deltas + 1;
            when Pack_REF_Delta =>
               Counts.REF_Deltas := Counts.REF_Deltas + 1;
         end case;

         Cursor := Next_Value;
      end loop;

      if Cursor /= Trailer_Value then
         Counts := (others => 0);
         Object_Count := 0;
         Trailer_Offset := 0;
         return Internal_Error;
      end if;

      Object_Count := Count_Value;
      Trailer_Offset := Trailer_Value;
      return Ok;
   exception
      when Constraint_Error =>
         Counts := (others => 0);
         Object_Count := 0;
         Trailer_Offset := 0;
         return Invalid_Command;
      when others =>
         Counts := (others => 0);
         Object_Count := 0;
         Trailer_Offset := 0;
         return Internal_Error;
   end Inventory_Pack_Objects;

   function Compute_Object_ID
     (Kind      : Pack_Object_Kind;
      Data      : Stream_Element_Array;
      Object_ID : out Stream_Element_Array;
      Last      : out Stream_Element_Offset)
      return Status
   is
      function Kind_Name return String is
      begin
         case Kind is
            when Pack_Commit =>
               return "commit";
            when Pack_Tree =>
               return "tree";
            when Pack_Blob =>
               return "blob";
            when Pack_Tag =>
               return "tag";
            when others =>
               return "";
         end case;
      end Kind_Name;

      function Decimal_Length (Value : Natural) return Natural is
         Work   : Natural := Value;
         Count  : Natural := 1;
      begin
         while Work >= 10 loop
            Work := Work / 10;
            Count := Count + 1;
         end loop;
         return Count;
      end Decimal_Length;

      Name           : constant String := Kind_Name;
      Payload_Length : Natural := 0;
      Size_Digits    : Natural := 0;
      Header_Length  : Natural := 0;
      Total_Length   : Natural := 0;
   begin
      Last := Object_ID'First - 1;

      if Name'Length = 0 then
         return Invalid_Command;
      elsif Object_ID'Length
        < Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
      then
         return Read_Failed;
      elsif Data'Length > Stream_Element_Offset (Natural'Last) then
         return Unsupported_Feature;
      end if;

      Payload_Length := Natural (Data'Length);
      Size_Digits := Decimal_Length (Payload_Length);
      if Name'Length > Natural'Last - 1
        or else Name'Length + 1 > Natural'Last - Size_Digits
        or else Name'Length + 1 + Size_Digits > Natural'Last - 1
      then
         return Unsupported_Feature;
      end if;

      Header_Length := Name'Length + 1 + Size_Digits + 1;
      if Payload_Length > Natural'Last - Header_Length then
         return Unsupported_Feature;
      end if;

      Total_Length := Header_Length + Payload_Length;

      declare
         Preimage : Stream_Element_Array (1 .. Stream_Element_Offset (Total_Length));
         Cursor   : Stream_Element_Offset := Preimage'First;
         Work_Size : Natural := Payload_Length;
         Digest   : CryptoLib.Hashes.SHA1_Digest;
      begin
         for Ch of Name loop
            Preimage (Cursor) := Stream_Element (Character'Pos (Ch));
            Cursor := Cursor + 1;
         end loop;

         Preimage (Cursor) := Stream_Element (Character'Pos (' '));
         Cursor := Cursor + 1;

         for Position in reverse 0 .. Size_Digits - 1 loop
            declare
               Divisor : Natural := 1;
            begin
               for Step in 1 .. Position loop
                  Divisor := Divisor * 10;
               end loop;

               Preimage (Cursor) :=
                 Stream_Element (Character'Pos ('0') + Work_Size / Divisor);
               Work_Size := Work_Size mod Divisor;
               Cursor := Cursor + 1;
            end;
         end loop;

         Preimage (Cursor) := 0;
         Cursor := Cursor + 1;

         if Payload_Length > 0 then
            Preimage (Cursor .. Preimage'Last) := Data;
         end if;

         Digest := CryptoLib.Hashes.SHA1 (Preimage);
         for Index in Digest'Range loop
            Object_ID
              (Object_ID'First + Stream_Element_Offset (Index - Digest'First)) :=
                Digest (Index);
         end loop;
      end;

      Last :=
        Object_ID'First
        + Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
        - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Object_ID'First - 1;
         return Invalid_Command;
      when others =>
         Last := Object_ID'First - 1;
         return Internal_Error;
   end Compute_Object_ID;

   function Valid_Tree_Mode (Mode : Natural) return Boolean is
   begin
      return
        Mode = 8#100644#
        or else Mode = 8#100755#
        or else Mode = 8#120000#
        or else Mode = 8#040000#
        or else Mode = 8#160000#;
   end Valid_Tree_Mode;

   function Build_Tree_Entry
     (File_Mode : Natural;
      Name      : String;
      Object_ID : Stream_Element_Array;
      Entry_Data : out Stream_Element_Array;
      Last      : out Stream_Element_Offset)
      return Status
   is
      Mode_Text : String (1 .. 12);
      Mode_First : Natural := Mode_Text'Last;
      Value : Natural := File_Mode;
      Cursor : Stream_Element_Offset := Entry_Data'First;

      procedure Store (Ch : Character) is
      begin
         Entry_Data (Cursor) := Stream_Element (Character'Pos (Ch));
         Cursor := Cursor + 1;
      end Store;
   begin
      Last := Entry_Data'First - 1;
      if not Valid_Tree_Mode (File_Mode)
        or else Name'Length = 0
        or else Name'Length > Maximum_Ref_Name_Length
        or else Object_ID'Length /=
          Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
      then
         return Invalid_Command;
      end if;

      for Ch of Name loop
         if Ch = Character'Val (0)
           or else Ch = '/'
           or else Ch = Character'Val (10)
           or else Ch = Character'Val (13)
         then
            return Invalid_Command;
         end if;
      end loop;

      loop
         Mode_Text (Mode_First) :=
           Character'Val (Character'Pos ('0') + (Value mod 8));
         Value := Value / 8;
         exit when Value = 0;
         if Mode_First = Mode_Text'First then
            return Invalid_Command;
         end if;
         Mode_First := Mode_First - 1;
      end loop;

      if Entry_Data'Length <
        Stream_Element_Offset
          ((Mode_Text'Last - Mode_First + 1) + Name'Length
           + Object_ID_SHA1_Raw_Length + 2)
      then
         return Invalid_Command;
      end if;

      for Index in Mode_First .. Mode_Text'Last loop
         Store (Mode_Text (Index));
      end loop;
      Store (' ');
      for Ch of Name loop
         Store (Ch);
      end loop;
      Store (Character'Val (0));
      Entry_Data
        (Cursor .. Cursor + Stream_Element_Offset (Object_ID'Length) - 1) :=
        Object_ID;
      Cursor := Cursor + Stream_Element_Offset (Object_ID'Length);
      Last := Cursor - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Entry_Data'First - 1;
         return Invalid_Command;
      when others =>
         Last := Entry_Data'First - 1;
         return Write_Failed;
   end Build_Tree_Entry;

   function Parse_Tree_Entry
     (Data         : Stream_Element_Array;
      Entry_Offset : Natural;
      File_Mode    : out Natural;
      Name         : out Stream_Element_Array;
      Name_Last    : out Stream_Element_Offset;
      Object_ID    : out Stream_Element_Array;
      Object_Last  : out Stream_Element_Offset;
      Next_Offset  : out Natural)
      return Status
   is
      Cursor        : Stream_Element_Offset;
      Mode_Digits   : Natural := 0;
      Name_First    : Stream_Element_Offset;
      Name_Length   : Stream_Element_Offset := 0;
      Object_First  : Stream_Element_Offset;
   begin
      File_Mode := 0;
      Name_Last := Name'First - 1;
      Object_Last := Object_ID'First - 1;
      Next_Offset := Entry_Offset;

      if Entry_Offset > Natural'Last - 1
        or else Object_ID'Length
          < Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
      then
         return Read_Failed;
      elsif Data'Length = 0
        or else Entry_Offset > Natural (Data'Length)
      then
         return Invalid_Command;
      end if;

      Cursor := Data'First + Stream_Element_Offset (Entry_Offset);
      while Cursor <= Data'Last
        and then Data (Cursor) /= Stream_Element (Character'Pos (' '))
      loop
         if Data (Cursor) < Stream_Element (Character'Pos ('0'))
           or else Data (Cursor) > Stream_Element (Character'Pos ('7'))
         then
            return Invalid_Command;
         elsif Mode_Digits >= 6
           or else File_Mode > (Natural'Last - 7) / 8
         then
            return Unsupported_Feature;
         end if;

         File_Mode :=
           File_Mode * 8
           + Natural (Data (Cursor) - Stream_Element (Character'Pos ('0')));
         Mode_Digits := Mode_Digits + 1;
         Cursor := Cursor + 1;
      end loop;

      if Cursor > Data'Last
        or else Mode_Digits = 0
        or else not Valid_Tree_Mode (File_Mode)
      then
         return Invalid_Command;
      end if;

      Cursor := Cursor + 1;
      Name_First := Cursor;
      while Cursor <= Data'Last and then Data (Cursor) /= 0 loop
         if Data (Cursor) = Stream_Element (Character'Pos ('/')) then
            return Invalid_Command;
         end if;
         Cursor := Cursor + 1;
      end loop;

      if Cursor > Data'Last or else Cursor = Name_First then
         return Invalid_Command;
      end if;

      Name_Length := Cursor - Name_First;
      if Name_Length > Name'Length then
         return Read_Failed;
      end if;

      Object_First := Cursor + 1;
      if Object_First > Data'Last
        or else Data'Last - Object_First + 1
          < Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
      then
         return Read_Failed;
      end if;

      Name
        (Name'First .. Name'First + Name_Length - 1) :=
          Data (Name_First .. Cursor - 1);
      Name_Last := Name'First + Name_Length - 1;

      Object_ID
        (Object_ID'First
         .. Object_ID'First
            + Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
            - 1) :=
        Data
          (Object_First
           .. Object_First
              + Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
              - 1);
      Object_Last :=
        Object_ID'First
        + Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
        - 1;
      Next_Offset :=
        Natural
          (Object_First
           + Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
           - Data'First);
      return Ok;
   exception
      when Constraint_Error =>
         File_Mode := 0;
         Name_Last := Name'First - 1;
         Object_Last := Object_ID'First - 1;
         Next_Offset := Entry_Offset;
         return Invalid_Command;
      when others =>
         File_Mode := 0;
         Name_Last := Name'First - 1;
         Object_Last := Object_ID'First - 1;
         Next_Offset := Entry_Offset;
         return Internal_Error;
   end Parse_Tree_Entry;

   function Validate_Tree_Object
     (Data        : Stream_Element_Array;
      Entry_Count : out Natural)
      return Status
   is
      Cursor      : Natural := 0;
      File_Mode   : Natural := 0;
      Name_Buffer : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Name_Last   : Stream_Element_Offset;
      Object_ID   : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Object_Last : Stream_Element_Offset;
      Next_Offset : Natural := 0;
      Status_Value : Status;
   begin
      Entry_Count := 0;
      if Data'Length = 0 then
         return Ok;
      elsif Data'Length > Stream_Element_Offset (Natural'Last) then
         return Unsupported_Feature;
      end if;

      while Cursor < Natural (Data'Length) loop
         Status_Value :=
           Parse_Tree_Entry
             (Data,
              Cursor,
              File_Mode,
              Name_Buffer,
              Name_Last,
              Object_ID,
              Object_Last,
              Next_Offset);
         if Status_Value /= Ok then
            Entry_Count := 0;
            return Status_Value;
         elsif Next_Offset <= Cursor
           or else Next_Offset > Natural (Data'Length)
           or else Object_Last /= Object_ID'Last
           or else Name_Last < Name_Buffer'First
         then
            Entry_Count := 0;
            return Invalid_Command;
         end if;
         Entry_Count := Entry_Count + 1;
         Cursor := Next_Offset;
      end loop;

      return Ok;
   exception
      when Constraint_Error =>
         Entry_Count := 0;
         return Invalid_Command;
      when others =>
         Entry_Count := 0;
         return Internal_Error;
   end Validate_Tree_Object;

   function Find_Tree_Entry
     (Data        : Stream_Element_Array;
      Name        : Stream_Element_Array;
      File_Mode   : out Natural;
      Object_ID   : out Stream_Element_Array;
      Object_Last : out Stream_Element_Offset)
      return Status
   is
      Cursor      : Natural := 0;
      Local_Mode  : Natural := 0;
      Name_Buffer : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Ref_Name_Length));
      Name_Last   : Stream_Element_Offset;
      Local_ID    : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Local_Last  : Stream_Element_Offset;
      Next_Offset : Natural := 0;
      Status_Value : Status;
   begin
      File_Mode := 0;
      Object_Last := Object_ID'First - 1;
      if Object_ID'Length
        < Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
      then
         return Read_Failed;
      elsif Name'Length = 0
        or else Name'Length > Stream_Element_Offset (Maximum_Ref_Name_Length)
      then
         return Invalid_Command;
      elsif Data'Length > Stream_Element_Offset (Natural'Last) then
         return Unsupported_Feature;
      end if;

      for Index in Name'Range loop
         if Name (Index) = 0
           or else Name (Index) = Stream_Element (Character'Pos ('/'))
         then
            return Invalid_Command;
         end if;
      end loop;

      while Cursor < Natural (Data'Length) loop
         Status_Value :=
           Parse_Tree_Entry
             (Data,
              Cursor,
              Local_Mode,
              Name_Buffer,
              Name_Last,
              Local_ID,
              Local_Last,
              Next_Offset);
         if Status_Value /= Ok then
            File_Mode := 0;
            Object_Last := Object_ID'First - 1;
            return Status_Value;
         elsif Next_Offset <= Cursor
           or else Next_Offset > Natural (Data'Length)
           or else Local_Last /= Local_ID'Last
           or else Name_Last < Name_Buffer'First
         then
            File_Mode := 0;
            Object_Last := Object_ID'First - 1;
            return Invalid_Command;
         end if;

         if Name_Last - Name_Buffer'First + 1 = Name'Length
           and then Name_Buffer
             (Name_Buffer'First .. Name_Last) = Name
         then
            File_Mode := Local_Mode;
            Object_ID
              (Object_ID'First
               .. Object_ID'First
                  + Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
                  - 1) := Local_ID;
            Object_Last :=
              Object_ID'First
              + Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
              - 1;
            return Ok;
         end if;

         Cursor := Next_Offset;
      end loop;

      return Invalid_Command;
   exception
      when Constraint_Error =>
         File_Mode := 0;
         Object_Last := Object_ID'First - 1;
         return Invalid_Command;
      when others =>
         File_Mode := 0;
         Object_Last := Object_ID'First - 1;
         return Internal_Error;
   end Find_Tree_Entry;

   function Find_Tree_Entry_Hex
     (Data        : Stream_Element_Array;
      Name        : Stream_Element_Array;
      File_Mode   : out Natural;
      Object_ID   : out Stream_Element_Array;
      Object_Last : out Stream_Element_Offset)
      return Status
   is
      Raw_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last : Stream_Element_Offset;
      Status_Value : Status;
   begin
      File_Mode := 0;
      Object_Last := Object_ID'First - 1;
      if Object_ID'Length
        < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Read_Failed;
      end if;

      Status_Value :=
        Find_Tree_Entry
          (Data, Name, File_Mode, Raw_ID, Raw_Last);
      if Status_Value /= Ok then
         Object_Last := Object_ID'First - 1;
         return Status_Value;
      elsif Raw_Last /= Raw_ID'Last then
         File_Mode := 0;
         Object_Last := Object_ID'First - 1;
         return Invalid_Command;
      end if;

      return Encode_Object_ID_Hex (Raw_ID, Object_ID, Object_Last);
   exception
      when Constraint_Error =>
         File_Mode := 0;
         Object_Last := Object_ID'First - 1;
         return Invalid_Command;
      when others =>
         File_Mode := 0;
         Object_Last := Object_ID'First - 1;
         return Internal_Error;
   end Find_Tree_Entry_Hex;

   function Build_Commit_Object
     (Tree_ID_Hex    : Stream_Element_Array;
      Has_Parent     : Boolean;
      Parent_ID_Hex  : Stream_Element_Array;
      Author_Line    : String;
      Committer_Line : String;
      Message        : String;
      Commit_Data    : out Stream_Element_Array;
      Last           : out Stream_Element_Offset)
      return Status
   is
      Cursor : Stream_Element_Offset := Commit_Data'First;

      function Clean_Header_Line (Text : String) return Boolean is
      begin
         if Text'Length = 0
           or else Text'Length > Maximum_Pkt_Line_Payload_Length
         then
            return False;
         end if;
         for Ch of Text loop
            if Ch = Character'Val (0)
              or else Ch = Character'Val (10)
              or else Ch = Character'Val (13)
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Clean_Header_Line;

      function Clean_Message (Text : String) return Boolean is
      begin
         if Text'Length > Maximum_Pkt_Line_Payload_Length then
            return False;
         end if;
         for Ch of Text loop
            if Ch = Character'Val (0) or else Ch = Character'Val (13) then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Clean_Message;

      procedure Store (Text : String) is
      begin
         for Ch of Text loop
            Commit_Data (Cursor) := Stream_Element (Character'Pos (Ch));
            Cursor := Cursor + 1;
         end loop;
      end Store;

      procedure Store_Bytes (Data : Stream_Element_Array) is
      begin
         Commit_Data (Cursor .. Cursor + Data'Length - 1) := Data;
         Cursor := Cursor + Data'Length;
      end Store_Bytes;

      Required_Length : Natural :=
        String'("tree ")'Length + Object_ID_SHA1_Hex_Length + 1
        + String'("author ")'Length + Author_Line'Length + 1
        + String'("committer ")'Length + Committer_Line'Length + 1
        + 1
        + Message'Length;
   begin
      Last := Commit_Data'First - 1;
      if Tree_ID_Hex'Length /=
          Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
        or else (Has_Parent
                 and then Parent_ID_Hex'Length /=
                   Stream_Element_Offset (Object_ID_SHA1_Hex_Length))
        or else not Clean_Header_Line (Author_Line)
        or else not Clean_Header_Line (Committer_Line)
        or else not Clean_Message (Message)
      then
         return Invalid_Command;
      end if;

      for Item of Tree_ID_Hex loop
         if not Hex_Character (Character'Val (Item)) then
            return Invalid_Command;
         end if;
      end loop;
      if Has_Parent then
         for Item of Parent_ID_Hex loop
            if not Hex_Character (Character'Val (Item)) then
               return Invalid_Command;
            end if;
         end loop;
         Required_Length :=
           Required_Length
           + String'("parent ")'Length + Object_ID_SHA1_Hex_Length + 1;
      end if;

      if Commit_Data'Length < Stream_Element_Offset (Required_Length) then
         return Invalid_Command;
      end if;

      Store ("tree ");
      Store_Bytes (Tree_ID_Hex);
      Store (Character'Val (10) & "");
      if Has_Parent then
         Store ("parent ");
         Store_Bytes (Parent_ID_Hex);
         Store (Character'Val (10) & "");
      end if;
      Store ("author " & Author_Line & Character'Val (10));
      Store ("committer " & Committer_Line & Character'Val (10));
      Store (Character'Val (10) & Message);
      Last := Cursor - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Commit_Data'First - 1;
         return Invalid_Command;
      when others =>
         Last := Commit_Data'First - 1;
         return Write_Failed;
   end Build_Commit_Object;

   function Build_Merge_Conflict_File
     (Ours_Label    : String;
      Ours_Data     : Stream_Element_Array;
      Theirs_Label  : String;
      Theirs_Data   : Stream_Element_Array;
      Conflict_Data : out Stream_Element_Array;
      Last          : out Stream_Element_Offset)
      return Status
   is
      Cursor : Stream_Element_Offset := Conflict_Data'First;

      function Clean_Label (Text : String) return Boolean is
      begin
         if Text'Length = 0
           or else Text'Length > Maximum_Ref_Name_Length
         then
            return False;
         end if;
         for Ch of Text loop
            if Ch = Character'Val (0)
              or else Ch = Character'Val (10)
              or else Ch = Character'Val (13)
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Clean_Label;

      procedure Store_Text (Text : String) is
      begin
         for Ch of Text loop
            Conflict_Data (Cursor) := Stream_Element (Character'Pos (Ch));
            Cursor := Cursor + 1;
         end loop;
      end Store_Text;

      procedure Store_Bytes (Data : Stream_Element_Array) is
      begin
         if Data'Length > 0 then
            Conflict_Data (Cursor .. Cursor + Data'Length - 1) := Data;
            Cursor := Cursor + Data'Length;
         end if;
      end Store_Bytes;

      function Ends_With_LF (Data : Stream_Element_Array) return Boolean is
      begin
         return
           Data'Length > 0
           and then Data (Data'Last) = Stream_Element (Character'Pos (Character'Val (10)));
      end Ends_With_LF;

      Required_Length : constant Natural :=
        String'("<<<<<<< ")'Length + Ours_Label'Length + 1
        + Natural (Ours_Data'Length)
        + (if Ends_With_LF (Ours_Data) then 0 else 1)
        + String'("=======")'Length + 1
        + Natural (Theirs_Data'Length)
        + (if Ends_With_LF (Theirs_Data) then 0 else 1)
        + String'(">>>>>>> ")'Length + Theirs_Label'Length + 1;
   begin
      Last := Conflict_Data'First - 1;
      if not Clean_Label (Ours_Label)
        or else not Clean_Label (Theirs_Label)
        or else Conflict_Data'Length < Stream_Element_Offset (Required_Length)
      then
         return Invalid_Command;
      end if;

      Store_Text ("<<<<<<< " & Ours_Label & Character'Val (10));
      Store_Bytes (Ours_Data);
      if not Ends_With_LF (Ours_Data) then
         Store_Text (Character'Val (10) & "");
      end if;
      Store_Text ("=======" & Character'Val (10));
      Store_Bytes (Theirs_Data);
      if not Ends_With_LF (Theirs_Data) then
         Store_Text (Character'Val (10) & "");
      end if;
      Store_Text (">>>>>>> " & Theirs_Label & Character'Val (10));
      Last := Cursor - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Conflict_Data'First - 1;
         return Invalid_Command;
      when others =>
         Last := Conflict_Data'First - 1;
         return Write_Failed;
   end Build_Merge_Conflict_File;

   function Classify_Three_Way_Blob_Merge
     (Base_ID_Hex   : Stream_Element_Array;
      Ours_ID_Hex   : Stream_Element_Array;
      Theirs_ID_Hex : Stream_Element_Array;
      Result        : out Three_Way_Merge_Result)
      return Status
   is
      function Valid_ID (Value : Stream_Element_Array) return Boolean is
      begin
         if Value'Length /=
           Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
         then
            return False;
         end if;
         for Item of Value loop
            if not Hex_Character (Character'Val (Item)) then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Valid_ID;

      function Same_ID
        (Left  : Stream_Element_Array;
         Right : Stream_Element_Array)
         return Boolean
      is
      begin
         if Left'Length /= Right'Length then
            return False;
         end if;
         for Offset in 0 .. Object_ID_SHA1_Hex_Length - 1 loop
            if Left (Left'First + Stream_Element_Offset (Offset))
              /= Right (Right'First + Stream_Element_Offset (Offset))
            then
               return False;
            end if;
         end loop;
         return True;
      end Same_ID;
   begin
      Result := Merge_Conflict;
      if not Valid_ID (Base_ID_Hex)
        or else not Valid_ID (Ours_ID_Hex)
        or else not Valid_ID (Theirs_ID_Hex)
      then
         return Invalid_Command;
      end if;

      if Same_ID (Ours_ID_Hex, Theirs_ID_Hex) then
         Result := Merge_Unchanged;
      elsif Same_ID (Base_ID_Hex, Ours_ID_Hex) then
         Result := Merge_Use_Theirs;
      elsif Same_ID (Base_ID_Hex, Theirs_ID_Hex) then
         Result := Merge_Use_Ours;
      else
         Result := Merge_Conflict;
      end if;
      return Ok;
   exception
      when Constraint_Error =>
         Result := Merge_Conflict;
         return Invalid_Command;
      when others =>
         Result := Merge_Conflict;
         return Internal_Error;
   end Classify_Three_Way_Blob_Merge;

   function Build_Sequencer_Pick_Line
     (Commit_ID_Hex : Stream_Element_Array;
      Subject       : String;
      Line          : out Stream_Element_Array;
      Last          : out Stream_Element_Offset)
      return Status
   is
      Cursor : Stream_Element_Offset := Line'First;
      Required_Length : constant Natural :=
        String'("pick ")'Length + Object_ID_SHA1_Hex_Length + 1
        + Subject'Length + 1;

      function Clean_Subject return Boolean is
      begin
         if Subject'Length = 0
           or else Subject'Length > Maximum_Pkt_Line_Payload_Length
         then
            return False;
         end if;
         for Ch of Subject loop
            if Ch = Character'Val (0)
              or else Ch = Character'Val (10)
              or else Ch = Character'Val (13)
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Clean_Subject;

      procedure Store_Text (Text : String) is
      begin
         for Ch of Text loop
            Line (Cursor) := Stream_Element (Character'Pos (Ch));
            Cursor := Cursor + 1;
         end loop;
      end Store_Text;

      procedure Store_Bytes (Data : Stream_Element_Array) is
      begin
         Line (Cursor .. Cursor + Data'Length - 1) := Data;
         Cursor := Cursor + Data'Length;
      end Store_Bytes;
   begin
      Last := Line'First - 1;
      if Commit_ID_Hex'Length /=
          Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
        or else not Clean_Subject
        or else Line'Length < Stream_Element_Offset (Required_Length)
      then
         return Invalid_Command;
      end if;

      for Item of Commit_ID_Hex loop
         if not Hex_Character (Character'Val (Item)) then
            return Invalid_Command;
         end if;
      end loop;

      Store_Text ("pick ");
      Store_Bytes (Commit_ID_Hex);
      Store_Text (" " & Subject & Character'Val (10));
      Last := Cursor - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Line'First - 1;
         return Invalid_Command;
      when others =>
         Last := Line'First - 1;
         return Write_Failed;
   end Build_Sequencer_Pick_Line;

   function Build_Sequencer_Pick_Todo
     (Commit_IDs_Hex : Object_ID_Hex_Array;
      Subjects       : Stream_Element_Array;
      Subject_Lasts  : Index_Path_Last_Array;
      Count          : Natural;
      Todo           : out Stream_Element_Array;
      Last           : out Stream_Element_Offset)
      return Status
   is
      Cursor        : Stream_Element_Offset := Todo'First;
      Subject_First : Stream_Element_Offset := Subjects'First;
      Line_Data     : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Pkt_Line_Payload_Length));
      Line_Last     : Stream_Element_Offset;
      Status_Value  : Status;

      function Subject_Text
        (First_Index : Stream_Element_Offset;
         Last_Index  : Stream_Element_Offset) return String
      is
         Result : String
           (1 .. Natural (Last_Index - First_Index + 1));
      begin
         for Offset in 0 .. Last_Index - First_Index loop
            if Subjects (First_Index + Offset) > 127 then
               return "";
            end if;
            Result (Natural (Offset) + 1) :=
              Character'Val (Subjects (First_Index + Offset));
         end loop;
         return Result;
      exception
         when others =>
            return "";
      end Subject_Text;
   begin
      Last := Todo'First - 1;
      if Count = 0
        or else Count > Commit_IDs_Hex'Length
        or else Count > Subject_Lasts'Length
      then
         return Invalid_Command;
      end if;

      for Index_Value in 1 .. Count loop
         if Subject_Lasts (Subject_Lasts'First + Index_Value - 1)
           < Subject_First
         then
            return Invalid_Command;
         end if;

         declare
            Subject_Last : constant Stream_Element_Offset :=
              Subject_Lasts (Subject_Lasts'First + Index_Value - 1);
            Subject_Value : constant String :=
              Subject_Text (Subject_First, Subject_Last);
         begin
            if Subject_Value'Length = 0 then
               return Invalid_Command;
            end if;
            Status_Value :=
              Build_Sequencer_Pick_Line
                (Stream_Element_Array
                   (Commit_IDs_Hex
                      (Commit_IDs_Hex'First + Index_Value - 1)),
                 Subject_Value,
                 Line_Data,
                 Line_Last);
            if Status_Value /= Ok then
               return Status_Value;
            elsif Cursor + (Line_Last - Line_Data'First) > Todo'Last then
               return Write_Failed;
            end if;

            Todo (Cursor .. Cursor + (Line_Last - Line_Data'First)) :=
              Line_Data (Line_Data'First .. Line_Last);
            Cursor := Cursor + (Line_Last - Line_Data'First) + 1;
            Subject_First := Subject_Last + 1;
         end;
      end loop;

      Last := Cursor - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Todo'First - 1;
         return Invalid_Command;
      when others =>
         Last := Todo'First - 1;
         return Write_Failed;
   end Build_Sequencer_Pick_Todo;

   function Build_Tag_Object
     (Target_ID_Hex : Stream_Element_Array;
      Target_Kind   : Pack_Object_Kind;
      Tag_Name      : String;
      Tagger_Line   : String;
      Message       : String;
      Tag_Data      : out Stream_Element_Array;
      Last          : out Stream_Element_Offset)
      return Status
   is
      Cursor : Stream_Element_Offset := Tag_Data'First;

      function Kind_Text return String is
      begin
         case Target_Kind is
            when Pack_Commit =>
               return "commit";
            when Pack_Tree =>
               return "tree";
            when Pack_Blob =>
               return "blob";
            when Pack_Tag =>
               return "tag";
            when others =>
               return "";
         end case;
      end Kind_Text;

      function Clean_Line (Text : String) return Boolean is
      begin
         if Text'Length = 0
           or else Text'Length > Maximum_Pkt_Line_Payload_Length
         then
            return False;
         end if;
         for Ch of Text loop
            if Ch = Character'Val (0)
              or else Ch = Character'Val (10)
              or else Ch = Character'Val (13)
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Clean_Line;

      function Clean_Message (Text : String) return Boolean is
      begin
         if Text'Length > Maximum_Pkt_Line_Payload_Length then
            return False;
         end if;
         for Ch of Text loop
            if Ch = Character'Val (0) or else Ch = Character'Val (13) then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Clean_Message;

      procedure Store (Text : String) is
      begin
         for Ch of Text loop
            Tag_Data (Cursor) := Stream_Element (Character'Pos (Ch));
            Cursor := Cursor + 1;
         end loop;
      end Store;

      procedure Store_Bytes (Data : Stream_Element_Array) is
      begin
         Tag_Data (Cursor .. Cursor + Data'Length - 1) := Data;
         Cursor := Cursor + Data'Length;
      end Store_Bytes;

      Type_Text : constant String := Kind_Text;
      Required_Length : constant Natural :=
        String'("object ")'Length + Object_ID_SHA1_Hex_Length + 1
        + String'("type ")'Length + Type_Text'Length + 1
        + String'("tag ")'Length + Tag_Name'Length + 1
        + String'("tagger ")'Length + Tagger_Line'Length + 1
        + 1
        + Message'Length;
   begin
      Last := Tag_Data'First - 1;
      if Target_ID_Hex'Length /=
          Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
        or else Type_Text'Length = 0
        or else not Clean_Line (Tag_Name)
        or else not Clean_Line (Tagger_Line)
        or else not Clean_Message (Message)
        or else Tag_Data'Length < Stream_Element_Offset (Required_Length)
      then
         return Invalid_Command;
      end if;

      for Item of Target_ID_Hex loop
         if not Hex_Character (Character'Val (Item)) then
            return Invalid_Command;
         end if;
      end loop;

      Store ("object ");
      Store_Bytes (Target_ID_Hex);
      Store (Character'Val (10) & "type " & Type_Text & Character'Val (10));
      Store ("tag " & Tag_Name & Character'Val (10));
      Store ("tagger " & Tagger_Line & Character'Val (10));
      Store (Character'Val (10) & Message);
      Last := Cursor - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Tag_Data'First - 1;
         return Invalid_Command;
      when others =>
         Last := Tag_Data'First - 1;
         return Write_Failed;
   end Build_Tag_Object;

   function Parse_Commit_Tree_ID
     (Data        : Stream_Element_Array;
      Tree_ID_Hex : out Stream_Element_Array;
      Last        : out Stream_Element_Offset)
      return Status
   is
      Raw_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last : Stream_Element_Offset;
      Hex_First : Stream_Element_Offset;
      Line_End  : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Last := Tree_ID_Hex'First - 1;
      if Tree_ID_Hex'Length
        < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Read_Failed;
      elsif Data'Length
        < Stream_Element_Offset (5 + Object_ID_SHA1_Hex_Length + 1)
      then
         return Read_Failed;
      elsif Data (Data'First) /= Stream_Element (Character'Pos ('t'))
        or else Data (Data'First + 1) /= Stream_Element (Character'Pos ('r'))
        or else Data (Data'First + 2) /= Stream_Element (Character'Pos ('e'))
        or else Data (Data'First + 3) /= Stream_Element (Character'Pos ('e'))
        or else Data (Data'First + 4) /= Stream_Element (Character'Pos (' '))
      then
         return Invalid_Command;
      end if;

      Hex_First := Data'First + 5;
      Line_End :=
        Hex_First + Stream_Element_Offset (Object_ID_SHA1_Hex_Length);
      if Line_End > Data'Last
        or else Data (Line_End) /= Stream_Element (Character'Pos (Character'Val (10)))
      then
         return Invalid_Command;
      end if;

      Tree_ID_Hex
        (Tree_ID_Hex'First
         .. Tree_ID_Hex'First
            + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
            - 1) :=
        Data
          (Hex_First
           .. Hex_First
              + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
              - 1);
      Status_Value :=
        Parse_Object_ID_Hex
          (Tree_ID_Hex
             (Tree_ID_Hex'First
              .. Tree_ID_Hex'First
                 + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                 - 1),
           Raw_ID,
           Raw_Last);
      if Status_Value /= Ok then
         Last := Tree_ID_Hex'First - 1;
         return Status_Value;
      end if;

      Last :=
        Tree_ID_Hex'First
        + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
        - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Tree_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Last := Tree_ID_Hex'First - 1;
         return Internal_Error;
   end Parse_Commit_Tree_ID;

   function Parse_Commit_Parent_ID
     (Data          : Stream_Element_Array;
      Parent_Index  : Positive;
      Parent_ID_Hex : out Stream_Element_Array;
      Last          : out Stream_Element_Offset)
      return Status
   is
      Tree_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Tree_Last : Stream_Element_Offset;
      Raw_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last : Stream_Element_Offset;
      Cursor : Stream_Element_Offset;
      Current_Parent : Natural := 0;
      Status_Value : Status;

      function Line_Has_Prefix
        (First : Stream_Element_Offset;
         Text  : String) return Boolean
      is
      begin
         if First + Stream_Element_Offset (Text'Length) - 1 > Data'Last then
            return False;
         end if;
         for Index in Text'Range loop
            if Data (First + Stream_Element_Offset (Index - Text'First))
              /= Stream_Element (Character'Pos (Text (Index)))
            then
               return False;
            end if;
         end loop;
         return True;
      end Line_Has_Prefix;

      function Find_LF
        (First : Stream_Element_Offset) return Stream_Element_Offset
      is
         Pos : Stream_Element_Offset := First;
      begin
         while Pos <= Data'Last loop
            if Data (Pos) = Stream_Element (Character'Pos (Character'Val (10))) then
               return Pos;
            elsif Data (Pos) = 0
              or else Data (Pos) = Stream_Element (Character'Pos (Character'Val (13)))
            then
               return Data'First - 1;
            end if;
            Pos := Pos + 1;
         end loop;
         return Data'First - 1;
      end Find_LF;
   begin
      Last := Parent_ID_Hex'First - 1;
      if Parent_ID_Hex'Length
        < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Read_Failed;
      end if;

      Status_Value := Parse_Commit_Tree_ID (Data, Tree_ID, Tree_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Cursor :=
        Data'First
        + Stream_Element_Offset (5 + Object_ID_SHA1_Hex_Length + 1);
      while Cursor <= Data'Last loop
         declare
            LF_Pos : constant Stream_Element_Offset := Find_LF (Cursor);
         begin
            if LF_Pos < Data'First then
               Last := Parent_ID_Hex'First - 1;
               return Invalid_Command;
            elsif LF_Pos = Cursor
              or else Line_Has_Prefix (Cursor, "author ")
              or else Line_Has_Prefix (Cursor, "committer ")
            then
               Last := Parent_ID_Hex'First - 1;
               return Invalid_Command;
            elsif not Line_Has_Prefix (Cursor, "parent ") then
               Last := Parent_ID_Hex'First - 1;
               return Invalid_Command;
            elsif LF_Pos - Cursor
              /= Stream_Element_Offset (7 + Object_ID_SHA1_Hex_Length)
            then
               Last := Parent_ID_Hex'First - 1;
               return Invalid_Command;
            end if;

            Current_Parent := Current_Parent + 1;
            if Current_Parent = Parent_Index then
               Parent_ID_Hex
                 (Parent_ID_Hex'First
                  .. Parent_ID_Hex'First
                     + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                     - 1) :=
                 Data
                   (Cursor + 7
                    .. Cursor + 7
                       + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                       - 1);
               Status_Value :=
                 Parse_Object_ID_Hex
                   (Parent_ID_Hex
                      (Parent_ID_Hex'First
                       .. Parent_ID_Hex'First
                          + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                          - 1),
                    Raw_ID,
                    Raw_Last);
               if Status_Value /= Ok then
                  Last := Parent_ID_Hex'First - 1;
                  return Status_Value;
               elsif Raw_Last /= Raw_ID'Last then
                  Last := Parent_ID_Hex'First - 1;
                  return Invalid_Command;
               end if;
               Last :=
                 Parent_ID_Hex'First
                 + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                 - 1;
               return Ok;
            end if;

            Cursor := LF_Pos + 1;
         end;
      end loop;

      Last := Parent_ID_Hex'First - 1;
      return Invalid_Command;
   exception
      when Constraint_Error =>
         Last := Parent_ID_Hex'First - 1;
         return Invalid_Command;
      when others =>
         Last := Parent_ID_Hex'First - 1;
         return Internal_Error;
   end Parse_Commit_Parent_ID;

   function Parse_Commit_Author_Line
     (Data : Stream_Element_Array;
      Text : out Stream_Element_Array;
      Last : out Stream_Element_Offset)
      return Status
   is
      Tree_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Tree_Last : Stream_Element_Offset;
      Cursor : Stream_Element_Offset;
      Status_Value : Status;

      function Line_Has_Prefix
        (First : Stream_Element_Offset;
         Prefix : String) return Boolean
      is
      begin
         if First + Stream_Element_Offset (Prefix'Length) - 1 > Data'Last then
            return False;
         end if;
         for Index in Prefix'Range loop
            if Data (First + Stream_Element_Offset (Index - Prefix'First))
              /= Stream_Element (Character'Pos (Prefix (Index)))
            then
               return False;
            end if;
         end loop;
         return True;
      end Line_Has_Prefix;

      function Find_LF
        (First : Stream_Element_Offset) return Stream_Element_Offset
      is
         Pos : Stream_Element_Offset := First;
      begin
         while Pos <= Data'Last loop
            if Data (Pos) = Stream_Element (Character'Pos (Character'Val (10))) then
               return Pos;
            elsif Data (Pos) = 0
              or else Data (Pos) = Stream_Element (Character'Pos (Character'Val (13)))
            then
               return Data'First - 1;
            end if;
            Pos := Pos + 1;
         end loop;
         return Data'First - 1;
      end Find_LF;
   begin
      Last := Text'First - 1;
      Status_Value := Parse_Commit_Tree_ID (Data, Tree_ID, Tree_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Cursor :=
        Data'First
        + Stream_Element_Offset (5 + Object_ID_SHA1_Hex_Length + 1);
      while Cursor <= Data'Last loop
         declare
            LF_Pos : constant Stream_Element_Offset := Find_LF (Cursor);
         begin
            if LF_Pos < Data'First or else LF_Pos = Cursor then
               Last := Text'First - 1;
               return Invalid_Command;
            elsif Line_Has_Prefix (Cursor, "parent ") then
               if LF_Pos - Cursor
                 /= Stream_Element_Offset (7 + Object_ID_SHA1_Hex_Length)
               then
                  Last := Text'First - 1;
                  return Invalid_Command;
               end if;
            elsif Line_Has_Prefix (Cursor, "author ") then
               declare
                  Text_First : constant Stream_Element_Offset := Cursor + 7;
                  Text_Length : constant Stream_Element_Offset := LF_Pos - Text_First;
               begin
                  if Text_Length = 0 then
                     Last := Text'First - 1;
                     return Invalid_Command;
                  elsif Text_Length > Text'Length then
                     Last := Text'First - 1;
                     return Read_Failed;
                  end if;
                  Text (Text'First .. Text'First + Text_Length - 1) :=
                    Data (Text_First .. LF_Pos - 1);
                  Last := Text'First + Text_Length - 1;
                  return Ok;
               end;
            else
               Last := Text'First - 1;
               return Invalid_Command;
            end if;

            Cursor := LF_Pos + 1;
         end;
      end loop;

      Last := Text'First - 1;
      return Invalid_Command;
   exception
      when Constraint_Error =>
         Last := Text'First - 1;
         return Invalid_Command;
      when others =>
         Last := Text'First - 1;
         return Internal_Error;
   end Parse_Commit_Author_Line;

   function Parse_Commit_Committer_Line
     (Data : Stream_Element_Array;
      Text : out Stream_Element_Array;
      Last : out Stream_Element_Offset)
      return Status
   is
      Tree_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Tree_Last : Stream_Element_Offset;
      Cursor : Stream_Element_Offset;
      Has_Author : Boolean := False;
      Status_Value : Status;

      function Line_Has_Prefix
        (First : Stream_Element_Offset;
         Prefix : String) return Boolean
      is
      begin
         if First + Stream_Element_Offset (Prefix'Length) - 1 > Data'Last then
            return False;
         end if;
         for Index in Prefix'Range loop
            if Data (First + Stream_Element_Offset (Index - Prefix'First))
              /= Stream_Element (Character'Pos (Prefix (Index)))
            then
               return False;
            end if;
         end loop;
         return True;
      end Line_Has_Prefix;

      function Find_LF
        (First : Stream_Element_Offset) return Stream_Element_Offset
      is
         Pos : Stream_Element_Offset := First;
      begin
         while Pos <= Data'Last loop
            if Data (Pos) = Stream_Element (Character'Pos (Character'Val (10))) then
               return Pos;
            elsif Data (Pos) = 0
              or else Data (Pos) = Stream_Element (Character'Pos (Character'Val (13)))
            then
               return Data'First - 1;
            end if;
            Pos := Pos + 1;
         end loop;
         return Data'First - 1;
      end Find_LF;
   begin
      Last := Text'First - 1;
      Status_Value := Parse_Commit_Tree_ID (Data, Tree_ID, Tree_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Cursor :=
        Data'First
        + Stream_Element_Offset (5 + Object_ID_SHA1_Hex_Length + 1);
      while Cursor <= Data'Last loop
         declare
            LF_Pos : constant Stream_Element_Offset := Find_LF (Cursor);
         begin
            if LF_Pos < Data'First or else LF_Pos = Cursor then
               Last := Text'First - 1;
               return Invalid_Command;
            elsif Line_Has_Prefix (Cursor, "parent ") then
               if Has_Author
                 or else LF_Pos - Cursor
                   /= Stream_Element_Offset (7 + Object_ID_SHA1_Hex_Length)
               then
                  Last := Text'First - 1;
                  return Invalid_Command;
               end if;
            elsif Line_Has_Prefix (Cursor, "author ") then
               if Has_Author or else LF_Pos = Cursor + 7 then
                  Last := Text'First - 1;
                  return Invalid_Command;
               end if;
               Has_Author := True;
            elsif Line_Has_Prefix (Cursor, "committer ") then
               if not Has_Author then
                  Last := Text'First - 1;
                  return Invalid_Command;
               end if;
               declare
                  Text_First : constant Stream_Element_Offset := Cursor + 10;
                  Text_Length : constant Stream_Element_Offset := LF_Pos - Text_First;
               begin
                  if Text_Length = 0 then
                     Last := Text'First - 1;
                     return Invalid_Command;
                  elsif Text_Length > Text'Length then
                     Last := Text'First - 1;
                     return Read_Failed;
                  end if;
                  Text (Text'First .. Text'First + Text_Length - 1) :=
                    Data (Text_First .. LF_Pos - 1);
                  Last := Text'First + Text_Length - 1;
                  return Ok;
               end;
            else
               Last := Text'First - 1;
               return Invalid_Command;
            end if;

            Cursor := LF_Pos + 1;
         end;
      end loop;

      Last := Text'First - 1;
      return Invalid_Command;
   exception
      when Constraint_Error =>
         Last := Text'First - 1;
         return Invalid_Command;
      when others =>
         Last := Text'First - 1;
         return Internal_Error;
   end Parse_Commit_Committer_Line;

   function Parse_Commit_Message_Offset
     (Data           : Stream_Element_Array;
      Message_Offset : out Natural)
      return Status
   is
      Parent_Count : Natural := 0;
      Cursor : Stream_Element_Offset;
      Status_Value : Status;

      function Find_LF
        (First : Stream_Element_Offset) return Stream_Element_Offset
      is
         Pos : Stream_Element_Offset := First;
      begin
         while Pos <= Data'Last loop
            if Data (Pos) = Stream_Element (Character'Pos (Character'Val (10))) then
               return Pos;
            elsif Data (Pos) = 0
              or else Data (Pos) = Stream_Element (Character'Pos (Character'Val (13)))
            then
               return Data'First - 1;
            end if;
            Pos := Pos + 1;
         end loop;
         return Data'First - 1;
      end Find_LF;
   begin
      Message_Offset := 0;
      if Data'Length > Stream_Element_Offset (Natural'Last) then
         return Unsupported_Feature;
      end if;

      Status_Value := Validate_Commit_Object (Data, Parent_Count);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Cursor := Data'First;
      while Cursor <= Data'Last loop
         declare
            LF_Pos : constant Stream_Element_Offset := Find_LF (Cursor);
         begin
            if LF_Pos < Data'First then
               Message_Offset := 0;
               return Invalid_Command;
            elsif LF_Pos = Cursor then
               Message_Offset := Natural (Cursor + 1 - Data'First);
               return Ok;
            end if;
            Cursor := LF_Pos + 1;
         end;
      end loop;

      Message_Offset := 0;
      return Invalid_Command;
   exception
      when Constraint_Error =>
         Message_Offset := 0;
         return Invalid_Command;
      when others =>
         Message_Offset := 0;
         return Internal_Error;
   end Parse_Commit_Message_Offset;

   function Validate_Commit_Object
     (Data         : Stream_Element_Array;
      Parent_Count : out Natural)
      return Status
   is
      Tree_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Tree_Last : Stream_Element_Offset;
      Cursor : Stream_Element_Offset;
      Has_Author : Boolean := False;
      Has_Committer : Boolean := False;
      Status_Value : Status;

      function Line_Has_Prefix
        (First : Stream_Element_Offset;
         Text  : String) return Boolean
      is
      begin
         if First + Stream_Element_Offset (Text'Length) - 1 > Data'Last then
            return False;
         end if;
         for Index in Text'Range loop
            if Data (First + Stream_Element_Offset (Index - Text'First))
              /= Stream_Element (Character'Pos (Text (Index)))
            then
               return False;
            end if;
         end loop;
         return True;
      end Line_Has_Prefix;

      function Find_LF
        (First : Stream_Element_Offset) return Stream_Element_Offset
      is
         Pos : Stream_Element_Offset := First;
      begin
         while Pos <= Data'Last loop
            if Data (Pos) = Stream_Element (Character'Pos (Character'Val (10))) then
               return Pos;
            elsif Data (Pos) = 0
              or else Data (Pos) = Stream_Element (Character'Pos (Character'Val (13)))
            then
               return Data'First - 1;
            end if;
            Pos := Pos + 1;
         end loop;
         return Data'First - 1;
      end Find_LF;

      function Valid_Object_ID_Line
        (First : Stream_Element_Offset;
         Prefix : String;
         LF_Pos : Stream_Element_Offset) return Boolean
      is
         Raw_ID : Stream_Element_Array
           (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
         Raw_Last : Stream_Element_Offset;
      begin
         if not Line_Has_Prefix (First, Prefix)
           or else LF_Pos - First
             /= Stream_Element_Offset (Prefix'Length + Object_ID_SHA1_Hex_Length)
         then
            return False;
         end if;
         return
           Parse_Object_ID_Hex
             (Data
                (First + Stream_Element_Offset (Prefix'Length)
                 .. LF_Pos - 1),
              Raw_ID,
              Raw_Last) = Ok
           and then Raw_Last = Raw_ID'Last;
      end Valid_Object_ID_Line;
   begin
      Parent_Count := 0;
      Status_Value := Parse_Commit_Tree_ID (Data, Tree_ID, Tree_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Cursor :=
        Data'First
        + Stream_Element_Offset (5 + Object_ID_SHA1_Hex_Length + 1);
      while Cursor <= Data'Last loop
         declare
            LF_Pos : constant Stream_Element_Offset := Find_LF (Cursor);
         begin
            if LF_Pos < Data'First then
               Parent_Count := 0;
               return Invalid_Command;
            elsif LF_Pos = Cursor then
               if Has_Author and then Has_Committer then
                  return Ok;
               else
                  Parent_Count := 0;
                  return Invalid_Command;
               end if;
            elsif Line_Has_Prefix (Cursor, "parent ") then
               if Has_Author or else Has_Committer
                 or else not Valid_Object_ID_Line (Cursor, "parent ", LF_Pos)
               then
                  Parent_Count := 0;
                  return Invalid_Command;
               end if;
               Parent_Count := Parent_Count + 1;
            elsif Line_Has_Prefix (Cursor, "author ") then
               if Has_Author or else Has_Committer or else LF_Pos = Cursor + 7 then
                  Parent_Count := 0;
                  return Invalid_Command;
               end if;
               Has_Author := True;
            elsif Line_Has_Prefix (Cursor, "committer ") then
               if not Has_Author or else Has_Committer or else LF_Pos = Cursor + 10 then
                  Parent_Count := 0;
                  return Invalid_Command;
               end if;
               Has_Committer := True;
            elsif not Has_Committer then
               Parent_Count := 0;
               return Invalid_Command;
            end if;
            Cursor := LF_Pos + 1;
         end;
      end loop;

      Parent_Count := 0;
      return Invalid_Command;
   exception
      when Constraint_Error =>
         Parent_Count := 0;
         return Invalid_Command;
      when others =>
         Parent_Count := 0;
         return Internal_Error;
   end Validate_Commit_Object;

   function Parse_Tag_Target
     (Data          : Stream_Element_Array;
      Target_ID_Hex : out Stream_Element_Array;
      Last          : out Stream_Element_Offset;
      Target_Kind   : out Pack_Object_Kind)
      return Status
   is
      Raw_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Raw_Last : Stream_Element_Offset;
      Hex_First : Stream_Element_Offset;
      Object_LF : Stream_Element_Offset;
      Type_First : Stream_Element_Offset;
      Type_LF : Stream_Element_Offset;
      Status_Value : Status;

      function Line_Has_Prefix
        (First : Stream_Element_Offset;
         Text  : String) return Boolean
      is
      begin
         if First + Stream_Element_Offset (Text'Length) - 1 > Data'Last then
            return False;
         end if;
         for Index in Text'Range loop
            if Data (First + Stream_Element_Offset (Index - Text'First))
              /= Stream_Element (Character'Pos (Text (Index)))
            then
               return False;
            end if;
         end loop;
         return True;
      end Line_Has_Prefix;

      function Find_LF
        (First : Stream_Element_Offset) return Stream_Element_Offset
      is
         Pos : Stream_Element_Offset := First;
      begin
         while Pos <= Data'Last loop
            if Data (Pos) = Stream_Element (Character'Pos (Character'Val (10))) then
               return Pos;
            elsif Data (Pos) = 0
              or else Data (Pos) = Stream_Element (Character'Pos (Character'Val (13)))
            then
               return Data'First - 1;
            end if;
            Pos := Pos + 1;
         end loop;
         return Data'First - 1;
      end Find_LF;
   begin
      Last := Target_ID_Hex'First - 1;
      Target_Kind := Pack_Blob;
      if Target_ID_Hex'Length
        < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Read_Failed;
      elsif Data'Length
        < Stream_Element_Offset
            (7 + Object_ID_SHA1_Hex_Length + 1 + 5 + 3 + 1)
      then
         return Read_Failed;
      elsif not Line_Has_Prefix (Data'First, "object ") then
         return Invalid_Command;
      end if;

      Hex_First := Data'First + 7;
      Object_LF := Hex_First + Stream_Element_Offset (Object_ID_SHA1_Hex_Length);
      if Object_LF > Data'Last
        or else Data (Object_LF) /= Stream_Element (Character'Pos (Character'Val (10)))
      then
         return Invalid_Command;
      end if;

      Target_ID_Hex
        (Target_ID_Hex'First
         .. Target_ID_Hex'First
            + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
            - 1) :=
        Data
          (Hex_First
           .. Hex_First
              + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
              - 1);
      Status_Value :=
        Parse_Object_ID_Hex
          (Target_ID_Hex
             (Target_ID_Hex'First
              .. Target_ID_Hex'First
                 + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
                 - 1),
           Raw_ID,
           Raw_Last);
      if Status_Value /= Ok or else Raw_Last /= Raw_ID'Last then
         Last := Target_ID_Hex'First - 1;
         return Status_Value;
      end if;

      Type_First := Object_LF + 1;
      if not Line_Has_Prefix (Type_First, "type ") then
         Last := Target_ID_Hex'First - 1;
         return Invalid_Command;
      end if;

      Type_LF := Find_LF (Type_First);
      if Type_LF < Data'First
        or else Type_LF = Type_First + 5
      then
         Last := Target_ID_Hex'First - 1;
         Target_Kind := Pack_Blob;
         return Invalid_Command;
      end if;

      declare
         Name_Length : constant Natural := Natural (Type_LF - Type_First - 5);
         Name        : String (1 .. Name_Length);
      begin
         for Offset in 0 .. Name_Length - 1 loop
            Name (Offset + 1) :=
              Character'Val
                (Natural (Data (Type_First + 5 + Stream_Element_Offset (Offset))));
         end loop;
         if not Kind_From_Name (Name, Target_Kind)
           or else Target_Kind in Pack_OFS_Delta | Pack_REF_Delta
         then
            Last := Target_ID_Hex'First - 1;
            Target_Kind := Pack_Blob;
            return Invalid_Command;
         end if;
      end;

      Last :=
        Target_ID_Hex'First
        + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
        - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Target_ID_Hex'First - 1;
         Target_Kind := Pack_Blob;
         return Invalid_Command;
      when others =>
         Last := Target_ID_Hex'First - 1;
         Target_Kind := Pack_Blob;
         return Internal_Error;
   end Parse_Tag_Target;

   function Parse_Tag_Name
     (Data : Stream_Element_Array;
      Name : out Stream_Element_Array;
      Last : out Stream_Element_Offset)
      return Status
   is
      Target_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Target_Last : Stream_Element_Offset;
      Target_Kind : Pack_Object_Kind := Pack_Blob;
      Cursor : Stream_Element_Offset;
      Tag_LF : Stream_Element_Offset;
      Name_First : Stream_Element_Offset;
      Name_Length : Stream_Element_Offset;
      Status_Value : Status;

      function Line_Has_Prefix
        (First : Stream_Element_Offset;
         Text  : String) return Boolean
      is
      begin
         if First + Stream_Element_Offset (Text'Length) - 1 > Data'Last then
            return False;
         end if;
         for Index in Text'Range loop
            if Data (First + Stream_Element_Offset (Index - Text'First))
              /= Stream_Element (Character'Pos (Text (Index)))
            then
               return False;
            end if;
         end loop;
         return True;
      end Line_Has_Prefix;

      function Find_LF
        (First : Stream_Element_Offset) return Stream_Element_Offset
      is
         Pos : Stream_Element_Offset := First;
      begin
         while Pos <= Data'Last loop
            if Data (Pos) = Stream_Element (Character'Pos (Character'Val (10))) then
               return Pos;
            elsif Data (Pos) = 0
              or else Data (Pos) = Stream_Element (Character'Pos (Character'Val (13)))
            then
               return Data'First - 1;
            end if;
            Pos := Pos + 1;
         end loop;
         return Data'First - 1;
      end Find_LF;
   begin
      Last := Name'First - 1;
      Status_Value :=
        Parse_Tag_Target (Data, Target_ID, Target_Last, Target_Kind);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Cursor :=
        Data'First
        + Stream_Element_Offset
            (7 + Object_ID_SHA1_Hex_Length + 1 + 5);
      while Cursor <= Data'Last
        and then Data (Cursor) /= Stream_Element (Character'Pos (Character'Val (10)))
      loop
         Cursor := Cursor + 1;
      end loop;
      if Cursor > Data'Last then
         return Invalid_Command;
      end if;
      Cursor := Cursor + 1;

      Tag_LF := Find_LF (Cursor);
      if Tag_LF < Data'First
        or else not Line_Has_Prefix (Cursor, "tag ")
        or else Tag_LF = Cursor + 4
      then
         Last := Name'First - 1;
         return Invalid_Command;
      end if;

      Name_First := Cursor + 4;
      Name_Length := Tag_LF - Name_First;
      if Name_Length > Name'Length then
         Last := Name'First - 1;
         return Read_Failed;
      end if;

      Name (Name'First .. Name'First + Name_Length - 1) :=
        Data (Name_First .. Tag_LF - 1);
      Last := Name'First + Name_Length - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Name'First - 1;
         return Invalid_Command;
      when others =>
         Last := Name'First - 1;
         return Internal_Error;
   end Parse_Tag_Name;

   function Parse_Tag_Message_Offset
     (Data           : Stream_Element_Array;
      Message_Offset : out Natural)
      return Status
   is
      Target_Kind : Pack_Object_Kind := Pack_Blob;
      Cursor : Stream_Element_Offset;
      Status_Value : Status;

      function Find_LF
        (First : Stream_Element_Offset) return Stream_Element_Offset
      is
         Pos : Stream_Element_Offset := First;
      begin
         while Pos <= Data'Last loop
            if Data (Pos) = Stream_Element (Character'Pos (Character'Val (10))) then
               return Pos;
            elsif Data (Pos) = 0
              or else Data (Pos) = Stream_Element (Character'Pos (Character'Val (13)))
            then
               return Data'First - 1;
            end if;
            Pos := Pos + 1;
         end loop;
         return Data'First - 1;
      end Find_LF;
   begin
      Message_Offset := 0;
      if Data'Length > Stream_Element_Offset (Natural'Last) then
         return Unsupported_Feature;
      end if;

      Status_Value := Validate_Tag_Object (Data, Target_Kind);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Cursor := Data'First;
      while Cursor <= Data'Last loop
         declare
            LF_Pos : constant Stream_Element_Offset := Find_LF (Cursor);
         begin
            if LF_Pos < Data'First then
               Message_Offset := 0;
               return Invalid_Command;
            elsif LF_Pos = Cursor then
               Message_Offset := Natural (Cursor + 1 - Data'First);
               return Ok;
            end if;
            Cursor := LF_Pos + 1;
         end;
      end loop;

      Message_Offset := 0;
      return Invalid_Command;
   exception
      when Constraint_Error =>
         Message_Offset := 0;
         return Invalid_Command;
      when others =>
         Message_Offset := 0;
         return Internal_Error;
   end Parse_Tag_Message_Offset;

   function Validate_Object_Data
     (Kind : Pack_Object_Kind;
      Data : Stream_Element_Array)
      return Status
   is
      Entry_Count : Natural := 0;
      Parent_Count : Natural := 0;
      Target_Kind : Pack_Object_Kind := Pack_Blob;
   begin
      case Kind is
         when Pack_Blob =>
            return Ok;
         when Pack_Tree =>
            return Validate_Tree_Object (Data, Entry_Count);
         when Pack_Commit =>
            return Validate_Commit_Object (Data, Parent_Count);
         when Pack_Tag =>
            return Validate_Tag_Object (Data, Target_Kind);
         when Pack_OFS_Delta | Pack_REF_Delta =>
            return Unsupported_Feature;
      end case;
   exception
      when Constraint_Error =>
         return Invalid_Command;
      when others =>
         return Internal_Error;
   end Validate_Object_Data;

   function Validate_Tag_Object
     (Data        : Stream_Element_Array;
      Target_Kind : out Pack_Object_Kind)
      return Status
   is
      Target_ID : Stream_Element_Array
        (1 .. Stream_Element_Offset (Object_ID_SHA1_Hex_Length));
      Target_Last : Stream_Element_Offset;
      Cursor : Stream_Element_Offset;
      Status_Value : Status;

      function Line_Has_Prefix
        (First : Stream_Element_Offset;
         Text  : String) return Boolean
      is
      begin
         if First + Stream_Element_Offset (Text'Length) - 1 > Data'Last then
            return False;
         end if;
         for Index in Text'Range loop
            if Data (First + Stream_Element_Offset (Index - Text'First))
              /= Stream_Element (Character'Pos (Text (Index)))
            then
               return False;
            end if;
         end loop;
         return True;
      end Line_Has_Prefix;

      function Find_LF
        (First : Stream_Element_Offset) return Stream_Element_Offset
      is
         Pos : Stream_Element_Offset := First;
      begin
         while Pos <= Data'Last loop
            if Data (Pos) = Stream_Element (Character'Pos (Character'Val (10))) then
               return Pos;
            elsif Data (Pos) = 0
              or else Data (Pos) = Stream_Element (Character'Pos (Character'Val (13)))
            then
               return Data'First - 1;
            end if;
            Pos := Pos + 1;
         end loop;
         return Data'First - 1;
      end Find_LF;
   begin
      Target_Kind := Pack_Blob;
      Status_Value :=
        Parse_Tag_Target (Data, Target_ID, Target_Last, Target_Kind);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Cursor :=
        Data'First
        + Stream_Element_Offset
            (7 + Object_ID_SHA1_Hex_Length + 1 + 5);
      while Cursor <= Data'Last
        and then Data (Cursor) /= Stream_Element (Character'Pos (Character'Val (10)))
      loop
         Cursor := Cursor + 1;
      end loop;
      if Cursor > Data'Last then
         Target_Kind := Pack_Blob;
         return Invalid_Command;
      end if;
      Cursor := Cursor + 1;

      declare
         Tag_LF : constant Stream_Element_Offset := Find_LF (Cursor);
      begin
         if Tag_LF < Data'First
           or else not Line_Has_Prefix (Cursor, "tag ")
           or else Tag_LF = Cursor + 4
         then
            Target_Kind := Pack_Blob;
            return Invalid_Command;
         end if;
         Cursor := Tag_LF + 1;
      end;

      if Cursor > Data'Last then
         Target_Kind := Pack_Blob;
         return Invalid_Command;
      elsif Line_Has_Prefix (Cursor, "tagger ") then
         declare
            Tagger_LF : constant Stream_Element_Offset := Find_LF (Cursor);
         begin
            if Tagger_LF < Data'First or else Tagger_LF = Cursor + 7 then
               Target_Kind := Pack_Blob;
               return Invalid_Command;
            end if;
            Cursor := Tagger_LF + 1;
         end;
      end if;

      if Cursor <= Data'Last
        and then Data (Cursor) = Stream_Element (Character'Pos (Character'Val (10)))
      then
         return Ok;
      end if;

      Target_Kind := Pack_Blob;
      return Invalid_Command;
   exception
      when Constraint_Error =>
         Target_Kind := Pack_Blob;
         return Invalid_Command;
      when others =>
         Target_Kind := Pack_Blob;
         return Internal_Error;
   end Validate_Tag_Object;

   function Encode_Object_ID_Hex
     (Object_ID : Stream_Element_Array;
      Hex_Text  : out Stream_Element_Array;
      Last      : out Stream_Element_Offset)
      return Status
   is
      Cursor : Stream_Element_Offset := Hex_Text'First;
   begin
      Last := Hex_Text'First - 1;

      if Object_ID'Length < Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
        or else Hex_Text'Length
          < Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
      then
         return Read_Failed;
      end if;

      for Offset in 0 .. Object_ID_SHA1_Raw_Length - 1 loop
         declare
            Byte_Value : constant Natural :=
              Natural (Object_ID (Object_ID'First + Stream_Element_Offset (Offset)));
         begin
            Hex_Text (Cursor) := Hex_Digit (Byte_Value / 16);
            Hex_Text (Cursor + 1) := Hex_Digit (Byte_Value mod 16);
            Cursor := Cursor + 2;
         end;
      end loop;

      Last :=
        Hex_Text'First
        + Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
        - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Hex_Text'First - 1;
         return Read_Failed;
      when others =>
         Last := Hex_Text'First - 1;
         return Internal_Error;
   end Encode_Object_ID_Hex;

   function Parse_Object_ID_Hex
     (Hex_Text  : Stream_Element_Array;
      Object_ID : out Stream_Element_Array;
      Last      : out Stream_Element_Offset)
      return Status
   is
      Cursor : Stream_Element_Offset := Object_ID'First;
   begin
      Last := Object_ID'First - 1;

      if Hex_Text'Length
        /= Stream_Element_Offset (Object_ID_SHA1_Hex_Length)
        or else Object_ID'Length
          < Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
      then
         return Read_Failed;
      end if;

      for Offset in 0 .. Object_ID_SHA1_Raw_Length - 1 loop
         declare
            High : constant Natural :=
              Hex_Value (Hex_Text
                (Hex_Text'First + Stream_Element_Offset (Offset * 2)));
            Low : constant Natural :=
              Hex_Value (Hex_Text
                (Hex_Text'First + Stream_Element_Offset (Offset * 2 + 1)));
         begin
            if High > 15 or else Low > 15 then
               Last := Object_ID'First - 1;
               return Invalid_Command;
            end if;

            Object_ID (Cursor) := Stream_Element (High * 16 + Low);
            Cursor := Cursor + 1;
         end;
      end loop;

      Last :=
        Object_ID'First
        + Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
        - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Object_ID'First - 1;
         return Read_Failed;
      when others =>
         Last := Object_ID'First - 1;
         return Internal_Error;
   end Parse_Object_ID_Hex;

   function Parse_Pack_Object_Header
     (Data              : Stream_Element_Array;
      Kind              : out Pack_Object_Kind;
      Uncompressed_Size : out Natural;
      Header_Length     : out Natural)
      return Status
   is
      Byte_Value  : Stream_Element;
      Kind_Code   : Natural;
      Size_Value  : Natural;
      Shift       : Natural := 4;
      Index_Value : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Kind := Pack_Blob;
      Uncompressed_Size := 0;
      Header_Length := 0;

      if Data'Length = 0 then
         return Read_Failed;
      end if;

      Byte_Value := Data (Data'First);
      Kind_Code := Natural ((Byte_Value / 16) mod 8);
      Size_Value := Natural (Byte_Value mod 16);
      Status_Value := Pack_Kind_From_Code (Kind_Code, Kind);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Header_Length := 1;
      Index_Value := Data'First + 1;
      while Byte_Value >= 128 loop
         if Index_Value > Data'Last then
            Kind := Pack_Blob;
            Uncompressed_Size := 0;
            Header_Length := 0;
            return Read_Failed;
         end if;

         Byte_Value := Data (Index_Value);
         declare
            Payload_Bits : constant Natural := Natural (Byte_Value mod 128);
            Multiplier   : Natural := 1;
         begin
            for Bit_Index in 1 .. Shift loop
               if Multiplier > Natural'Last / 2 then
                  Kind := Pack_Blob;
                  Uncompressed_Size := 0;
                  Header_Length := 0;
                  return Invalid_Command;
               end if;
               Multiplier := Multiplier * 2;
            end loop;

            if Payload_Bits > 0
              and then Multiplier > Natural'Last / Payload_Bits
            then
               Kind := Pack_Blob;
               Uncompressed_Size := 0;
               Header_Length := 0;
               return Invalid_Command;
            elsif Size_Value > Natural'Last - Payload_Bits * Multiplier then
               Kind := Pack_Blob;
               Uncompressed_Size := 0;
               Header_Length := 0;
               return Invalid_Command;
            end if;
            Size_Value := Size_Value + Payload_Bits * Multiplier;
         end;

         Header_Length := Header_Length + 1;
         Shift := Shift + 7;
         Index_Value := Index_Value + 1;
      end loop;

      Uncompressed_Size := Size_Value;
      return Ok;
   exception
      when Constraint_Error =>
         Kind := Pack_Blob;
         Uncompressed_Size := 0;
         Header_Length := 0;
         return Read_Failed;
      when others =>
         Kind := Pack_Blob;
         Uncompressed_Size := 0;
         Header_Length := 0;
         return Internal_Error;
   end Parse_Pack_Object_Header;

   function Inflate_Pack_Object_Data
     (Compressed_Data            : Stream_Element_Array;
      Expected_Uncompressed_Size : Natural;
      Inflated_Data              : out Stream_Element_Array;
      Last                       : out Stream_Element_Offset)
      return Status
   is
      Filter       : Zlib.Filter_Type;
      Input_Cursor : Stream_Element_Offset := Compressed_Data'First;
      Output_Total : Natural := 0;
      In_Last      : Stream_Element_Offset := Compressed_Data'First;
      Out_Last     : Stream_Element_Offset := Inflated_Data'First - 1;
      Output_Cursor : Stream_Element_Offset := Inflated_Data'First;
   begin
      Last := Inflated_Data'First - 1;

      if Expected_Uncompressed_Size
        > Natural (Inflated_Data'Length)
      then
         return Read_Failed;
      elsif Compressed_Data'Length = 0 then
         return Read_Failed;
      end if;

      Zlib.Inflate_Init (Filter, Header => Zlib.Zlib_Header);

      while Input_Cursor <= Compressed_Data'Last loop
         if Output_Cursor <= Inflated_Data'Last then
            Zlib.Translate
              (Filter,
               Compressed_Data (Input_Cursor .. Compressed_Data'Last),
               In_Last,
               Inflated_Data (Output_Cursor .. Inflated_Data'Last),
               Out_Last,
               Zlib.No_Flush);
         else
            declare
               Empty_Output : Stream_Element_Array (1 .. 0);
            begin
               Zlib.Translate
                 (Filter,
                  Compressed_Data (Input_Cursor .. Compressed_Data'Last),
                  In_Last,
                  Empty_Output,
                  Out_Last,
                  Zlib.No_Flush);
            end;
         end if;

         if Out_Last >= Output_Cursor then
            declare
               Produced : constant Natural :=
                 Natural (Out_Last - Output_Cursor + 1);
            begin
               if Produced > Natural'Last - Output_Total then
                  Zlib.Close (Filter, Ignore_Error => True);
                  Last := Inflated_Data'First - 1;
                  return Unsupported_Feature;
               end if;

               Output_Total := Output_Total + Produced;
               if Output_Total > Expected_Uncompressed_Size then
                  Zlib.Close (Filter, Ignore_Error => True);
                  Last := Inflated_Data'First - 1;
                  return Invalid_Command;
               end if;

               Output_Cursor := Out_Last + 1;
               Last := Out_Last;
            end;
         end if;

         if In_Last >= Input_Cursor then
            Input_Cursor := In_Last + 1;
         elsif Out_Last < Output_Cursor - 1 then
            Zlib.Close (Filter, Ignore_Error => True);
            Last := Inflated_Data'First - 1;
            return Read_Failed;
         end if;

         exit when Zlib.Stream_End (Filter);
      end loop;

      declare
         Empty_Input : Stream_Element_Array (1 .. 0);
      begin
         while not Zlib.Stream_End (Filter) loop
            if Output_Cursor <= Inflated_Data'Last then
               Zlib.Translate
                 (Filter,
                  Empty_Input,
                  In_Last,
                  Inflated_Data (Output_Cursor .. Inflated_Data'Last),
                  Out_Last,
                  Zlib.Finish);
            else
               declare
                  Empty_Output : Stream_Element_Array (1 .. 0);
               begin
                  Zlib.Translate
                    (Filter,
                     Empty_Input,
                     In_Last,
                     Empty_Output,
                     Out_Last,
                     Zlib.Finish);
               end;
            end if;

            if Out_Last >= Output_Cursor then
               declare
                  Produced : constant Natural :=
                    Natural (Out_Last - Output_Cursor + 1);
               begin
                  if Produced > Natural'Last - Output_Total then
                     Zlib.Close (Filter, Ignore_Error => True);
                     Last := Inflated_Data'First - 1;
                     return Unsupported_Feature;
                  end if;

                  Output_Total := Output_Total + Produced;
                  if Output_Total > Expected_Uncompressed_Size then
                     Zlib.Close (Filter, Ignore_Error => True);
                     Last := Inflated_Data'First - 1;
                     return Invalid_Command;
                  end if;

                  Output_Cursor := Out_Last + 1;
                  Last := Out_Last;
               end;
            end if;
         end loop;
      end;

      Zlib.Close (Filter, Ignore_Error => True);

      if Output_Total /= Expected_Uncompressed_Size then
         Last := Inflated_Data'First - 1;
         return Invalid_Command;
      end if;

      return Ok;
   exception
      when Zlib.Zlib_Error | Zlib.Status_Error =>
         if Zlib.Is_Open (Filter) then
            Zlib.Close (Filter, Ignore_Error => True);
         end if;
         Last := Inflated_Data'First - 1;
         return Read_Failed;
      when Constraint_Error =>
         if Zlib.Is_Open (Filter) then
            Zlib.Close (Filter, Ignore_Error => True);
         end if;
         Last := Inflated_Data'First - 1;
         return Invalid_Command;
      when others =>
         if Zlib.Is_Open (Filter) then
            Zlib.Close (Filter, Ignore_Error => True);
         end if;
         Last := Inflated_Data'First - 1;
         return Internal_Error;
   end Inflate_Pack_Object_Data;

   function Inflate_Pack_Object_Data
     (Compressed_Data            : Stream_Element_Array;
      Expected_Uncompressed_Size : Natural;
      Inflated_Data              : out Stream_Element_Array;
      Last                       : out Stream_Element_Offset;
      Consumed_Length            : out Natural)
      return Status
   is
      Filter       : Zlib.Filter_Type;
      Input_Cursor : Stream_Element_Offset := Compressed_Data'First;
      Output_Total : Natural := 0;
      In_Last      : Stream_Element_Offset := Compressed_Data'First;
      Out_Last     : Stream_Element_Offset := Inflated_Data'First - 1;
      Output_Cursor : Stream_Element_Offset := Inflated_Data'First;
   begin
      Last := Inflated_Data'First - 1;
      Consumed_Length := 0;

      if Expected_Uncompressed_Size > Natural (Inflated_Data'Length) then
         return Read_Failed;
      elsif Compressed_Data'Length = 0 then
         return Read_Failed;
      end if;

      Zlib.Inflate_Init (Filter, Header => Zlib.Zlib_Header);

      while Input_Cursor <= Compressed_Data'Last loop
         if Output_Cursor <= Inflated_Data'Last then
            Zlib.Translate
              (Filter,
               Compressed_Data (Input_Cursor .. Compressed_Data'Last),
               In_Last,
               Inflated_Data (Output_Cursor .. Inflated_Data'Last),
               Out_Last,
               Zlib.No_Flush);
         else
            declare
               Empty_Output : Stream_Element_Array (1 .. 0);
            begin
               Zlib.Translate
                 (Filter,
                  Compressed_Data (Input_Cursor .. Compressed_Data'Last),
                  In_Last,
                  Empty_Output,
                  Out_Last,
                  Zlib.No_Flush);
            end;
         end if;

         if Out_Last >= Output_Cursor then
            declare
               Produced : constant Natural :=
                 Natural (Out_Last - Output_Cursor + 1);
            begin
               if Produced > Natural'Last - Output_Total then
                  Zlib.Close (Filter, Ignore_Error => True);
                  Last := Inflated_Data'First - 1;
                  Consumed_Length := 0;
                  return Unsupported_Feature;
               end if;

               Output_Total := Output_Total + Produced;
               if Output_Total > Expected_Uncompressed_Size then
                  Zlib.Close (Filter, Ignore_Error => True);
                  Last := Inflated_Data'First - 1;
                  Consumed_Length := 0;
                  return Invalid_Command;
               end if;

               Output_Cursor := Out_Last + 1;
               Last := Out_Last;
            end;
         end if;

         if Zlib.Stream_End (Filter) then
            Consumed_Length :=
              Natural (In_Last - Compressed_Data'First + 1);
            exit;
         elsif In_Last >= Input_Cursor then
            Input_Cursor := In_Last + 1;
         elsif Out_Last < Output_Cursor - 1 then
            Zlib.Close (Filter, Ignore_Error => True);
            Last := Inflated_Data'First - 1;
            Consumed_Length := 0;
            return Read_Failed;
         end if;
      end loop;

      if not Zlib.Stream_End (Filter) then
         declare
            Empty_Input : Stream_Element_Array (1 .. 0);
         begin
            while not Zlib.Stream_End (Filter) loop
               if Output_Cursor <= Inflated_Data'Last then
                  Zlib.Translate
                    (Filter,
                     Empty_Input,
                     In_Last,
                     Inflated_Data (Output_Cursor .. Inflated_Data'Last),
                     Out_Last,
                     Zlib.Finish);
               else
                  declare
                     Empty_Output : Stream_Element_Array (1 .. 0);
                  begin
                     Zlib.Translate
                       (Filter,
                        Empty_Input,
                        In_Last,
                        Empty_Output,
                        Out_Last,
                        Zlib.Finish);
                  end;
               end if;

               if Out_Last >= Output_Cursor then
                  declare
                     Produced : constant Natural :=
                       Natural (Out_Last - Output_Cursor + 1);
                  begin
                     if Produced > Natural'Last - Output_Total then
                        Zlib.Close (Filter, Ignore_Error => True);
                        Last := Inflated_Data'First - 1;
                        Consumed_Length := 0;
                        return Unsupported_Feature;
                     end if;

                     Output_Total := Output_Total + Produced;
                     if Output_Total > Expected_Uncompressed_Size then
                        Zlib.Close (Filter, Ignore_Error => True);
                        Last := Inflated_Data'First - 1;
                        Consumed_Length := 0;
                        return Invalid_Command;
                     end if;

                     Output_Cursor := Out_Last + 1;
                     Last := Out_Last;
                  end;
               end if;
            end loop;
         end;

         Consumed_Length := Natural (Compressed_Data'Length);
      end if;

      Zlib.Close (Filter, Ignore_Error => True);

      if Output_Total /= Expected_Uncompressed_Size
        or else Consumed_Length = 0
      then
         Last := Inflated_Data'First - 1;
         Consumed_Length := 0;
         return Invalid_Command;
      end if;

      return Ok;
   exception
      when Zlib.Zlib_Error | Zlib.Status_Error =>
         if Zlib.Is_Open (Filter) then
            Zlib.Close (Filter, Ignore_Error => True);
         end if;
         Last := Inflated_Data'First - 1;
         Consumed_Length := 0;
         return Read_Failed;
      when Constraint_Error =>
         if Zlib.Is_Open (Filter) then
            Zlib.Close (Filter, Ignore_Error => True);
         end if;
         Last := Inflated_Data'First - 1;
         Consumed_Length := 0;
         return Invalid_Command;
      when others =>
         if Zlib.Is_Open (Filter) then
            Zlib.Close (Filter, Ignore_Error => True);
         end if;
         Last := Inflated_Data'First - 1;
         Consumed_Length := 0;
         return Internal_Error;
   end Inflate_Pack_Object_Data;

   function Inflate_Pack_Object_At_Offset
     (Pack_Data         : Stream_Element_Array;
      Pack_Offset       : Natural;
      Kind              : out Pack_Object_Kind;
      Uncompressed_Size : out Natural;
      Header_Length     : out Natural;
      Payload_Offset    : out Natural;
      Inflated_Data     : out Stream_Element_Array;
      Last              : out Stream_Element_Offset)
      return Status
   is
      Next_Offset : Natural := 0;
   begin
      return
        Inflate_Pack_Object_At_Offset
          (Pack_Data,
           Pack_Offset,
           Kind,
           Uncompressed_Size,
           Header_Length,
           Payload_Offset,
           Inflated_Data,
           Last,
           Next_Offset);
   end Inflate_Pack_Object_At_Offset;

   function Inflate_Pack_Object_At_Offset
     (Pack_Data         : Stream_Element_Array;
      Pack_Offset       : Natural;
      Kind              : out Pack_Object_Kind;
      Uncompressed_Size : out Natural;
      Header_Length     : out Natural;
      Payload_Offset    : out Natural;
      Inflated_Data     : out Stream_Element_Array;
      Last              : out Stream_Element_Offset;
      Next_Offset       : out Natural)
      return Status
   is
      Pack_Version  : Natural := 0;
      Object_Count  : Natural := 0;
      Object_First  : Stream_Element_Offset;
      Payload_First : Stream_Element_Offset;
      Status_Value  : Status;
      Ignored_ID    :
        Stream_Element_Array
          (1 .. Stream_Element_Offset (Object_ID_SHA1_Raw_Length));
      Ignored_Last  : Stream_Element_Offset;
      Consumed      : Natural := 0;
      Compressed_Consumed : Natural := 0;
      Ignored_Offset : Natural := 0;
   begin
      Kind := Pack_Blob;
      Uncompressed_Size := 0;
      Header_Length := 0;
      Payload_Offset := 0;
      Next_Offset := 0;
      Last := Inflated_Data'First - 1;

      Status_Value := Parse_Pack_Header (Pack_Data, Pack_Version, Object_Count);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Pack_Offset < 12
        or else Pack_Offset >= Natural (Pack_Data'Length)
      then
         return Invalid_Command;
      end if;

      Object_First := Pack_Data'First + Stream_Element_Offset (Pack_Offset);
      Status_Value :=
        Parse_Pack_Object_Header
          (Pack_Data (Object_First .. Pack_Data'Last),
           Kind,
           Uncompressed_Size,
           Header_Length);
      if Status_Value /= Ok then
         Kind := Pack_Blob;
         Uncompressed_Size := 0;
         Header_Length := 0;
         return Status_Value;
      end if;

      Payload_First := Object_First + Stream_Element_Offset (Header_Length);
      if Payload_First > Pack_Data'Last then
         Kind := Pack_Blob;
         Uncompressed_Size := 0;
         Header_Length := 0;
         return Read_Failed;
      end if;

      case Kind is
         when Pack_REF_Delta =>
            Status_Value :=
              Parse_Pack_REF_Delta_Base
                (Pack_Data (Payload_First .. Pack_Data'Last),
                 Ignored_ID,
                 Ignored_Last,
                 Consumed);
            if Status_Value /= Ok then
               Kind := Pack_Blob;
               Uncompressed_Size := 0;
               Header_Length := 0;
               return Status_Value;
            end if;
            Payload_First := Payload_First + Stream_Element_Offset (Consumed);
         when Pack_OFS_Delta =>
            Status_Value :=
              Parse_Pack_OFS_Delta_Base
                (Pack_Data (Payload_First .. Pack_Data'Last),
                 Ignored_Offset,
                 Consumed);
            if Status_Value /= Ok then
               Kind := Pack_Blob;
               Uncompressed_Size := 0;
               Header_Length := 0;
               return Status_Value;
            end if;
            Payload_First := Payload_First + Stream_Element_Offset (Consumed);
         when others =>
            null;
      end case;

      if Payload_First > Pack_Data'Last then
         Kind := Pack_Blob;
         Uncompressed_Size := 0;
         Header_Length := 0;
         return Read_Failed;
      end if;

      Payload_Offset := Natural (Payload_First - Pack_Data'First);
      Status_Value :=
        Inflate_Pack_Object_Data
          (Pack_Data (Payload_First .. Pack_Data'Last),
           Uncompressed_Size,
           Inflated_Data,
           Last,
           Compressed_Consumed);
      if Status_Value /= Ok then
         Last := Inflated_Data'First - 1;
         return Status_Value;
      end if;

      if Payload_Offset > Natural'Last - Compressed_Consumed then
         Last := Inflated_Data'First - 1;
         return Unsupported_Feature;
      end if;

      Next_Offset := Payload_Offset + Compressed_Consumed;
      return Ok;
   exception
      when Constraint_Error =>
         Kind := Pack_Blob;
         Uncompressed_Size := 0;
         Header_Length := 0;
         Payload_Offset := 0;
         Next_Offset := 0;
         Last := Inflated_Data'First - 1;
         return Invalid_Command;
      when others =>
         Kind := Pack_Blob;
         Uncompressed_Size := 0;
         Header_Length := 0;
         Payload_Offset := 0;
         Next_Offset := 0;
         Last := Inflated_Data'First - 1;
         return Internal_Error;
   end Inflate_Pack_Object_At_Offset;

   function Validate_Pack_Object_Sequence
     (Pack_Data      : Stream_Element_Array;
      Scratch        : out Stream_Element_Array;
      Object_Count   : out Natural;
      Trailer_Offset : out Natural)
      return Status
   is
      Version_Value  : Natural := 0;
      Count_Value    : Natural := 0;
      Cursor         : Natural := 12;
      Trailer_Value  : Natural := 0;
      Status_Value   : Status;
      Kind_Value     : Pack_Object_Kind := Pack_Blob;
      Size_Value     : Natural := 0;
      Header_Length  : Natural := 0;
      Payload_Offset : Natural := 0;
      Last_Value     : Stream_Element_Offset;
      Next_Value     : Natural := 0;
   begin
      Object_Count := 0;
      Trailer_Offset := 0;

      if Pack_Data'Length
        < Stream_Element_Offset (12 + Object_ID_SHA1_Raw_Length)
      then
         return Read_Failed;
      end if;

      Status_Value := Parse_Pack_Header (Pack_Data, Version_Value, Count_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Trailer_Value :=
        Natural (Pack_Data'Length)
        - Object_ID_SHA1_Raw_Length;

      if Trailer_Value < 12 then
         return Read_Failed;
      end if;

      for Object_Number in 1 .. Count_Value loop
         if Cursor >= Trailer_Value then
            Object_Count := 0;
            Trailer_Offset := 0;
            return Invalid_Command;
         end if;

         Status_Value :=
           Inflate_Pack_Object_At_Offset
             (Pack_Data,
              Cursor,
              Kind_Value,
              Size_Value,
              Header_Length,
              Payload_Offset,
              Scratch,
              Last_Value,
              Next_Value);
         if Status_Value /= Ok then
            Object_Count := 0;
            Trailer_Offset := 0;
            return Status_Value;
         elsif Next_Value <= Cursor
           or else Next_Value > Trailer_Value
         then
            Object_Count := 0;
            Trailer_Offset := 0;
            return Invalid_Command;
         elsif Object_Number < Count_Value
           and then Next_Value = Trailer_Value
         then
            Object_Count := 0;
            Trailer_Offset := 0;
            return Invalid_Command;
         end if;

         Cursor := Next_Value;
      end loop;

      if Cursor /= Trailer_Value then
         Object_Count := 0;
         Trailer_Offset := 0;
         return Invalid_Command;
      end if;

      Object_Count := Count_Value;
      Trailer_Offset := Trailer_Value;
      return Ok;
   exception
      when Constraint_Error =>
         Object_Count := 0;
         Trailer_Offset := 0;
         return Invalid_Command;
      when others =>
         Object_Count := 0;
         Trailer_Offset := 0;
         return Internal_Error;
   end Validate_Pack_Object_Sequence;

   function Apply_Pack_Delta
     (Base_Data  : Stream_Element_Array;
      Delta_Data : Stream_Element_Array;
      Result     : out Stream_Element_Array;
      Last       : out Stream_Element_Offset)
      return Status
   is
      Cursor        : Stream_Element_Offset := Delta_Data'First;
      Source_Size   : Natural := 0;
      Target_Size   : Natural := 0;
      Output_Count  : Natural := 0;
      Output_Cursor : Stream_Element_Offset := Result'First;

      function Read_Delta_Size
        (Value : out Natural)
         return Status
      is
         Byte_Value : Stream_Element;
         Shift      : Natural := 0;
         Factor     : Natural := 1;
      begin
         Value := 0;

         loop
            if Cursor > Delta_Data'Last then
               return Read_Failed;
            end if;

            Byte_Value := Delta_Data (Cursor);
            declare
               Payload : constant Natural := Natural (Byte_Value mod 128);
            begin
               if Payload > 0 and then Factor > Natural'Last / Payload then
                  return Invalid_Command;
               elsif Value > Natural'Last - Payload * Factor then
                  return Invalid_Command;
               end if;

               Value := Value + Payload * Factor;
            end;

            Cursor := Cursor + 1;
            exit when Byte_Value < 128;

            Shift := Shift + 7;
            if Shift >= Natural'Size or else Factor > Natural'Last / 128 then
               return Invalid_Command;
            end if;

            Factor := Factor * 128;
         end loop;

         return Ok;
      exception
         when Constraint_Error =>
            Value := 0;
            return Invalid_Command;
         when others =>
            Value := 0;
            return Internal_Error;
      end Read_Delta_Size;

      function Add_Byte_To_Natural
        (Value      : Natural;
         Byte_Value : Stream_Element;
         Factor     : Natural)
         return Natural
      is
         Byte_Natural : constant Natural := Natural (Byte_Value);
      begin
         if Byte_Natural > 0 and then Factor > Natural'Last / Byte_Natural
         then
            raise Constraint_Error;
         elsif Value > Natural'Last - Byte_Natural * Factor then
            raise Constraint_Error;
         end if;

         return Value + Byte_Natural * Factor;
      end Add_Byte_To_Natural;

      function Read_Copy_Byte
        (Offset : Natural)
         return Stream_Element
      is
         pragma Unreferenced (Offset);
      begin
         if Cursor > Delta_Data'Last then
            raise Constraint_Error;
         end if;

         declare
            Value : constant Stream_Element :=
              Delta_Data (Cursor);
         begin
            Cursor := Cursor + 1;
            return Value;
         end;
      end Read_Copy_Byte;
   begin
      Last := Result'First - 1;

      declare
         Status_Value : Status := Read_Delta_Size (Source_Size);
      begin
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         Status_Value := Read_Delta_Size (Target_Size);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end;

      if Source_Size /= Natural (Base_Data'Length) then
         return Invalid_Command;
      elsif Target_Size > Natural (Result'Length) then
         return Read_Failed;
      end if;

      while Cursor <= Delta_Data'Last loop
         declare
            Opcode : constant Stream_Element := Delta_Data (Cursor);
         begin
            Cursor := Cursor + 1;

            if Opcode >= 128 then
               declare
                  Copy_Offset : Natural := 0;
                  Copy_Size   : Natural := 0;
               begin
                  if (Opcode and 16#01#) /= 0 then
                     Copy_Offset :=
                       Add_Byte_To_Natural
                         (Copy_Offset, Read_Copy_Byte (0), 1);
                  end if;
                  if (Opcode and 16#02#) /= 0 then
                     Copy_Offset :=
                       Add_Byte_To_Natural
                         (Copy_Offset, Read_Copy_Byte (1), 256);
                  end if;
                  if (Opcode and 16#04#) /= 0 then
                     Copy_Offset :=
                       Add_Byte_To_Natural
                         (Copy_Offset, Read_Copy_Byte (2), 65_536);
                  end if;
                  if (Opcode and 16#08#) /= 0 then
                     Copy_Offset :=
                       Add_Byte_To_Natural
                         (Copy_Offset, Read_Copy_Byte (3), 16_777_216);
                  end if;

                  if (Opcode and 16#10#) /= 0 then
                     Copy_Size :=
                       Add_Byte_To_Natural
                         (Copy_Size, Read_Copy_Byte (4), 1);
                  end if;
                  if (Opcode and 16#20#) /= 0 then
                     Copy_Size :=
                       Add_Byte_To_Natural
                         (Copy_Size, Read_Copy_Byte (5), 256);
                  end if;
                  if (Opcode and 16#40#) /= 0 then
                     Copy_Size :=
                       Add_Byte_To_Natural
                         (Copy_Size, Read_Copy_Byte (6), 65_536);
                  end if;

                  if Copy_Size = 0 then
                     Copy_Size := 65_536;
                  end if;

                  if Copy_Offset > Natural (Base_Data'Length)
                    or else Copy_Size > Natural (Base_Data'Length)
                    or else Copy_Offset
                      > Natural (Base_Data'Length) - Copy_Size
                    or else Copy_Size > Target_Size - Output_Count
                  then
                     Last := Result'First - 1;
                     return Invalid_Command;
                  end if;

                  for Offset in 0 .. Copy_Size - 1 loop
                     Result (Output_Cursor + Stream_Element_Offset (Offset)) :=
                       Base_Data
                         (Base_Data'First
                          + Stream_Element_Offset (Copy_Offset + Offset));
                  end loop;

                  Output_Cursor :=
                    Output_Cursor + Stream_Element_Offset (Copy_Size);
                  Output_Count := Output_Count + Copy_Size;
                  Last := Output_Cursor - 1;
               end;
            elsif Opcode = 0 then
               Last := Result'First - 1;
               return Invalid_Command;
            else
               declare
                  Insert_Size : constant Natural := Natural (Opcode);
               begin
                  if Insert_Size > Natural (Delta_Data'Last - Cursor + 1)
                    or else Insert_Size > Target_Size - Output_Count
                  then
                     Last := Result'First - 1;
                     return Read_Failed;
                  end if;

                  for Offset in 0 .. Insert_Size - 1 loop
                     Result (Output_Cursor + Stream_Element_Offset (Offset)) :=
                       Delta_Data (Cursor + Stream_Element_Offset (Offset));
                  end loop;

                  Cursor := Cursor + Stream_Element_Offset (Insert_Size);
                  Output_Cursor :=
                    Output_Cursor + Stream_Element_Offset (Insert_Size);
                  Output_Count := Output_Count + Insert_Size;
                  Last := Output_Cursor - 1;
               end;
            end if;
         end;
      end loop;

      if Output_Count /= Target_Size then
         Last := Result'First - 1;
         return Invalid_Command;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Last := Result'First - 1;
         return Invalid_Command;
      when others =>
         Last := Result'First - 1;
         return Internal_Error;
   end Apply_Pack_Delta;

   function Apply_Pack_Delta_Chain
     (Base_Data  : Stream_Element_Array;
      Delta_Data : Stream_Element_Array;
      Deltas     : Pack_Delta_Span_Array;
      Workspace  : out Stream_Element_Array;
      Result     : out Stream_Element_Array;
      Last       : out Stream_Element_Offset)
      return Status
   is
      Current_In_Result : Boolean := True;
      Current_Last      : Stream_Element_Offset := Result'First - 1;
      Workspace_Last    : Stream_Element_Offset := Workspace'First - 1;
      Status_Value      : Status;

      function Copy_To_Result
        (Source : Stream_Element_Array)
         return Status
      is
      begin
         Last := Result'First - 1;
         if Source'Length > Result'Length then
            return Read_Failed;
         end if;

         if Source'Length = 0 then
            return Ok;
         end if;

         for Offset in 0 .. Natural (Source'Length) - 1 loop
            Result (Result'First + Stream_Element_Offset (Offset)) :=
              Source (Source'First + Stream_Element_Offset (Offset));
         end loop;
         Last := Result'First + Source'Length - 1;
         return Ok;
      exception
         when Constraint_Error =>
            Last := Result'First - 1;
            return Read_Failed;
         when others =>
            Last := Result'First - 1;
            return Internal_Error;
      end Copy_To_Result;
   begin
      Last := Result'First - 1;

      if Deltas'Length > Maximum_Pack_Delta_Chain_Length then
         return Unsupported_Feature;
      elsif Deltas'Length = 0 then
         return Copy_To_Result (Base_Data);
      end if;

      for Delta_Index in Deltas'Range loop
         declare
            Span : constant Pack_Delta_Span := Deltas (Delta_Index);
         begin
            if Span.First < Delta_Data'First
              or else Span.Last > Delta_Data'Last
              or else Span.First > Span.Last
            then
               Last := Result'First - 1;
               return Read_Failed;
            end if;

            if Delta_Index = Deltas'First then
               Status_Value :=
                 Apply_Pack_Delta
                   (Base_Data,
                    Delta_Data (Span.First .. Span.Last),
                    Result,
                    Current_Last);
               Current_In_Result := True;
            elsif Current_In_Result then
               Status_Value :=
                 Apply_Pack_Delta
                   (Result (Result'First .. Current_Last),
                    Delta_Data (Span.First .. Span.Last),
                    Workspace,
                    Workspace_Last);
               Current_In_Result := False;
            else
               Status_Value :=
                 Apply_Pack_Delta
                   (Workspace (Workspace'First .. Workspace_Last),
                    Delta_Data (Span.First .. Span.Last),
                    Result,
                    Current_Last);
               Current_In_Result := True;
            end if;

            if Status_Value /= Ok then
               Last := Result'First - 1;
               return Status_Value;
            end if;
         end;
      end loop;

      if Current_In_Result then
         Last := Current_Last;
         return Ok;
      else
         return Copy_To_Result (Workspace (Workspace'First .. Workspace_Last));
      end if;
   exception
      when Constraint_Error =>
         Last := Result'First - 1;
         return Invalid_Command;
      when others =>
         Last := Result'First - 1;
         return Internal_Error;
   end Apply_Pack_Delta_Chain;

   function Parse_Pack_REF_Delta_Base
     (Data            : Stream_Element_Array;
      Base_Object_ID  : out Stream_Element_Array;
      Base_Last       : out Stream_Element_Offset;
      Consumed_Length : out Natural)
      return Status
   is
   begin
      Base_Last := Base_Object_ID'First - 1;
      Consumed_Length := 0;

      if Data'Length < Stream_Element_Offset (Object_ID_SHA1_Raw_Length) then
         return Read_Failed;
      elsif Base_Object_ID'Length
        < Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
      then
         return Read_Failed;
      end if;

      for Offset in 0 .. Object_ID_SHA1_Raw_Length - 1 loop
         Base_Object_ID
           (Base_Object_ID'First + Stream_Element_Offset (Offset)) :=
             Data (Data'First + Stream_Element_Offset (Offset));
      end loop;

      Base_Last :=
        Base_Object_ID'First
        + Stream_Element_Offset (Object_ID_SHA1_Raw_Length)
        - 1;
      Consumed_Length := Object_ID_SHA1_Raw_Length;
      return Ok;
   exception
      when Constraint_Error =>
         Base_Last := Base_Object_ID'First - 1;
         Consumed_Length := 0;
         return Read_Failed;
      when others =>
         Base_Last := Base_Object_ID'First - 1;
         Consumed_Length := 0;
         return Internal_Error;
   end Parse_Pack_REF_Delta_Base;

   function Parse_Pack_OFS_Delta_Base
     (Data            : Stream_Element_Array;
      Negative_Offset : out Natural;
      Consumed_Length : out Natural)
      return Status
   is
      Byte_Value : Stream_Element;
      Value      : Natural := 0;
   begin
      Negative_Offset := 0;
      Consumed_Length := 0;

      if Data'Length = 0 then
         return Read_Failed;
      end if;

      for Index in Data'Range loop
         Byte_Value := Data (Index);

         if Consumed_Length = 0 then
            Value := Natural (Byte_Value mod 128);
         else
            if Value > (Natural'Last - 1) / 128 then
               return Invalid_Command;
            end if;
            Value := (Value + 1) * 128;
            if Value > Natural'Last - Natural (Byte_Value mod 128) then
               return Invalid_Command;
            end if;
            Value := Value + Natural (Byte_Value mod 128);
         end if;

         Consumed_Length := Consumed_Length + 1;
         if Byte_Value < 128 then
            Negative_Offset := Value;
            return Ok;
         end if;
      end loop;

      Negative_Offset := 0;
      Consumed_Length := 0;
      return Read_Failed;
   exception
      when Constraint_Error =>
         Negative_Offset := 0;
         Consumed_Length := 0;
         return Read_Failed;
      when others =>
         Negative_Offset := 0;
         Consumed_Length := 0;
         return Internal_Error;
   end Parse_Pack_OFS_Delta_Base;

   function Valid_Object_ID (Text : String) return Boolean is
   begin
      if Text'Length /= Object_ID_SHA1_Hex_Length then
         return False;
      end if;

      for Ch of Text loop
         if not Hex_Character (Ch) then
            return False;
         end if;
      end loop;
      return True;
   exception
      when others =>
         return False;
   end Valid_Object_ID;

   function Valid_Ref_Name (Name : String) return Boolean is
      Component_Start : Natural := Name'First;
      Previous        : Character := Character'Val (0);
   begin
      if Name = "HEAD" then
         return True;
      elsif Name'Length = 0
        or else Name'Length > Maximum_Ref_Name_Length
        or else Name (Name'First) = '/'
        or else Name (Name'Last) = '/'
        or else Name (Name'Last) = '.'
        or else Name = "@"
      then
         return False;
      end if;

      for Index in Name'Range loop
         declare
            Ch : constant Character := Name (Index);
         begin
            if Ch <= ' '
              or else Ch = Character'Val (127)
              or else Ch = '~'
              or else Ch = '^'
              or else Ch = ':'
              or else Ch = '?'
              or else Ch = '*'
              or else Ch = '['
              or else Ch = '\'
            then
               return False;
            elsif Ch = '/' then
               if not Safe_Ref_Component (Name (Component_Start .. Index - 1)) then
                  return False;
               end if;
               Component_Start := Index + 1;
            elsif Ch = '.' and then Previous = '.' then
               return False;
            elsif Ch = '{' and then Previous = '@' then
               return False;
            end if;
            Previous := Ch;
         end;
      end loop;

      return Safe_Ref_Component (Name (Component_Start .. Name'Last));
   exception
      when others =>
         return False;
   end Valid_Ref_Name;

   function Valid_Fetch_Refspec (RefSpec : String) return Boolean is
      function Valid_Refspec_Part
        (Text           : String;
         Wildcard_Count : out Natural)
         return Boolean
      is
         Component_Start : Natural := Text'First;
         Previous        : Character := Character'Val (0);
      begin
         Wildcard_Count := 0;
         if Text'Length = 0
           or else Text'Length > Maximum_Ref_Name_Length
           or else Text (Text'First) = '/'
           or else Text (Text'Last) = '/'
           or else Text (Text'Last) = '.'
           or else Text = "@"
         then
            return False;
         end if;

         for Index in Text'Range loop
            declare
               Ch : constant Character := Text (Index);
            begin
               if Ch <= ' '
                 or else Ch = Character'Val (127)
                 or else Ch = '~'
                 or else Ch = '^'
                 or else Ch = ':'
                 or else Ch = '?'
                 or else Ch = '['
                 or else Ch = '\'
               then
                  return False;
               elsif Ch = '*' then
                  Wildcard_Count := Wildcard_Count + 1;
                  if Wildcard_Count > 1 then
                     return False;
                  end if;
               elsif Ch = '/' then
                  if not Safe_Ref_Component
                    (Text (Component_Start .. Index - 1))
                  then
                     return False;
                  end if;
                  Component_Start := Index + 1;
               elsif Ch = '.' and then Previous = '.' then
                  return False;
               elsif Ch = '{' and then Previous = '@' then
                  return False;
               end if;
               Previous := Ch;
            end;
         end loop;

         return Safe_Ref_Component (Text (Component_Start .. Text'Last));
      exception
         when others =>
            Wildcard_Count := 0;
            return False;
      end Valid_Refspec_Part;

      Start : Natural := RefSpec'First;
      Colon : Natural := 0;
      Source_Wildcards : Natural := 0;
      Target_Wildcards : Natural := 0;
   begin
      if RefSpec'Length = 0
        or else RefSpec'Length > Maximum_Ref_Name_Length * 2 + 2
      then
         return False;
      end if;

      if RefSpec (Start) = '+' then
         Start := Start + 1;
         if Start > RefSpec'Last then
            return False;
         end if;
      end if;

      for Index in Start .. RefSpec'Last loop
         if RefSpec (Index) = ':' then
            if Colon /= 0 then
               return False;
            end if;
            Colon := Index;
         end if;
      end loop;

      if Colon = 0 or else Colon = Start or else Colon = RefSpec'Last then
         return False;
      end if;

      if not Valid_Refspec_Part
        (RefSpec (Start .. Colon - 1), Source_Wildcards)
        or else not Valid_Refspec_Part
          (RefSpec (Colon + 1 .. RefSpec'Last), Target_Wildcards)
      then
         return False;
      end if;

      return Source_Wildcards = Target_Wildcards;
   exception
      when others =>
         return False;
   end Valid_Fetch_Refspec;

   function Valid_Push_Refspec (RefSpec : String) return Boolean is
      function Valid_Refspec_Part
        (Text           : String;
         Wildcard_Count : out Natural)
         return Boolean
      is
         Component_Start : Natural := Text'First;
         Previous        : Character := Character'Val (0);
      begin
         Wildcard_Count := 0;
         if Text'Length = 0
           or else Text'Length > Maximum_Ref_Name_Length
           or else Text (Text'First) = '/'
           or else Text (Text'Last) = '/'
           or else Text (Text'Last) = '.'
           or else Text = "@"
         then
            return False;
         end if;

         for Index in Text'Range loop
            declare
               Ch : constant Character := Text (Index);
            begin
               if Ch <= ' '
                 or else Ch = Character'Val (127)
                 or else Ch = '~'
                 or else Ch = '^'
                 or else Ch = ':'
                 or else Ch = '?'
                 or else Ch = '['
                 or else Ch = '\'
               then
                  return False;
               elsif Ch = '*' then
                  Wildcard_Count := Wildcard_Count + 1;
                  if Wildcard_Count > 1 then
                     return False;
                  end if;
               elsif Ch = '/' then
                  if not Safe_Ref_Component
                    (Text (Component_Start .. Index - 1))
                  then
                     return False;
                  end if;
                  Component_Start := Index + 1;
               elsif Ch = '.' and then Previous = '.' then
                  return False;
               elsif Ch = '{' and then Previous = '@' then
                  return False;
               end if;
               Previous := Ch;
            end;
         end loop;

         return Safe_Ref_Component (Text (Component_Start .. Text'Last));
      exception
         when others =>
            Wildcard_Count := 0;
            return False;
      end Valid_Refspec_Part;

      Start : Natural := RefSpec'First;
      Colon : Natural := 0;
      Source_Wildcards : Natural := 0;
      Target_Wildcards : Natural := 0;
   begin
      if RefSpec'Length = 0
        or else RefSpec'Length > Maximum_Ref_Name_Length * 2 + 2
      then
         return False;
      end if;

      if RefSpec (Start) = '+' then
         Start := Start + 1;
         if Start > RefSpec'Last then
            return False;
         end if;
      end if;

      for Index in Start .. RefSpec'Last loop
         if RefSpec (Index) = ':' then
            if Colon /= 0 then
               return False;
            end if;
            Colon := Index;
         end if;
      end loop;

      if Colon = 0 then
         return Valid_Refspec_Part
           (RefSpec (Start .. RefSpec'Last), Source_Wildcards)
           and then Source_Wildcards = 0;
      elsif Colon = RefSpec'Last then
         return False;
      elsif Colon = Start then
         return Valid_Refspec_Part
           (RefSpec (Colon + 1 .. RefSpec'Last), Target_Wildcards)
           and then Target_Wildcards = 0;
      end if;

      if not Valid_Refspec_Part
        (RefSpec (Start .. Colon - 1), Source_Wildcards)
        or else not Valid_Refspec_Part
          (RefSpec (Colon + 1 .. RefSpec'Last), Target_Wildcards)
      then
         return False;
      end if;

      return Source_Wildcards = Target_Wildcards;
   exception
      when others =>
         return False;
   end Valid_Push_Refspec;

   function Valid_Push_Default_Mode (Mode : String) return Boolean is
   begin
      return Mode = "nothing"
        or else Mode = "current"
        or else Mode = "upstream"
        or else Mode = "simple"
        or else Mode = "matching";
   exception
      when others =>
         return False;
   end Valid_Push_Default_Mode;

   function Valid_Pull_Rebase_Mode (Mode : String) return Boolean is
   begin
      return Mode = "true"
        or else Mode = "false"
        or else Mode = "merges"
        or else Mode = "interactive";
   exception
      when others =>
         return False;
   end Valid_Pull_Rebase_Mode;

   function Classify_Ref_Name
     (Name : String;
      Kind : out Ref_Name_Kind)
      return Status
   is
   begin
      Kind := Ref_Other;
      if not Valid_Ref_Name (Name) then
         return Invalid_Command;
      elsif Name = "HEAD" then
         Kind := Ref_HEAD;
      elsif Name'Length > 11
        and then Name (Name'First .. Name'First + 10) = "refs/heads/"
      then
         Kind := Ref_Branch;
      elsif Name'Length > 10
        and then Name (Name'First .. Name'First + 9) = "refs/tags/"
      then
         Kind := Ref_Tag;
      elsif Name'Length > 13
        and then Name (Name'First .. Name'First + 12) = "refs/remotes/"
      then
         Kind := Ref_Remote;
      else
         Kind := Ref_Other;
      end if;
      return Ok;
   exception
      when others =>
         Kind := Ref_Other;
         return Internal_Error;
   end Classify_Ref_Name;

   function Parse_Side_Band_Packet
     (Data    : Stream_Element_Array;
      Kind    : out Side_Band_Kind;
      Payload : out Stream_Element_Array;
      Last    : out Stream_Element_Offset)
      return Status
   is
      Pkt_Kind      : Pkt_Line_Kind;
      Packet_Length : Natural := 0;
      Status_Value  : Status;
      Payload_Length : Natural := 0;
   begin
      Kind := Side_Band_Data;
      Last := Payload'First - 1;

      Status_Value := Parse_Pkt_Line_Header (Data, Pkt_Kind, Packet_Length);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Pkt_Kind /= Pkt_Data or else Packet_Length < 5 then
         return Invalid_Command;
      end if;

      case Natural (Data (Data'First + 4)) is
         when 1 =>
            Kind := Side_Band_Data;
         when 2 =>
            Kind := Side_Band_Progress;
         when 3 =>
            Kind := Side_Band_Error;
         when others =>
            return Invalid_Command;
      end case;

      Payload_Length := Packet_Length - 5;
      if Payload_Length = 0 then
         return Ok;
      elsif Payload'Length < Stream_Element_Offset (Payload_Length) then
         return Read_Failed;
      end if;

      for Offset in 0 .. Payload_Length - 1 loop
         Payload (Payload'First + Stream_Element_Offset (Offset)) :=
           Data (Data'First + 5 + Stream_Element_Offset (Offset));
      end loop;
      Last := Payload'First + Stream_Element_Offset (Payload_Length) - 1;
      return Ok;
   exception
      when Constraint_Error =>
         Kind := Side_Band_Data;
         Last := Payload'First - 1;
         return Read_Failed;
      when others =>
         Kind := Side_Band_Data;
         Last := Payload'First - 1;
         return Internal_Error;
   end Parse_Side_Band_Packet;

   function Validate_Side_Band_Stream
     (Data    : Stream_Element_Array;
      Summary : out Side_Band_Stream_Summary)
      return Status
   is
      Cursor        : Pkt_Line_Cursor;
      Pkt_Kind      : Pkt_Line_Kind := Pkt_Data;
      Side_Kind     : Side_Band_Kind := Side_Band_Data;
      Packet_First  : Stream_Element_Offset;
      Packet_Last   : Stream_Element_Offset;
      Payload_First : Stream_Element_Offset;
      Payload_Last  : Stream_Element_Offset;
      Side_Buffer   : Stream_Element_Array
        (Stream_Element_Offset'(1)
         .. Stream_Element_Offset (Maximum_Pkt_Line_Payload_Length));
      Side_Last     : Stream_Element_Offset;
      Version       : Natural := 0;
      Count         : Natural := 0;
      Status_Value  : Status;
   begin
      Summary := (others => <>);
      if Data'Length = 0 then
         return Invalid_Command;
      end if;

      Reset_Pkt_Line_Cursor (Data, Cursor);
      loop
         Status_Value :=
           Next_Pkt_Line
             (Data,
              Cursor,
              Pkt_Kind,
              Packet_First,
              Packet_Last,
              Payload_First,
              Payload_Last);
         exit when Status_Value = End_Of_Stream;
         if Status_Value /= Ok then
            Summary := (others => <>);
            return Status_Value;
         end if;

         case Pkt_Kind is
            when Pkt_Data =>
               Status_Value :=
                 Parse_Side_Band_Packet
                   (Data (Packet_First .. Packet_Last),
                    Side_Kind,
                    Side_Buffer,
                    Side_Last);
               if Status_Value /= Ok then
                  Summary := (others => <>);
                  return Status_Value;
               end if;

               case Side_Kind is
                  when Side_Band_Data =>
                     Summary.Data_Count := Summary.Data_Count + 1;
                     if Side_Last >= Side_Buffer'First then
                        Status_Value :=
                          Parse_Pack_Header
                            (Side_Buffer (Side_Buffer'First .. Side_Last),
                             Version,
                             Count);
                        if Status_Value = Ok then
                           Summary.Has_Pack_Data := True;
                           Summary.Pack_Object_Count := Count;
                        end if;
                     end if;
                  when Side_Band_Progress =>
                     Summary.Progress_Count := Summary.Progress_Count + 1;
                  when Side_Band_Error =>
                     Summary.Error_Count := Summary.Error_Count + 1;
               end case;
            when Pkt_Flush =>
               Summary.Has_Flush := True;
               if not Pkt_Line_Cursor_Done (Cursor) then
                  Summary := (others => <>);
                  return Invalid_Command;
               end if;
            when Pkt_Delimiter | Pkt_Response_End =>
               Summary := (others => <>);
               return Invalid_Command;
         end case;
      end loop;

      if Summary.Data_Count = 0
        and then Summary.Progress_Count = 0
        and then Summary.Error_Count = 0
      then
         Summary := (others => <>);
         return Invalid_Command;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Summary := (others => <>);
         return Read_Failed;
      when others =>
         Summary := (others => <>);
         return Internal_Error;
   end Validate_Side_Band_Stream;

   function Parse_Status_Report_Packet
     (Data         : Stream_Element_Array;
      Kind         : out Status_Report_Kind;
      Ref_Name     : out Stream_Element_Array;
      Ref_Last     : out Stream_Element_Offset;
      Message      : out Stream_Element_Array;
      Message_Last : out Stream_Element_Offset)
      return Status
   is
      Pkt_Kind      : Pkt_Line_Kind;
      Packet_Length : Natural := 0;
      Status_Value  : Status;
      Line_First    : Stream_Element_Offset;
      Line_Last     : Stream_Element_Offset;
      Content_Last  : Stream_Element_Offset;

      function Matches
        (First : Stream_Element_Offset;
         Text  : String)
         return Boolean
      is
      begin
         if First + Stream_Element_Offset (Text'Length) - 1 > Content_Last then
            return False;
         end if;

         for Offset in 0 .. Text'Length - 1 loop
            if Data (First + Stream_Element_Offset (Offset))
              /= Character'Pos (Text (Text'First + Offset))
            then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Matches;

      function Copy_Range
        (First  : Stream_Element_Offset;
         Last   : Stream_Element_Offset;
         Target : out Stream_Element_Array;
         Final  : out Stream_Element_Offset)
         return Status
      is
         Length : Natural := 0;
      begin
         Final := Target'First - 1;
         if Last < First then
            return Ok;
         end if;

         Length := Natural (Last - First + 1);
         if Target'Length < Stream_Element_Offset (Length) then
            return Read_Failed;
         end if;

         for Offset in 0 .. Length - 1 loop
            Target (Target'First + Stream_Element_Offset (Offset)) :=
              Data (First + Stream_Element_Offset (Offset));
         end loop;
         Final := Target'First + Stream_Element_Offset (Length) - 1;
         return Ok;
      exception
         when Constraint_Error =>
            Final := Target'First - 1;
            return Read_Failed;
         when others =>
            Final := Target'First - 1;
            return Internal_Error;
      end Copy_Range;

      function Ref_Range_Valid
        (First : Stream_Element_Offset;
         Last  : Stream_Element_Offset)
         return Boolean
      is
         Length : Natural := 0;
      begin
         if Last < First then
            return False;
         end if;

         Length := Natural (Last - First + 1);
         if Length > Maximum_Ref_Name_Length then
            return False;
         end if;

         declare
            Text : String (1 .. Length);
         begin
            for Offset in 0 .. Length - 1 loop
               Text (Text'First + Offset) :=
                 Character'Val
                   (Data (First + Stream_Element_Offset (Offset)));
            end loop;
            return Valid_Ref_Name (Text);
         end;
      exception
         when others =>
            return False;
      end Ref_Range_Valid;

      function Find_Space
        (First : Stream_Element_Offset;
         Last  : Stream_Element_Offset)
         return Stream_Element_Offset
      is
      begin
         for Index in First .. Last loop
            if Data (Index) = Character'Pos (' ') then
               return Index;
            end if;
         end loop;
         return Last + 1;
      exception
         when others =>
            return Last + 1;
      end Find_Space;
   begin
      Kind := Status_Unpack_Error;
      Ref_Last := Ref_Name'First - 1;
      Message_Last := Message'First - 1;

      Status_Value := Parse_Pkt_Line_Header (Data, Pkt_Kind, Packet_Length);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Pkt_Kind /= Pkt_Data or else Packet_Length < 5 then
         return Invalid_Command;
      end if;

      Line_First := Data'First + 4;
      Line_Last := Data'First + Stream_Element_Offset (Packet_Length) - 1;
      if Data (Line_Last) /= Character'Pos (Character'Val (10)) then
         return Invalid_Command;
      end if;
      Content_Last := Line_Last - 1;

      if Matches (Line_First, "unpack ok")
        and then Content_Last = Line_First + 8
      then
         Kind := Status_Unpack_Ok;
         return Ok;
      elsif Matches (Line_First, "unpack ")
        and then Content_Last >= Line_First + 7
      then
         Kind := Status_Unpack_Error;
         return Copy_Range
           (Line_First + 7, Content_Last, Message, Message_Last);
      elsif Matches (Line_First, "ok ")
        and then Content_Last >= Line_First + 3
      then
         if not Ref_Range_Valid (Line_First + 3, Content_Last) then
            return Invalid_Command;
         end if;
         Kind := Status_Ref_Ok;
         return Copy_Range
           (Line_First + 3, Content_Last, Ref_Name, Ref_Last);
      elsif Matches (Line_First, "ng ")
        and then Content_Last >= Line_First + 5
      then
         declare
            Separator : constant Stream_Element_Offset :=
              Find_Space (Line_First + 3, Content_Last);
         begin
            if Separator > Content_Last
              or else Separator = Line_First + 3
              or else Separator = Content_Last
              or else not Ref_Range_Valid (Line_First + 3, Separator - 1)
            then
               return Invalid_Command;
            end if;

            Kind := Status_Ref_Error;
            Status_Value :=
              Copy_Range (Line_First + 3, Separator - 1, Ref_Name, Ref_Last);
            if Status_Value /= Ok then
               return Status_Value;
            end if;

            return Copy_Range
              (Separator + 1, Content_Last, Message, Message_Last);
         end;
      end if;

      return Invalid_Command;
   exception
      when Constraint_Error =>
         Kind := Status_Unpack_Error;
         Ref_Last := Ref_Name'First - 1;
         Message_Last := Message'First - 1;
         return Read_Failed;
      when others =>
         Kind := Status_Unpack_Error;
         Ref_Last := Ref_Name'First - 1;
         Message_Last := Message'First - 1;
         return Internal_Error;
   end Parse_Status_Report_Packet;

   function Parse_Capability_Token
     (Token      : Stream_Element_Array;
      Name       : out Stream_Element_Array;
      Name_Last  : out Stream_Element_Offset;
      Value      : out Stream_Element_Array;
      Value_Last : out Stream_Element_Offset;
      Has_Value  : out Boolean)
      return Status
   is
      Separator : Stream_Element_Offset := Token'Last + 1;
      Name_Length : Natural := 0;
      Value_Length : Natural := 0;

      function Safe_Capability_Byte
        (Item       : Stream_Element;
         In_Value   : Boolean)
         return Boolean
      is
      begin
         if Item <= Character'Pos (' ')
           or else Item = Character'Pos (Character'Val (127))
         then
            return False;
         elsif not In_Value and then Item = Character'Pos ('=') then
            return True;
         else
            return Item /= Character'Pos (Character'Val (0));
         end if;
      exception
         when others =>
            return False;
      end Safe_Capability_Byte;
   begin
      Name_Last := Name'First - 1;
      Value_Last := Value'First - 1;
      Has_Value := False;

      if Token'Length = 0
        or else Token'Length > Stream_Element_Offset (Maximum_Capability_Token_Length)
      then
         return Invalid_Command;
      end if;

      for Index in Token'Range loop
         if not Safe_Capability_Byte (Token (Index), Index > Separator) then
            return Invalid_Command;
         elsif Token (Index) = Character'Pos ('=') then
            if Has_Value then
               return Invalid_Command;
            end if;
            Has_Value := True;
            Separator := Index;
         end if;
      end loop;

      if Has_Value then
         if Separator = Token'First or else Separator = Token'Last then
            return Invalid_Command;
         end if;
         Name_Length := Natural (Separator - Token'First);
         Value_Length := Natural (Token'Last - Separator);
      else
         Name_Length := Natural (Token'Length);
      end if;

      if Name'Length < Stream_Element_Offset (Name_Length)
        or else Value'Length < Stream_Element_Offset (Value_Length)
      then
         return Read_Failed;
      end if;

      for Offset in 0 .. Name_Length - 1 loop
         Name (Name'First + Stream_Element_Offset (Offset)) :=
           Token (Token'First + Stream_Element_Offset (Offset));
      end loop;
      Name_Last := Name'First + Stream_Element_Offset (Name_Length) - 1;

      if Has_Value then
         for Offset in 0 .. Value_Length - 1 loop
            Value (Value'First + Stream_Element_Offset (Offset)) :=
              Token (Separator + 1 + Stream_Element_Offset (Offset));
         end loop;
         Value_Last := Value'First + Stream_Element_Offset (Value_Length) - 1;
      end if;

      return Ok;
   exception
      when Constraint_Error =>
         Name_Last := Name'First - 1;
         Value_Last := Value'First - 1;
         Has_Value := False;
         return Read_Failed;
      when others =>
         Name_Last := Name'First - 1;
         Value_Last := Value'First - 1;
         Has_Value := False;
         return Internal_Error;
   end Parse_Capability_Token;

   function Copy_Next_Capability_Token
     (List      : Stream_Element_Array;
      Cursor    : in out Stream_Element_Offset;
      Token     : out Stream_Element_Array;
      Last      : out Stream_Element_Offset;
      Has_Token : out Boolean)
      return Status
   is
      Token_First : Stream_Element_Offset;
      Token_Last  : Stream_Element_Offset;
      Token_Length : Natural := 0;
      Name_Buffer : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Capability_Token_Length));
      Value_Buffer : Stream_Element_Array
        (1 .. Stream_Element_Offset (Maximum_Capability_Token_Length));
      Ignored_Name_Last : Stream_Element_Offset;
      Ignored_Value_Last : Stream_Element_Offset;
      Ignored_Has_Value : Boolean := False;
      Status_Value : Status;
   begin
      Last := Token'First - 1;
      Has_Token := False;

      if List'Length = 0 then
         return Ok;
      elsif Cursor < List'First or else Cursor > List'Last + 1 then
         return Invalid_Command;
      elsif Cursor = List'Last + 1 then
         return Ok;
      elsif List (Cursor) = Character'Pos (' ') then
         return Invalid_Command;
      end if;

      Token_First := Cursor;
      Token_Last := List'Last;
      for Index in Cursor .. List'Last loop
         if List (Index) = Character'Pos (' ') then
            Token_Last := Index - 1;
            Cursor := Index + 1;
            exit;
         elsif Index = List'Last then
            Cursor := List'Last + 1;
         end if;
      end loop;

      Token_Length := Natural (Token_Last - Token_First + 1);
      if Token_Length = 0
        or else Token_Length > Maximum_Capability_Token_Length
      then
         return Invalid_Command;
      elsif Token'Length < Stream_Element_Offset (Token_Length) then
         return Read_Failed;
      end if;

      Status_Value :=
        Parse_Capability_Token
          (List (Token_First .. Token_Last),
           Name_Buffer, Ignored_Name_Last,
           Value_Buffer, Ignored_Value_Last,
           Ignored_Has_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      for Offset in 0 .. Token_Length - 1 loop
         Token (Token'First + Stream_Element_Offset (Offset)) :=
           List (Token_First + Stream_Element_Offset (Offset));
      end loop;
      Last := Token'First + Stream_Element_Offset (Token_Length) - 1;
      Has_Token := True;
      return Ok;
   exception
      when Constraint_Error =>
         Last := Token'First - 1;
         Has_Token := False;
         return Read_Failed;
      when others =>
         Last := Token'First - 1;
         Has_Token := False;
         return Internal_Error;
   end Copy_Next_Capability_Token;
end SSH_Lib.Git;
