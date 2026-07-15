with Hostkit.Fs;
with Ada.Directories;
with Ada.Streams.Stream_IO;
with CryptoLib.Hashes;

package body SSH_Lib.File_Transfer is
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;
   use type Ada.Directories.File_Kind;
   use type Ada.Streams.Stream_Element_Offset;
   use type Ada.Streams.Stream_Element_Array;
   use type Interfaces.Unsigned_64;

   function SFTP_Transfer_Options
     (Pipeline_Depth        : Positive := SSH_Lib.SFTP.Default_Pipeline_Depth;
      Retry_Count           : Natural := 0;
      Verify_After_Transfer : Boolean := False;
      Atomic_Upload               : Boolean := False;
      Read_Chunk_Size             : Positive := SSH_Lib.SFTP.Upload_Chunk_Size;
      Write_Chunk_Size            : Positive := SSH_Lib.SFTP.Upload_Chunk_Size;
      Adaptive_Chunking           : Boolean := False;
      Minimum_Adaptive_Chunk_Size : Positive := 4 * 1024)
      return SSH_Lib.SFTP.Transfer_Options is
   begin
      return
        (Pipeline_Depth        => Pipeline_Depth,
         Retry_Count           => Retry_Count,
         Verify_After_Transfer => Verify_After_Transfer,
         Atomic_Upload               => Atomic_Upload,
         Read_Chunk_Size             => Read_Chunk_Size,
         Write_Chunk_Size            => Write_Chunk_Size,
         Adaptive_Chunking           => Adaptive_Chunking,
         Minimum_Adaptive_Chunk_Size => Minimum_Adaptive_Chunk_Size);
   end SFTP_Transfer_Options;

   function SFTP_Recursive_Options
     (Preserve_Attributes : Boolean := False;
      Filter              : SSH_Lib.SFTP.Recursive_Filter_Access := null;
      Progress            : SSH_Lib.SFTP.Recursive_Progress_Access := null;
      Continue_On_Error   : Boolean := False;
      Overwrite_Files     : Boolean := True;
      Follow_Symlinks     : Boolean := False;
      Skip_Unchanged      : Boolean := False)
      return SSH_Lib.SFTP.Recursive_Options is
   begin
      return
        (Preserve_Attributes => Preserve_Attributes,
         Filter              => Filter,
         Progress            => Progress,
         Continue_On_Error   => Continue_On_Error,
         Overwrite_Files     => Overwrite_Files,
         Follow_Symlinks     => Follow_Symlinks,
         Skip_Unchanged      => Skip_Unchanged);
   end SFTP_Recursive_Options;

   function Base_Result
     (Operation   : Workflow_Operation;
      Status      : CryptoLib.Errors.Status;
      Remote_Path : String := "";
      Local_Path  : String := "") return Workflow_Result
   is
      Result : Workflow_Result;
   begin
      Result.Operation := Operation;
      Result.Status := Status;
      Result.Remote_Path := To_Unbounded_String (Remote_Path);
      Result.Local_Path := To_Unbounded_String (Local_Path);
      SSH_Lib.Protocol.Buffers.Clear (Result.Digest);
      return Result;
   end Base_Result;

   function Kind_For
     (Attributes : SSH_Lib.SFTP.File_Attributes) return Inventory_Entry_Kind is
   begin
      if SSH_Lib.SFTP.Is_Directory (Attributes) then
         return Inventory_Directory;
      elsif SSH_Lib.SFTP.Is_Regular_File (Attributes) then
         return Inventory_File;
      elsif SSH_Lib.SFTP.Is_Symlink (Attributes) then
         return Inventory_Symlink;
      else
         return Inventory_Other;
      end if;
   exception
      when others =>
         return Inventory_Other;
   end Kind_For;

   function Join_Remote_Path (Parent : String; Name : String) return String is
   begin
      if Parent'Length = 0 then
         return Name;
      elsif Parent (Parent'Last) = '/' then
         return Parent & Name;
      else
         return Parent & "/" & Name;
      end if;
   end Join_Remote_Path;

   function Local_Join (Parent : String; Name : String) return String is
   begin
      if Parent'Length = 0 then
         return Name;
      elsif Parent (Parent'Last) = '/' then
         return Parent & Name;
      else
         return Parent & "/" & Name;
      end if;
   end Local_Join;

   function Contains_NUL (Value : String) return Boolean is
   begin
      for Ch of Value loop
         if Ch = Character'Val (0) then
            return True;
         end if;
      end loop;
      return False;
   end Contains_NUL;

   procedure Ensure_Local_Parent (Path : String) is
      Parent : constant String := Ada.Directories.Containing_Directory (Path);
   begin
      if Parent'Length > 0 and then not Ada.Directories.Exists (Parent) then
         Ada.Directories.Create_Path (Parent);
      end if;
   exception
      when others =>
         null;
   end Ensure_Local_Parent;

   --  The raw C symlink() this used has no Windows equivalent, so restore would not link
   --  there. Hostkit.Fs.Create_Link makes a symbolic link on whichever host -- symlink() on
   --  POSIX, CreateSymbolicLinkW on Windows, where it may be refused without the privilege.
   function Create_Local_Symlink
     (Target_Path : String;
      Link_Path   : String) return CryptoLib.Errors.Status
   is
   begin
      if Target_Path'Length = 0 or else Link_Path'Length = 0
        or else Contains_NUL (Target_Path) or else Contains_NUL (Link_Path)
      then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      if Hostkit.Fs.Create_Link (Target_Path, Link_Path) then
         return CryptoLib.Errors.Ok;
      end if;

      return CryptoLib.Errors.Remote_Failure;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Create_Local_Symlink;

   function Hex_Value (Ch : Character) return Natural is
   begin
      if Ch in '0' .. '9' then
         return Character'Pos (Ch) - Character'Pos ('0');
      elsif Ch in 'A' .. 'F' then
         return 10 + Character'Pos (Ch) - Character'Pos ('A');
      elsif Ch in 'a' .. 'f' then
         return 10 + Character'Pos (Ch) - Character'Pos ('a');
      else
         return Natural'Last;
      end if;
   end Hex_Value;

   function Hex_Digit (Value : Natural) return Character is
      Hex_Chars : constant String := "0123456789ABCDEF";
   begin
      return Hex_Chars (Value + 1);
   end Hex_Digit;

   function Hex_Encode
     (Data : Ada.Streams.Stream_Element_Array) return String
   is
      Result : String (1 .. Data'Length * 2);
      Output_Index : Positive := Result'First;
      Value : Natural;
   begin
      for Octet of Data loop
         Value := Natural (Octet);
         Result (Output_Index) := Hex_Digit (Value / 16);
         Result (Output_Index + 1) := Hex_Digit (Value mod 16);
         Output_Index := Output_Index + 2;
      end loop;
      return Result;
   exception
      when others =>
         return "";
   end Hex_Encode;

   function Hex_Decode
     (Value  : String;
      Buffer : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Data : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Value'Length / 2));
      Input_Index : Positive := Value'First;
      High_Nibble : Natural;
      Low_Nibble  : Natural;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Buffer);
      if Value'Length mod 2 /= 0 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      for Output_Index in Data'Range loop
         High_Nibble := Hex_Value (Value (Input_Index));
         Low_Nibble := Hex_Value (Value (Input_Index + 1));
         if High_Nibble = Natural'Last or else Low_Nibble = Natural'Last then
            return CryptoLib.Errors.Read_Failed;
         end if;
         Data (Output_Index) := Ada.Streams.Stream_Element
           (High_Nibble * 16 + Low_Nibble);
         Input_Index := Input_Index + 2;
      end loop;

      return SSH_Lib.Protocol.Buffers.Set (Buffer, Data);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Buffer);
         return CryptoLib.Errors.Read_Failed;
   end Hex_Decode;

   function Escape_Field (Value : String) return String is
      Result : Unbounded_String;
   begin
      for Ch of Value loop
         case Ch is
            when Character'Val (9) | Character'Val (10) | Character'Val (13) | '%' =>
               Append (Result, '%');
               Append (Result, Hex_Digit (Character'Pos (Ch) / 16));
               Append (Result, Hex_Digit (Character'Pos (Ch) mod 16));
            when others =>
               Append (Result, Ch);
         end case;
      end loop;
      return To_String (Result);
   end Escape_Field;

   function Unescape_Field
     (Value  : String;
      Output : out Unbounded_String) return CryptoLib.Errors.Status
   is
      Index : Positive := Value'First;
   begin
      Output := Null_Unbounded_String;
      while Index <= Value'Last loop
         if Value (Index) = '%' then
            if Index + 2 > Value'Last
              or else Hex_Value (Value (Index + 1)) = Natural'Last
              or else Hex_Value (Value (Index + 2)) = Natural'Last
            then
               return CryptoLib.Errors.Read_Failed;
            end if;
            Append
              (Output,
               Character'Val
                 (Hex_Value (Value (Index + 1)) * 16
                  + Hex_Value (Value (Index + 2))));
            Index := Index + 3;
         else
            Append (Output, Value (Index));
            Index := Index + 1;
         end if;
      end loop;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Output := Null_Unbounded_String;
         return CryptoLib.Errors.Read_Failed;
   end Unescape_Field;

   function Kind_Code (Kind : Inventory_Entry_Kind) return Character is
   begin
      case Kind is
         when Inventory_File      => return 'F';
         when Inventory_Directory => return 'D';
         when Inventory_Symlink   => return 'L';
         when Inventory_Other     => return 'O';
      end case;
   end Kind_Code;

   function Kind_From_Code
     (Code : Character; Kind : out Inventory_Entry_Kind)
      return CryptoLib.Errors.Status is
   begin
      case Code is
         when 'F' => Kind := Inventory_File;
         when 'D' => Kind := Inventory_Directory;
         when 'L' => Kind := Inventory_Symlink;
         when 'O' => Kind := Inventory_Other;
         when others => return CryptoLib.Errors.Read_Failed;
      end case;
      return CryptoLib.Errors.Ok;
   end Kind_From_Code;

   function Size_Image (Value : Interfaces.Unsigned_64) return String is
      Raw : constant String := Interfaces.Unsigned_64'Image (Value);
   begin
      if Raw'Length > 0 and then Raw (Raw'First) = ' ' then
         return Raw (Raw'First + 1 .. Raw'Last);
      end if;
      return Raw;
   end Size_Image;

   function Parse_Size
     (Value : String; Size : out Interfaces.Unsigned_64; Known : out Boolean)
      return CryptoLib.Errors.Status
   is
   begin
      Size := 0;
      Known := False;
      if Value = "-" then
         return CryptoLib.Errors.Ok;
      elsif Value'Length = 0 then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Known := True;
      for Ch of Value loop
         if Ch not in '0' .. '9' then
            return CryptoLib.Errors.Read_Failed;
         end if;
         Size := Size * 10 + Interfaces.Unsigned_64
           (Character'Pos (Ch) - Character'Pos ('0'));
      end loop;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Size := 0;
         Known := False;
         return CryptoLib.Errors.Read_Failed;
   end Parse_Size;

   function Has_Prefix_Path (Path : String; Root : String) return Boolean is
   begin
      return Path = Root
        or else
          (Path'Length > Root'Length
           and then Path (Path'First .. Path'First + Root'Length - 1) = Root
           and then Path (Path'First + Root'Length) = '/');
   exception
      when others =>
         return False;
   end Has_Prefix_Path;

   function Relative_To_Root (Path : String; Root : String) return String is
   begin
      if Path = Root then
         return "";
      elsif Has_Prefix_Path (Path, Root) then
         return Path (Path'First + Root'Length + 1 .. Path'Last);
      else
         return "";
      end if;
   exception
      when others =>
         return "";
   end Relative_To_Root;

   function Digest_Present (Item : Inventory_Entry) return Boolean is
   begin
      return Length (Item.Digest_Algorithm) > 0
        or else SSH_Lib.Protocol.Buffers.Length (Item.Digest) > 0;
   end Digest_Present;

   function Digest_Pair_Valid (Item : Inventory_Entry) return Boolean is
   begin
      return (Length (Item.Digest_Algorithm) = 0
              and then SSH_Lib.Protocol.Buffers.Length (Item.Digest) = 0)
        or else (Length (Item.Digest_Algorithm) > 0
                 and then SSH_Lib.Protocol.Buffers.Length (Item.Digest) > 0);
   end Digest_Pair_Valid;

   function Read_Local_File
     (Path : String;
      Data : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      File : Ada.Streams.Stream_IO.File_Type;
      Size : Ada.Streams.Stream_IO.Count;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Data);
      Ada.Streams.Stream_IO.Open (File, Ada.Streams.Stream_IO.In_File, Path);
      Size := Ada.Streams.Stream_IO.Size (File);
      declare
         Raw  : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Size));
         Last : Ada.Streams.Stream_Element_Offset;
      begin
         Ada.Streams.Stream_IO.Read (File, Raw, Last);
         Ada.Streams.Stream_IO.Close (File);
         if Last < Raw'Last then
            return SSH_Lib.Protocol.Buffers.Set (Data, Raw (Raw'First .. Last));
         end if;
         return SSH_Lib.Protocol.Buffers.Set (Data, Raw);
      end;
   exception
      when others =>
         if Ada.Streams.Stream_IO.Is_Open (File) then
            Ada.Streams.Stream_IO.Close (File);
         end if;
         SSH_Lib.Protocol.Buffers.Clear (Data);
         return CryptoLib.Errors.Read_Failed;
   end Read_Local_File;

   function MD5_Array
     (Data : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array
   is
      Digest : constant CryptoLib.Hashes.MD5_Digest :=
        CryptoLib.Hashes.MD5 (Data);
      Result : Ada.Streams.Stream_Element_Array (1 .. 16);
   begin
      for Index in Digest'Range loop
         Result (Ada.Streams.Stream_Element_Offset (Index)) := Digest (Index);
      end loop;
      return Result;
   end MD5_Array;

   function SHA1_Array
     (Data : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array
   is
      Digest : constant CryptoLib.Hashes.SHA1_Digest :=
        CryptoLib.Hashes.SHA1 (Data);
      Result : Ada.Streams.Stream_Element_Array (1 .. 20);
   begin
      for Index in Digest'Range loop
         Result (Ada.Streams.Stream_Element_Offset (Index)) := Digest (Index);
      end loop;
      return Result;
   end SHA1_Array;

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

   function SHA512_Array
     (Data : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array
   is
      Digest : constant CryptoLib.Hashes.SHA512_Digest :=
        CryptoLib.Hashes.SHA512 (Data);
      Result : Ada.Streams.Stream_Element_Array (1 .. 64);
   begin
      for Index in Digest'Range loop
         Result (Ada.Streams.Stream_Element_Offset (Index)) := Digest (Index);
      end loop;
      return Result;
   end SHA512_Array;

   function Local_File_Digest_Matches
     (Path : String;
      Item : Inventory_Entry) return Boolean
   is
      Data_Buffer  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected     : constant Ada.Streams.Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Item.Digest);
      Algorithm    : constant String := To_String (Item.Digest_Algorithm);
      Status_Value : CryptoLib.Errors.Status;
   begin
      if not Digest_Present (Item) then
         return True;
      elsif not Digest_Pair_Valid (Item) then
         return False;
      end if;

      Status_Value := Read_Local_File (Path, Data_Buffer);
      if Status_Value /= CryptoLib.Errors.Ok then
         return False;
      end if;

      declare
         Data : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Data_Buffer);
      begin
         if Algorithm = "md5" then
            return MD5_Array (Data) = Expected;
         elsif Algorithm = "sha1" then
            return SHA1_Array (Data) = Expected;
         elsif Algorithm = "sha256" then
            return SHA256_Array (Data) = Expected;
         elsif Algorithm = "sha512" then
            return SHA512_Array (Data) = Expected;
         else
            return False;
         end if;
      end;
   exception
      when others =>
         return False;
   end Local_File_Digest_Matches;

   procedure Count_Local_Path
     (Local_Path : String;
      Recursive  : Boolean;
      Items      : in out Natural;
      Bytes      : in out Interfaces.Unsigned_64)
   is
      Search       : Ada.Directories.Search_Type;
      Local_Item   : Ada.Directories.Directory_Entry_Type;
      Searching    : Boolean := False;
   begin
      if Local_Path'Length = 0 or else not Ada.Directories.Exists (Local_Path) then
         return;
      end if;

      Items := Items + 1;
      if Ada.Directories.Kind (Local_Path) = Ada.Directories.Ordinary_File then
         Bytes := Bytes + Interfaces.Unsigned_64 (Ada.Directories.Size (Local_Path));
      elsif Recursive and then Ada.Directories.Kind (Local_Path) = Ada.Directories.Directory then
         Ada.Directories.Start_Search
           (Search,
            Directory => Local_Path,
            Pattern   => "*",
            Filter    =>
              Ada.Directories.Filter_Type'
                (Ada.Directories.Ordinary_File => True,
                 Ada.Directories.Directory     => True,
                 Ada.Directories.Special_File  => False));
         Searching := True;
         while Ada.Directories.More_Entries (Search) loop
            Ada.Directories.Get_Next_Entry (Search, Local_Item);
            declare
               Name : constant String := Ada.Directories.Simple_Name (Local_Item);
            begin
               if Name /= "." and then Name /= ".." then
                  Count_Local_Path
                    (Ada.Directories.Compose (Local_Path, Name), Recursive,
                     Items, Bytes);
               end if;
            end;
         end loop;
         Ada.Directories.End_Search (Search);
      end if;
   exception
      when others =>
         if Searching then
            Ada.Directories.End_Search (Search);
         end if;
   end Count_Local_Path;

   procedure Copy_Counts
     (From : Inventory_Result;
      To   : in out Workflow_Result) is
   begin
      To.Items_Processed := From.Result.Items_Processed;
      To.Bytes_Processed := From.Result.Bytes_Processed;
   end Copy_Counts;

   function Contains_Inventory_Path
     (Inventory : Inventory_Result;
      Path      : String) return Boolean
   is
   begin
      for Item of Inventory.Entries loop
         if To_String (Item.Path) = Path then
            return True;
         end if;
      end loop;
      return False;
   end Contains_Inventory_Path;

   function Expected_Entry_For_Path
     (Inventory : Inventory_Result;
      Path      : String;
      Item      : out Inventory_Entry) return Boolean
   is
   begin
      for Candidate of Inventory.Entries loop
         if To_String (Candidate.Path) = Path then
            Item := Candidate;
            return True;
         end if;
      end loop;
      Item := (others => <>);
      return False;
   end Expected_Entry_For_Path;

   procedure Add_Inventory_Entry
     (Result      : in out Inventory_Result;
      Remote_Path : String;
      Attributes  : SSH_Lib.SFTP.File_Attributes;
      Link_Target : Unbounded_String := Null_Unbounded_String) is
   begin
      Result.Entries.Append
        (Inventory_Entry'
           (Path             => To_Unbounded_String (Remote_Path),
            Kind             => Kind_For (Attributes),
            Attributes       => Attributes,
            Link_Target      => Link_Target,
            Digest_Algorithm => Null_Unbounded_String,
            Digest           => <>));
      Result.Result.Items_Processed := Result.Result.Items_Processed + 1;
      if Attributes.Size_Known then
         Result.Result.Bytes_Processed :=
           Result.Result.Bytes_Processed + Attributes.Size;
      end if;
   exception
      when others =>
         Result.Result.Status := CryptoLib.Errors.Internal_Error;
   end Add_Inventory_Entry;

   procedure Collect_Inventory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Recursive   : Boolean;
      Result      : in out Inventory_Result)
   is
      Attributes   : SSH_Lib.SFTP.File_Attributes;
      Entries      : SSH_Lib.SFTP.Directory_Entry_Vectors.Vector;
      Status_Value : CryptoLib.Errors.Status;
   begin
      if Result.Result.Status /= CryptoLib.Errors.Ok then
         return;
      end if;

      Status_Value := SSH_Lib.SFTP.LStat (Session, Remote_Path, Attributes);
      if Status_Value /= CryptoLib.Errors.Ok then
         Result.Result.Status := Status_Value;
         return;
      end if;

      Add_Inventory_Entry (Result, Remote_Path, Attributes);
      if SSH_Lib.SFTP.Is_Symlink (Attributes) then
         declare
            Target     : Unbounded_String;
            Last_Index : constant Natural := Result.Entries.Last_Index;
            Item_Copy  : Inventory_Entry := Result.Entries.Element (Last_Index);
         begin
            Status_Value := SSH_Lib.SFTP.Read_Link (Session, Remote_Path, Target);
            if Status_Value /= CryptoLib.Errors.Ok then
               Result.Result.Status := Status_Value;
               return;
            end if;
            Item_Copy.Link_Target := Target;
            Result.Entries.Replace_Element (Last_Index, Item_Copy);
         end;
      end if;
      if not Recursive or else not SSH_Lib.SFTP.Is_Directory (Attributes) then
         return;
      end if;

      Status_Value := SSH_Lib.SFTP.List_Directory (Session, Remote_Path, Entries);
      if Status_Value /= CryptoLib.Errors.Ok then
         Result.Result.Status := Status_Value;
         return;
      end if;

      for Directory_Item of Entries loop
         declare
            Name : constant String := To_String (Directory_Item.Name);
         begin
            if Name /= "." and then Name /= ".." then
               Collect_Inventory
                 (Session,
                  Join_Remote_Path (Remote_Path, Name),
                  Recursive,
                  Result);
               if Result.Result.Status /= CryptoLib.Errors.Ok then
                  return;
               end if;
            end if;
         end;
      end loop;
   exception
      when others =>
         Result.Result.Status := CryptoLib.Errors.Internal_Error;
   end Collect_Inventory;

   procedure Collect_Inventory
     (Client      : in out SSH_Lib.SFTP.Client;
      Remote_Path : String;
      Recursive   : Boolean;
      Result      : in out Inventory_Result;
      Algorithms  : String := "";
      Block_Size  : Interfaces.Unsigned_32 := 0)
   is
      Attributes   : SSH_Lib.SFTP.File_Attributes;
      Entries      : SSH_Lib.SFTP.Directory_Entry_Vectors.Vector;
      Status_Value : CryptoLib.Errors.Status;
   begin
      if Result.Result.Status /= CryptoLib.Errors.Ok then
         return;
      end if;

      Status_Value := SSH_Lib.SFTP.LStat (Client, Remote_Path, Attributes);
      if Status_Value /= CryptoLib.Errors.Ok then
         Result.Result.Status := Status_Value;
         return;
      end if;

      Add_Inventory_Entry (Result, Remote_Path, Attributes);
      if SSH_Lib.SFTP.Is_Symlink (Attributes) then
         declare
            Target     : Unbounded_String;
            Last_Index : constant Natural := Result.Entries.Last_Index;
            Item_Copy  : Inventory_Entry := Result.Entries.Element (Last_Index);
         begin
            Status_Value := SSH_Lib.SFTP.Read_Link (Client, Remote_Path, Target);
            if Status_Value /= CryptoLib.Errors.Ok then
               Result.Result.Status := Status_Value;
               return;
            end if;
            Item_Copy.Link_Target := Target;
            Result.Entries.Replace_Element (Last_Index, Item_Copy);
         end;
      end if;
      if Algorithms'Length > 0 and then SSH_Lib.SFTP.Is_Regular_File (Attributes) then
         declare
            Last_Index : constant Natural := Result.Entries.Last_Index;
            Item_Copy  : Inventory_Entry := Result.Entries.Element (Last_Index);
         begin
            Status_Value := SSH_Lib.SFTP.Check_File
              (Client, Remote_Path, Algorithms, 0, 0, Block_Size,
               Item_Copy.Digest_Algorithm, Item_Copy.Digest);
            if Status_Value /= CryptoLib.Errors.Ok then
               Result.Result.Status := Status_Value;
               return;
            end if;
            Result.Entries.Replace_Element (Last_Index, Item_Copy);
         end;
      end if;

      if not Recursive or else not SSH_Lib.SFTP.Is_Directory (Attributes) then
         return;
      end if;

      Status_Value := SSH_Lib.SFTP.List_Directory (Client, Remote_Path, Entries);
      if Status_Value /= CryptoLib.Errors.Ok then
         Result.Result.Status := Status_Value;
         return;
      end if;

      for Directory_Item of Entries loop
         declare
            Name : constant String := To_String (Directory_Item.Name);
         begin
            if Name /= "." and then Name /= ".." then
               Collect_Inventory
                 (Client,
                  Join_Remote_Path (Remote_Path, Name),
                  Recursive,
                  Result,
                  Algorithms,
                  Block_Size);
               if Result.Result.Status /= CryptoLib.Errors.Ok then
                  return;
               end if;
            end if;
         end;
      end loop;
   exception
      when others =>
         Result.Result.Status := CryptoLib.Errors.Internal_Error;
   end Collect_Inventory;

   function Upload
     (Session        : in out SSH_Lib.Sessions.Session;
      Local_Path     : String;
      Remote_Path    : String;
      Recursive      : Boolean := False;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options;
      Transfer       : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return Workflow_Result
   is
      Result       : Workflow_Result :=
        Base_Result (Upload_Workflow, CryptoLib.Errors.Ok, Remote_Path, Local_Path);
      Status_Value : CryptoLib.Errors.Status;
      Count_Items  : Natural := 0;
      Count_Bytes  : Interfaces.Unsigned_64 := 0;
   begin
      if Local_Path'Length = 0 or else Remote_Path'Length = 0 then
         Result.Status := CryptoLib.Errors.Invalid_Command;
         return Result;
      end if;

      if Recursive
        or else
          (Ada.Directories.Exists (Local_Path)
           and then Ada.Directories.Kind (Local_Path) = Ada.Directories.Directory)
      then
         Status_Value := SSH_Lib.SFTP.Upload_Directory
           (Session, Remote_Path, Local_Path, Directory_Mode, File_Mode, Options);
      else
         Status_Value := SSH_Lib.SFTP.Upload_File
           (Session, Remote_Path, Local_Path, File_Mode, Transfer);
      end if;

      Result.Status := Status_Value;
      if Status_Value = CryptoLib.Errors.Ok then
         Count_Local_Path
           (Local_Path,
            Recursive or else
              (Ada.Directories.Exists (Local_Path)
               and then Ada.Directories.Kind (Local_Path) = Ada.Directories.Directory),
            Count_Items, Count_Bytes);
         Result.Items_Processed := Count_Items;
         Result.Bytes_Processed := Count_Bytes;
      end if;
      return Result;
   exception
      when others =>
         return Base_Result
           (Upload_Workflow, CryptoLib.Errors.Internal_Error,
            Remote_Path, Local_Path);
   end Upload;

   function Verify
     (Session       : in out SSH_Lib.Sessions.Session;
      Remote_Path   : String;
      Expected_Size : Interfaces.Unsigned_64 := 0;
      Check_Size    : Boolean := False;
      Algorithms    : String := "";
      Offset        : Interfaces.Unsigned_64 := 0;
      Length        : Interfaces.Unsigned_64 := 0;
      Block_Size    : Interfaces.Unsigned_32 := 0)
      return Workflow_Result
   is
      Result       : Workflow_Result :=
        Base_Result (Verify_Workflow, CryptoLib.Errors.Ok, Remote_Path);
      Attributes   : SSH_Lib.SFTP.File_Attributes;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.SFTP.Stat (Session, Remote_Path, Attributes);
      Result.Status := Status_Value;
      if Status_Value /= CryptoLib.Errors.Ok then
         return Result;
      end if;

      Result.Items_Processed := 1;
      if Attributes.Size_Known then
         Result.Bytes_Processed := Attributes.Size;
      end if;

      if Check_Size
        and then (not Attributes.Size_Known or else Attributes.Size /= Expected_Size)
      then
         Result.Status := CryptoLib.Errors.Remote_Failure;
         return Result;
      end if;

      if Algorithms'Length > 0 then
         Status_Value := SSH_Lib.SFTP.Check_File
           (Session, Remote_Path, Algorithms, Offset, Length, Block_Size,
            Result.Digest_Algorithm, Result.Digest);
         Result.Status := Status_Value;
         Result.Verified := Status_Value = CryptoLib.Errors.Ok;
      else
         Result.Verified := True;
      end if;
      return Result;
   exception
      when others =>
         return Base_Result
           (Verify_Workflow, CryptoLib.Errors.Internal_Error, Remote_Path);
   end Verify;

   function Delete
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Target      : Delete_Target := Delete_Auto;
      Options     : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options)
      return Workflow_Result
   is
      Result       : Workflow_Result :=
        Base_Result (Delete_Workflow, CryptoLib.Errors.Ok, Remote_Path);
      Attributes   : SSH_Lib.SFTP.File_Attributes;
      Status_Value : CryptoLib.Errors.Status;
      Before       : Inventory_Result;
   begin
      if Target = Delete_Tree or else Target = Delete_Auto then
         Before := Inventory (Session, Remote_Path, True);
         if Before.Result.Status /= CryptoLib.Errors.Ok then
            Result.Status := Before.Result.Status;
            return Result;
         end if;
      end if;

      case Target is
         when Delete_File =>
            Status_Value := SSH_Lib.SFTP.Remove_File (Session, Remote_Path);
         when Delete_Directory =>
            Status_Value := SSH_Lib.SFTP.Remove_Directory (Session, Remote_Path);
         when Delete_Tree =>
            Status_Value := SSH_Lib.SFTP.Remove_Tree (Session, Remote_Path, Options);
         when Delete_Auto =>
            Status_Value := SSH_Lib.SFTP.LStat (Session, Remote_Path, Attributes);
            if Status_Value = CryptoLib.Errors.Ok then
               if SSH_Lib.SFTP.Is_Directory (Attributes) then
                  Status_Value := SSH_Lib.SFTP.Remove_Tree
                    (Session, Remote_Path, Options);
               else
                  Status_Value := SSH_Lib.SFTP.Remove_File
                    (Session, Remote_Path);
               end if;
            end if;
      end case;

      Result.Status := Status_Value;
      if Status_Value = CryptoLib.Errors.Ok then
         if Target = Delete_Tree or else Target = Delete_Auto then
            Copy_Counts (Before, Result);
         else
            Result.Items_Processed := 1;
         end if;
      end if;
      return Result;
   exception
      when others =>
         return Base_Result
           (Delete_Workflow, CryptoLib.Errors.Internal_Error, Remote_Path);
   end Delete;

   function Restore
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Recursive   : Boolean := False;
      Policy      : Restore_Conflict_Policy := Overwrite_Existing;
      Options     : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options;
      Transfer    : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return Workflow_Result
   is
      Result       : Workflow_Result :=
        Base_Result (Restore_Workflow, CryptoLib.Errors.Ok, Remote_Path, Local_Path);
      Attributes   : SSH_Lib.SFTP.File_Attributes;
      Status_Value : CryptoLib.Errors.Status;
      Before       : Inventory_Result;
   begin
      if Policy = Fail_If_Exists and then Ada.Directories.Exists (Local_Path) then
         Result.Status := CryptoLib.Errors.Remote_Failure;
         return Result;
      elsif Policy = Skip_Existing and then Ada.Directories.Exists (Local_Path) then
         Result.Status := CryptoLib.Errors.Ok;
         Result.Verified := True;
         return Result;
      end if;

      Status_Value := SSH_Lib.SFTP.LStat (Session, Remote_Path, Attributes);
      if Status_Value /= CryptoLib.Errors.Ok then
         Result.Status := Status_Value;
         return Result;
      end if;

      if Recursive or else SSH_Lib.SFTP.Is_Directory (Attributes) then
         Before := Inventory (Session, Remote_Path, True);
         if Before.Result.Status /= CryptoLib.Errors.Ok then
            Result.Status := Before.Result.Status;
            return Result;
         end if;
         Status_Value := SSH_Lib.SFTP.Download_Directory
           (Session, Remote_Path, Local_Path, Options);
      else
         Status_Value := SSH_Lib.SFTP.Download_File
           (Session, Remote_Path, Local_Path, Transfer);
      end if;

      Result.Status := Status_Value;
      if Status_Value = CryptoLib.Errors.Ok then
         if Recursive or else SSH_Lib.SFTP.Is_Directory (Attributes) then
            Copy_Counts (Before, Result);
         else
            Result.Items_Processed := 1;
            if Attributes.Size_Known then
               Result.Bytes_Processed := Attributes.Size;
            end if;
         end if;
      end if;
      return Result;
   exception
      when others =>
         return Base_Result
           (Restore_Workflow, CryptoLib.Errors.Internal_Error,
            Remote_Path, Local_Path);
   end Restore;

   function Inventory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Recursive   : Boolean := False)
      return Inventory_Result
   is
      Result       : Inventory_Result;
      Client       : SSH_Lib.SFTP.Client;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Result.Result :=
        Base_Result (Inventory_Workflow, CryptoLib.Errors.Ok, Remote_Path);
      Status_Value := SSH_Lib.SFTP.Open (Session, Client);
      if Status_Value /= CryptoLib.Errors.Ok then
         Result.Result.Status := Status_Value;
         return Result;
      end if;

      Collect_Inventory (Client, Remote_Path, Recursive, Result);
      Close_Status := SSH_Lib.SFTP.Close (Client);
      return Result;
   exception
      when others =>
         Result.Result :=
           Base_Result
             (Inventory_Workflow, CryptoLib.Errors.Internal_Error,
              Remote_Path);
         Result.Entries.Clear;
         return Result;
   end Inventory;

   function Inventory_With_Checks
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Recursive   : Boolean := False;
      Algorithms  : String := "sha256";
      Block_Size  : Interfaces.Unsigned_32 := 0)
      return Inventory_Result
   is
      Result       : Inventory_Result;
      Client       : SSH_Lib.SFTP.Client;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
   begin
      Result.Result :=
        Base_Result (Inventory_Workflow, CryptoLib.Errors.Ok, Remote_Path);
      if Algorithms'Length = 0 then
         Result.Result.Status := CryptoLib.Errors.Invalid_Command;
         return Result;
      end if;

      Status_Value := SSH_Lib.SFTP.Open (Session, Client);
      if Status_Value /= CryptoLib.Errors.Ok then
         Result.Result.Status := Status_Value;
         return Result;
      end if;

      Collect_Inventory
        (Client, Remote_Path, Recursive, Result, Algorithms, Block_Size);
      Close_Status := SSH_Lib.SFTP.Close (Client);
      return Result;
   exception
      when others =>
         Result.Result :=
           Base_Result
             (Inventory_Workflow, CryptoLib.Errors.Internal_Error,
              Remote_Path);
         Result.Entries.Clear;
         return Result;
   end Inventory_With_Checks;

   function Inventory_Manifest
     (Inventory : Inventory_Result)
      return Unbounded_String
   is
      Result : Unbounded_String :=
        To_Unbounded_String
          ("SSH_LIB_INVENTORY" & Character'Val (9) & "3"
           & Character'Val (10));
   begin
      for Item of Inventory.Entries loop
         Append (Result, Kind_Code (Item.Kind));
         Append (Result, Character'Val (9));
         if Item.Attributes.Size_Known then
            Append (Result, Size_Image (Item.Attributes.Size));
         else
            Append (Result, "-");
         end if;
         Append (Result, Character'Val (9));
         if Length (Item.Digest_Algorithm) > 0 then
            Append (Result, Escape_Field (To_String (Item.Digest_Algorithm)));
         else
            Append (Result, "-");
         end if;
         Append (Result, Character'Val (9));
         if SSH_Lib.Protocol.Buffers.Length (Item.Digest) > 0 then
            Append (Result, Hex_Encode (SSH_Lib.Protocol.Buffers.To_Array (Item.Digest)));
         else
            Append (Result, "-");
         end if;
         Append (Result, Character'Val (9));
         Append (Result, Escape_Field (To_String (Item.Path)));
         Append (Result, Character'Val (9));
         if Item.Kind = Inventory_Symlink and then Length (Item.Link_Target) > 0 then
            Append (Result, Escape_Field (To_String (Item.Link_Target)));
         else
            Append (Result, "-");
         end if;
         Append (Result, Character'Val (10));
      end loop;
      return Result;
   exception
      when others =>
         return Null_Unbounded_String;
   end Inventory_Manifest;

   function Parse_Line
     (Line      : String;
      Version   : Positive;
      Inventory : in out Inventory_Result) return CryptoLib.Errors.Status
   is
      Tabs        : array (1 .. 5) of Natural := [others => 0];
      Tab_Count   : Natural := 0;
      Kind        : Inventory_Entry_Kind := Inventory_Other;
      Path        : Unbounded_String;
      Link_Target : Unbounded_String;
      Algorithm   : Unbounded_String;
      Digest      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Size        : Interfaces.Unsigned_64 := 0;
      Size_Known  : Boolean := False;
      Attributes  : SSH_Lib.SFTP.File_Attributes;
      Status_Value : CryptoLib.Errors.Status;
   begin
      for Index in Line'Range loop
         if Line (Index) = Character'Val (9) then
            Tab_Count := Tab_Count + 1;
            if Tab_Count <= Tabs'Last then
               Tabs (Tab_Count) := Index;
            end if;
         end if;
      end loop;

      if Tabs (1) /= Line'First + 1
        or else (Version = 1 and then Tab_Count /= 2)
        or else (Version = 2 and then Tab_Count /= 4)
        or else (Version = 3 and then Tab_Count /= 5)
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Status_Value := Kind_From_Code (Line (Line'First), Kind);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value := Parse_Size
        (Line (Tabs (1) + 1 .. Tabs (2) - 1), Size, Size_Known);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      if Version = 1 then
         Status_Value := Unescape_Field
           (Line (Tabs (2) + 1 .. Line'Last), Path);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
      else
         if Line (Tabs (3) + 1 .. Tabs (4) - 1) /= "-" then
            Status_Value := Hex_Decode
              (Line (Tabs (3) + 1 .. Tabs (4) - 1), Digest);
            if Status_Value /= CryptoLib.Errors.Ok then
               return Status_Value;
            end if;
         else
            SSH_Lib.Protocol.Buffers.Clear (Digest);
         end if;

         if Line (Tabs (2) + 1 .. Tabs (3) - 1) /= "-" then
            Status_Value := Unescape_Field
              (Line (Tabs (2) + 1 .. Tabs (3) - 1), Algorithm);
            if Status_Value /= CryptoLib.Errors.Ok then
               return Status_Value;
            end if;
         else
            Algorithm := Null_Unbounded_String;
         end if;

         if Version = 2 then
            Status_Value := Unescape_Field
              (Line (Tabs (4) + 1 .. Line'Last), Path);
            if Status_Value /= CryptoLib.Errors.Ok then
               return Status_Value;
            end if;
         else
            Status_Value := Unescape_Field
              (Line (Tabs (4) + 1 .. Tabs (5) - 1), Path);
            if Status_Value /= CryptoLib.Errors.Ok then
               return Status_Value;
            end if;

            if Line (Tabs (5) + 1 .. Line'Last) /= "-" then
               Status_Value := Unescape_Field
                 (Line (Tabs (5) + 1 .. Line'Last), Link_Target);
               if Status_Value /= CryptoLib.Errors.Ok then
                  return Status_Value;
               end if;
            else
               Link_Target := Null_Unbounded_String;
            end if;
         end if;
      end if;

      if Version = 3 then
         if Kind = Inventory_Symlink and then Length (Link_Target) = 0 then
            return CryptoLib.Errors.Read_Failed;
         elsif Kind /= Inventory_Symlink and then Length (Link_Target) > 0 then
            return CryptoLib.Errors.Read_Failed;
         end if;
      end if;

      if Contains_Inventory_Path (Inventory, To_String (Path)) then
         return CryptoLib.Errors.Read_Failed;
      end if;

      declare
         Parsed_Item : constant Inventory_Entry :=
           (Path             => Path,
            Kind             => Kind,
            Attributes       => (others => <>),
            Link_Target      => Link_Target,
            Digest_Algorithm => Algorithm,
            Digest           => Digest);
      begin
         if not Digest_Pair_Valid (Parsed_Item) then
            return CryptoLib.Errors.Read_Failed;
         end if;
      end;

      Attributes := (others => <>);
      Attributes.Size_Known := Size_Known;
      Attributes.Size := Size;
      Inventory.Entries.Append
        (Inventory_Entry'
           (Path             => Path,
            Kind             => Kind,
            Attributes       => Attributes,
            Link_Target      => Link_Target,
            Digest_Algorithm => Algorithm,
            Digest           => Digest));
      Inventory.Result.Items_Processed := Inventory.Result.Items_Processed + 1;
      if Size_Known then
         Inventory.Result.Bytes_Processed :=
           Inventory.Result.Bytes_Processed + Size;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         return CryptoLib.Errors.Read_Failed;
   end Parse_Line;

   function Parse_Inventory_Manifest
     (Manifest  : String;
      Inventory : out Inventory_Result) return CryptoLib.Errors.Status
   is
      Start        : Positive := Manifest'First;
      Line_End     : Natural;
      Line_Number  : Natural := 0;
      Version      : Positive := 1;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Inventory := (others => <>);
      Inventory.Result := Base_Result (Inventory_Workflow, CryptoLib.Errors.Ok);
      if Manifest'Length = 0 then
         Inventory.Result.Status := CryptoLib.Errors.Read_Failed;
         return CryptoLib.Errors.Read_Failed;
      end if;

      while Start <= Manifest'Last loop
         Line_End := Start;
         while Line_End <= Manifest'Last
           and then Manifest (Line_End) /= Character'Val (10)
         loop
            Line_End := Line_End + 1;
         end loop;

         declare
            Line_Last : constant Natural := Line_End - 1;
         begin
            Line_Number := Line_Number + 1;
            if Line_Last >= Start then
               declare
                  Line : constant String := Manifest (Start .. Line_Last);
               begin
                  if Line_Number = 1 then
                     if Line = "SSH_LIB_INVENTORY" & Character'Val (9) & "1" then
                        Version := 1;
                     elsif Line = "SSH_LIB_INVENTORY" & Character'Val (9) & "2" then
                        Version := 2;
                     elsif Line = "SSH_LIB_INVENTORY" & Character'Val (9) & "3" then
                        Version := 3;
                     else
                        Inventory.Result.Status := CryptoLib.Errors.Read_Failed;
                        return CryptoLib.Errors.Read_Failed;
                     end if;
                  else
                     Status_Value := Parse_Line (Line, Version, Inventory);
                     if Status_Value /= CryptoLib.Errors.Ok then
                        Inventory.Result.Status := Status_Value;
                        Inventory.Entries.Clear;
                        return Status_Value;
                     end if;
                  end if;
               end;
            end if;
         end;
         Start := Line_End + 1;
      end loop;

      if Line_Number = 0 then
         Inventory.Result.Status := CryptoLib.Errors.Read_Failed;
         return CryptoLib.Errors.Read_Failed;
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Inventory := (others => <>);
         Inventory.Result.Status := CryptoLib.Errors.Read_Failed;
         return CryptoLib.Errors.Read_Failed;
   end Parse_Inventory_Manifest;

   function Equivalent_Inventory
     (Left  : Inventory_Result;
      Right : Inventory_Result) return Boolean
   is
   begin
      if Natural (Left.Entries.Length) /= Natural (Right.Entries.Length) then
         return False;
      elsif Natural (Left.Entries.Length) = 0 then
         return True;
      end if;
      for Index in 0 .. Natural (Left.Entries.Length) - 1 loop
         declare
            L : constant Inventory_Entry := Left.Entries.Element (Index);
            R : constant Inventory_Entry := Right.Entries.Element (Index);
         begin
            if To_String (L.Path) /= To_String (R.Path)
              or else L.Kind /= R.Kind
              or else L.Attributes.Size_Known /= R.Attributes.Size_Known
              or else To_String (L.Link_Target) /= To_String (R.Link_Target)
              or else
                (L.Attributes.Size_Known and then L.Attributes.Size /= R.Attributes.Size)
            then
               return False;
            end if;

            if Digest_Present (L) or else Digest_Present (R) then
               if To_String (L.Digest_Algorithm) /= To_String (R.Digest_Algorithm)
                 or else SSH_Lib.Protocol.Buffers.To_Array (L.Digest)
                   /= SSH_Lib.Protocol.Buffers.To_Array (R.Digest)
               then
                  return False;
               end if;
            end if;
         end;
      end loop;
      return True;
   exception
      when others =>
         return False;
   end Equivalent_Inventory;

   function Verify_Inventory
     (Session     : in out SSH_Lib.Sessions.Session;
      Manifest    : String;
      Remote_Path : String;
      Recursive   : Boolean := True)
      return Workflow_Result
   is
      Expected     : Inventory_Result;
      Current      : Inventory_Result;
      Client       : SSH_Lib.SFTP.Client;
      Need_Digest  : Boolean := False;
      Expected_Item : Inventory_Entry;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      pragma Unreferenced (Close_Status);
      Result       : Workflow_Result :=
        Base_Result (Verify_Workflow, CryptoLib.Errors.Ok, Remote_Path);
   begin
      Status_Value := Parse_Inventory_Manifest (Manifest, Expected);
      if Status_Value /= CryptoLib.Errors.Ok then
         Result.Status := Status_Value;
         return Result;
      end if;

      for Item of Expected.Entries loop
         if Digest_Present (Item) then
            if not Digest_Pair_Valid (Item) then
               Result.Status := CryptoLib.Errors.Read_Failed;
               return Result;
            end if;
            Need_Digest := True;
         end if;
      end loop;

      Current := Inventory (Session, Remote_Path, Recursive);
      if Need_Digest and then Current.Result.Status = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.SFTP.Open (Session, Client);
         if Status_Value /= CryptoLib.Errors.Ok then
            Result.Status := Status_Value;
            return Result;
         end if;

         if Natural (Current.Entries.Length) > 0 then
            for Index in 0 .. Natural (Current.Entries.Length) - 1 loop
               declare
                  Item_Copy : Inventory_Entry := Current.Entries.Element (Index);
               begin
                  if SSH_Lib.SFTP.Is_Regular_File (Item_Copy.Attributes)
                    and then Expected_Entry_For_Path
                      (Expected, To_String (Item_Copy.Path), Expected_Item)
                    and then Digest_Present (Expected_Item)
                  then
                     Status_Value := SSH_Lib.SFTP.Check_File
                       (Client, To_String (Item_Copy.Path),
                        To_String (Expected_Item.Digest_Algorithm), 0, 0, 0,
                        Item_Copy.Digest_Algorithm, Item_Copy.Digest);
                     if Status_Value /= CryptoLib.Errors.Ok then
                        Current.Result.Status := Status_Value;
                        exit;
                     end if;
                     Current.Entries.Replace_Element (Index, Item_Copy);
                  end if;
               end;
            end loop;
         end if;
         Close_Status := SSH_Lib.SFTP.Close (Client);
      end if;
      Result := Current.Result;
      Result.Operation := Verify_Workflow;
      if Current.Result.Status /= CryptoLib.Errors.Ok then
         return Result;
      end if;

      Result.Verified := Equivalent_Inventory (Expected, Current);
      if not Result.Verified then
         Result.Status := CryptoLib.Errors.Remote_Failure;
      end if;
      return Result;
   exception
      when others =>
         return Base_Result
           (Verify_Workflow, CryptoLib.Errors.Internal_Error, Remote_Path);
   end Verify_Inventory;

   function Restore_From_Inventory
     (Session     : in out SSH_Lib.Sessions.Session;
      Inventory   : Inventory_Result;
      Source_Root : String;
      Local_Root  : String;
      Policy      : Restore_Conflict_Policy := Overwrite_Existing;
      Transfer    : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return Workflow_Result
   is
      Result       : Workflow_Result :=
        Base_Result (Restore_Workflow, CryptoLib.Errors.Ok, Source_Root, Local_Root);
      Status_Value : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
   begin
      if Inventory.Result.Status /= CryptoLib.Errors.Ok
        or else Source_Root'Length = 0
        or else Local_Root'Length = 0
      then
         Result.Status := CryptoLib.Errors.Invalid_Command;
         return Result;
      end if;

      for Item of Inventory.Entries loop
         declare
            Remote_Path : constant String := To_String (Item.Path);
         begin
            if not Has_Prefix_Path (Remote_Path, Source_Root) then
               Result.Status := CryptoLib.Errors.Invalid_Command;
               return Result;
            end if;

            declare
               Relative : constant String := Relative_To_Root (Remote_Path, Source_Root);
               Local_Path : constant String :=
                 (if Relative'Length = 0 then Local_Root else Local_Join (Local_Root, Relative));
            begin
               case Item.Kind is
                  when Inventory_Directory =>
                     if Ada.Directories.Exists (Local_Path) then
                        if Policy = Fail_If_Exists
                          and then Ada.Directories.Kind (Local_Path) /= Ada.Directories.Directory
                        then
                           Result.Status := CryptoLib.Errors.Remote_Failure;
                           return Result;
                        end if;
                     else
                        Ada.Directories.Create_Path (Local_Path);
                     end if;
                  when Inventory_File =>
                     if Ada.Directories.Exists (Local_Path) then
                        case Policy is
                           when Fail_If_Exists =>
                              Result.Status := CryptoLib.Errors.Remote_Failure;
                              return Result;
                           when Skip_Existing =>
                              if Digest_Present (Item)
                                and then not Local_File_Digest_Matches
                                  (Local_Path, Item)
                              then
                                 Result.Status := CryptoLib.Errors.Remote_Failure;
                                 return Result;
                              end if;
                              Result.Items_Processed := Result.Items_Processed + 1;
                              if Item.Attributes.Size_Known then
                                 Result.Bytes_Processed :=
                                   Result.Bytes_Processed + Item.Attributes.Size;
                              end if;
                              goto Continue;
                           when Overwrite_Existing =>
                              null;
                        end case;
                     else
                        Ensure_Local_Parent (Local_Path);
                     end if;
                     Status_Value := SSH_Lib.SFTP.Download_File
                       (Session, Remote_Path, Local_Path, Transfer);
                     if Status_Value /= CryptoLib.Errors.Ok then
                        Result.Status := Status_Value;
                        return Result;
                     end if;
                     if Digest_Present (Item)
                       and then not Local_File_Digest_Matches (Local_Path, Item)
                     then
                        Result.Status := CryptoLib.Errors.Remote_Failure;
                        return Result;
                     end if;
                  when Inventory_Symlink =>
                     if Length (Item.Link_Target) = 0 then
                        Result.Status := CryptoLib.Errors.Unsupported_Feature;
                        return Result;
                     end if;

                     if Ada.Directories.Exists (Local_Path) then
                        case Policy is
                           when Fail_If_Exists =>
                              Result.Status := CryptoLib.Errors.Remote_Failure;
                              return Result;
                           when Skip_Existing =>
                              Result.Items_Processed := Result.Items_Processed + 1;
                              goto Continue;
                           when Overwrite_Existing =>
                              begin
                                 if Ada.Directories.Kind (Local_Path) = Ada.Directories.Directory then
                                    Result.Status := CryptoLib.Errors.Remote_Failure;
                                    return Result;
                                 end if;
                                 Ada.Directories.Delete_File (Local_Path);
                              exception
                                 when others =>
                                    Result.Status := CryptoLib.Errors.Remote_Failure;
                                    return Result;
                              end;
                        end case;
                     else
                        Ensure_Local_Parent (Local_Path);
                     end if;

                     Status_Value := Create_Local_Symlink
                       (To_String (Item.Link_Target), Local_Path);
                     if Status_Value /= CryptoLib.Errors.Ok then
                        Result.Status := Status_Value;
                        return Result;
                     end if;
                  when Inventory_Other =>
                     Result.Status := CryptoLib.Errors.Unsupported_Feature;
                     return Result;
               end case;

               Result.Items_Processed := Result.Items_Processed + 1;
               if Item.Attributes.Size_Known then
                  Result.Bytes_Processed :=
                    Result.Bytes_Processed + Item.Attributes.Size;
               end if;
               <<Continue>>
               null;
            end;
         end;
      end loop;

      Result.Verified := True;
      return Result;
   exception
      when others =>
         return Base_Result
           (Restore_Workflow, CryptoLib.Errors.Internal_Error,
            Source_Root, Local_Root);
   end Restore_From_Inventory;

   function Restore_From_Manifest
     (Session     : in out SSH_Lib.Sessions.Session;
      Manifest    : String;
      Source_Root : String;
      Local_Root  : String;
      Policy      : Restore_Conflict_Policy := Overwrite_Existing;
      Transfer    : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return Workflow_Result
   is
      Parsed       : Inventory_Result;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := Parse_Inventory_Manifest (Manifest, Parsed);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Base_Result
           (Restore_Workflow, Status_Value, Source_Root, Local_Root);
      end if;
      return Restore_From_Inventory
        (Session, Parsed, Source_Root, Local_Root, Policy, Transfer);
   exception
      when others =>
         return Base_Result
           (Restore_Workflow, CryptoLib.Errors.Internal_Error,
            Source_Root, Local_Root);
   end Restore_From_Manifest;

   function Valid_File_Name (File_Name : String) return Boolean is
   begin
      if File_Name'Length = 0
        or else File_Name'Length > Maximum_File_Name_Length
        or else File_Name = "."
        or else File_Name = ".."
      then
         return False;
      end if;

      for Name_Character of File_Name loop
         if Name_Character = '/'
           or else Name_Character = Character'Val (0)
           or else Name_Character = Character'Val (10)
           or else Name_Character = Character'Val (13)
         then
            return False;
         end if;
      end loop;
      return True;
   exception
      when others =>
         return False;
   end Valid_File_Name;

   function Local_File_Name (Local_Path : String) return String is
   begin
      if Local_Path'Length = 0 then
         return "";
      end if;

      return Ada.Directories.Simple_Name (Local_Path);
   exception
      when others =>
         return "";
   end Local_File_Name;

   function Build_Remote_File_Path
     (Remote_Path : String;
      File_Name   : String;
      Full_Path   : out Unbounded_String)
      return CryptoLib.Errors.Status
   is
   begin
      Full_Path := Null_Unbounded_String;
      if Remote_Path'Length = 0 or else not Valid_File_Name (File_Name) then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      for Path_Character of Remote_Path loop
         if Path_Character = Character'Val (0) then
            return CryptoLib.Errors.Invalid_Command;
         end if;
      end loop;

      if Remote_Path (Remote_Path'Last) = '/' then
         if Remote_Path'Length + File_Name'Length >
           Maximum_SFTP_Remote_Path_Length
         then
            return CryptoLib.Errors.Invalid_Command;
         end if;
         Full_Path := To_Unbounded_String (Remote_Path & File_Name);
      else
         if Remote_Path'Length + 1 + File_Name'Length >
           Maximum_SFTP_Remote_Path_Length
         then
            return CryptoLib.Errors.Invalid_Command;
         end if;
         Full_Path := To_Unbounded_String (Remote_Path & "/" & File_Name);
      end if;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Full_Path := Null_Unbounded_String;
         return CryptoLib.Errors.Invalid_Command;
   end Build_Remote_File_Path;

   function Upload_Data
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      File_Name   : String;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644";
      Method      : Upload_Method := Upload_Auto;
      SFTP_Options : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      SFTP_Remote_Path : Unbounded_String;
      Status_Value     : CryptoLib.Errors.Status;
   begin
      case Method is
         when Upload_Auto | Upload_SCP =>
            return SSH_Lib.SCP.Upload_Data
              (Session, Remote_Path, File_Name, Data, Mode);
         when Upload_SFTP =>
            Status_Value := Build_Remote_File_Path
              (Remote_Path, File_Name, SFTP_Remote_Path);
            if Status_Value /= CryptoLib.Errors.Ok then
               return Status_Value;
            end if;
            return SSH_Lib.SFTP.Upload_Data
              (Session, To_String (SFTP_Remote_Path), Data, Mode, SFTP_Options);
      end case;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Upload_Data;

   function Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Method      : Upload_Method := Upload_Auto;
      SFTP_Options : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      File_Name        : constant String := Local_File_Name (Local_Path);
      SFTP_Remote_Path : Unbounded_String;
      Status_Value     : CryptoLib.Errors.Status;
   begin
      case Method is
         when Upload_Auto | Upload_SCP =>
            if not Valid_File_Name (File_Name) then
               return CryptoLib.Errors.Invalid_Command;
            end if;
            return SSH_Lib.SCP.Upload_File
              (Session     => Session,
               Remote_Path => Remote_Path,
               Local_Path  => Local_Path,
               File_Name   => File_Name,
               Mode        => Mode);
         when Upload_SFTP =>
            Status_Value := Build_Remote_File_Path
              (Remote_Path, File_Name, SFTP_Remote_Path);
            if Status_Value /= CryptoLib.Errors.Ok then
               return Status_Value;
            end if;
            return SSH_Lib.SFTP.Upload_File
              (Session     => Session,
               Remote_Path => To_String (SFTP_Remote_Path),
               Local_Path  => Local_Path,
               Mode        => Mode,
               Options     => SFTP_Options);
      end case;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Upload_File;

   function Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      File_Name   : String;
      Mode        : String := "0644";
      Method      : Upload_Method := Upload_Auto;
      SFTP_Options : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status
   is
      SFTP_Remote_Path : Unbounded_String;
      Status_Value     : CryptoLib.Errors.Status;
   begin
      case Method is
         when Upload_Auto | Upload_SCP =>
            return SSH_Lib.SCP.Upload_File
              (Session     => Session,
               Remote_Path => Remote_Path,
               Local_Path  => Local_Path,
               File_Name   => File_Name,
               Mode        => Mode);
         when Upload_SFTP =>
            Status_Value := Build_Remote_File_Path
              (Remote_Path, File_Name, SFTP_Remote_Path);
            if Status_Value /= CryptoLib.Errors.Ok then
               return Status_Value;
            end if;
            return SSH_Lib.SFTP.Upload_File
              (Session     => Session,
               Remote_Path => To_String (SFTP_Remote_Path),
               Local_Path  => Local_Path,
               Mode        => Mode,
               Options     => SFTP_Options);
      end case;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Upload_File;

   function Download_Data
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Download_Data (Session, Remote_Path, Data, Options);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Data);
         return CryptoLib.Errors.Internal_Error;
   end Download_Data;

   function Upload_Stream
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Size        : Interfaces.Unsigned_64;
      Reader      : SSH_Lib.SFTP.Stream_Reader_Access;
      Mode        : String := "0644";
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Upload_Stream
        (Session, Remote_Path, Size, Reader, Mode, Options);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Upload_Stream;

   function Download_Stream
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Writer      : SSH_Lib.SFTP.Stream_Writer_Access;
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Download_Stream
        (Session, Remote_Path, Writer, Options);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Download_Stream;

   function Download_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Download_File (Session, Remote_Path, Local_Path, Options);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Download_File;

   function Resume_Download_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Resume_Download_File
        (Session, Remote_Path, Local_Path, Options);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Resume_Download_File;

   function Resume_Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644";
      Options     : SSH_Lib.SFTP.Transfer_Options :=
        SSH_Lib.SFTP.Default_Transfer_Options)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Resume_Upload_File
        (Session, Remote_Path, Local_Path, Mode, Options);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Resume_Upload_File;

   function List_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Names       : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.List_Directory (Session, Remote_Path, Names);
   exception
      when others =>
         Names := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end List_Directory;

   function List_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Entries     : out SSH_Lib.SFTP.Directory_Entry_Vectors.Vector)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.List_Directory (Session, Remote_Path, Entries);
   exception
      when others =>
         Entries.Clear;
         return CryptoLib.Errors.Internal_Error;
   end List_Directory;

   function List_Directory_Paged
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Callback    : SSH_Lib.SFTP.Directory_Page_Callback_Access)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.List_Directory_Paged
        (Session, Remote_Path, Callback);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end List_Directory_Paged;

   function Stat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Stat (Session, Remote_Path, Attributes);
   exception
      when others =>
         Attributes := (others => <>);
         return CryptoLib.Errors.Internal_Error;
   end Stat;

   function LStat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.LStat (Session, Remote_Path, Attributes);
   exception
      when others =>
         Attributes := (others => <>);
         return CryptoLib.Errors.Internal_Error;
   end LStat;

   function Realpath
     (Session        : in out SSH_Lib.Sessions.Session;
      Remote_Path    : String;
      Canonical_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Realpath (Session, Remote_Path, Canonical_Path);
   exception
      when others =>
         Canonical_Path := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end Realpath;

   function Set_Permissions
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Set_Permissions (Session, Remote_Path, Mode);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Set_Permissions;

   function Set_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Set_Attributes (Session, Remote_Path, Attributes);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Set_Attributes;

   function Make_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String := "0755")
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Make_Directory (Session, Remote_Path, Mode);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Make_Directory;

   function Remove_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Remove_Directory (Session, Remote_Path);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Remove_Directory;

   function Remove_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Remove_File (Session, Remote_Path);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Remove_File;

   function Upload_Directory
     (Session        : in out SSH_Lib.Sessions.Session;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Upload_Directory
        (Session, Remote_Path, Local_Path, Directory_Mode, File_Mode, Options);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Upload_Directory;

   function Download_Directory
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Options     : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Download_Directory
        (Session, Remote_Path, Local_Path, Options);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Download_Directory;

   function Remove_Tree
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Options     : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Remove_Tree (Session, Remote_Path, Options);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Remove_Tree;

   function Copy_Tree
     (Session             : in out SSH_Lib.Sessions.Session;
      Source_Remote_Path  : String;
      Target_Remote_Path  : String;
      Directory_Mode      : String := "0755";
      File_Mode           : String := "0644";
      Options             : SSH_Lib.SFTP.Recursive_Options :=
        SSH_Lib.SFTP.Default_Recursive_Options)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Copy_Tree
        (Session, Source_Remote_Path, Target_Remote_Path,
         Directory_Mode, File_Mode, Options);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Copy_Tree;

   function Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Rename (Session, Old_Path, New_Path);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Rename;

   function Posix_Rename
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Posix_Rename (Session, Old_Path, New_Path);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Posix_Rename;

   function Hardlink
     (Session  : in out SSH_Lib.Sessions.Session;
      Old_Path : String;
      New_Path : String)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Hardlink (Session, Old_Path, New_Path);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Hardlink;

   function LSet_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.LSet_Attributes (Session, Remote_Path, Attributes);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end LSet_Attributes;

   function StatVFS
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Stats       : out SSH_Lib.SFTP.File_System_Stats)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.StatVFS (Session, Remote_Path, Stats);
   exception
      when others =>
         Stats := (others => 0);
         return CryptoLib.Errors.Internal_Error;
   end StatVFS;

   function Limits
     (Session : in out SSH_Lib.Sessions.Session;
      Values  : out SSH_Lib.SFTP.Server_Limits)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Limits (Session, Values);
   exception
      when others =>
         Values := (others => 0);
         return CryptoLib.Errors.Internal_Error;
   end Limits;

   function Extended_Request
     (Session        : in out SSH_Lib.Sessions.Session;
      Extension_Name : String;
      Payload        : Ada.Streams.Stream_Element_Array;
      Reply_Data     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Extended_Request
        (Session, Extension_Name, Payload, Reply_Data);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Reply_Data);
         return CryptoLib.Errors.Internal_Error;
   end Extended_Request;

   function Read_Link
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Target_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Read_Link (Session, Remote_Path, Target_Path);
   exception
      when others =>
         Target_Path := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end Read_Link;

   function Create_Symlink
     (Session     : in out SSH_Lib.Sessions.Session;
      Target_Path : String;
      Link_Path   : String)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Create_Symlink (Session, Target_Path, Link_Path);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Create_Symlink;

   function Read_At
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Natural;
      Data        : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Read_At
        (Session, Remote_Path, Offset, Length, Data);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Data);
         return CryptoLib.Errors.Internal_Error;
   end Read_At;

   function Write_At
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Offset      : Interfaces.Unsigned_64;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644")
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Write_At
        (Session, Remote_Path, Offset, Data, Mode);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Write_At;

   function FStat
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : out SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.FStat (Session, Remote_Path, Attributes);
   exception
      when others =>
         Attributes := (others => <>);
         return CryptoLib.Errors.Internal_Error;
   end FStat;

   function Set_Handle_Permissions
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Mode        : String)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Set_Handle_Permissions
        (Session, Remote_Path, Mode);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Set_Handle_Permissions;

   function Set_Handle_Attributes
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Attributes  : SSH_Lib.SFTP.File_Attributes)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Set_Handle_Attributes
        (Session, Remote_Path, Attributes);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Set_Handle_Attributes;

   function Fsync
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Fsync (Session, Remote_Path);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Fsync;

   function Expand_Path
     (Session       : in out SSH_Lib.Sessions.Session;
      Remote_Path   : String;
      Expanded_Path : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Expand_Path (Session, Remote_Path, Expanded_Path);
   exception
      when others =>
         Expanded_Path := Null_Unbounded_String;
         return CryptoLib.Errors.Internal_Error;
   end Expand_Path;

   function Check_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Algorithms  : String;
      Offset      : Interfaces.Unsigned_64;
      Length      : Interfaces.Unsigned_64;
      Block_Size  : Interfaces.Unsigned_32;
      Algorithm   : out Ada.Strings.Unbounded.Unbounded_String;
      Digest      : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Check_File
        (Session, Remote_Path, Algorithms, Offset, Length, Block_Size,
         Algorithm, Digest);
   exception
      when others =>
         Algorithm := Null_Unbounded_String;
         SSH_Lib.Protocol.Buffers.Clear (Digest);
         return CryptoLib.Errors.Internal_Error;
   end Check_File;

   function Sync_Directory
     (Session        : in out SSH_Lib.Sessions.Session;
      Direction      : SSH_Lib.SFTP.Sync_Direction;
      Remote_Path    : String;
      Local_Path     : String;
      Directory_Mode : String := "0755";
      File_Mode      : String := "0644";
      Options        : SSH_Lib.SFTP.Sync_Options :=
        SSH_Lib.SFTP.Default_Sync_Options)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Sync_Directory
        (Session, Direction, Remote_Path, Local_Path,
         Directory_Mode, File_Mode, Options);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Sync_Directory;

   function Copy_File_Range
     (Session            : in out SSH_Lib.Sessions.Session;
      Source_Remote_Path : String;
      Target_Remote_Path : String;
      Source_Offset      : Interfaces.Unsigned_64;
      Length             : Interfaces.Unsigned_64;
      Target_Offset      : Interfaces.Unsigned_64 := 0;
      Mode               : String := "0644")
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.SFTP.Copy_File_Range
        (Session, Source_Remote_Path, Target_Remote_Path,
         Source_Offset, Length, Target_Offset, Mode);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Copy_File_Range;
end SSH_Lib.File_Transfer;
