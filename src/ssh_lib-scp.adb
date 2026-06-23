with Ada.Directories;
with Ada.Streams.Stream_IO;
with SSH_Lib.Protocol.Channels;

package body SSH_Lib.SCP is
   use Ada.Strings.Unbounded;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type Ada.Streams.Stream_IO.Count;
   use type Ada.Directories.File_Kind;
   use type CryptoLib.Errors.Status;

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

   function Local_File_Ready
     (Local_Path : String; Size : out Natural) return CryptoLib.Errors.Status
   is
      Size_Value : Ada.Streams.Stream_IO.Count;
   begin
      Size := 0;
      if Local_Path'Length = 0
        or else not Ada.Directories.Exists (Local_Path)
        or else
          Ada.Directories.Kind (Local_Path) /= Ada.Directories.Ordinary_File
      then
         return CryptoLib.Errors.Read_Failed;
      end if;

      declare
         File_Item : Ada.Streams.Stream_IO.File_Type;
      begin
         Ada.Streams.Stream_IO.Open
           (File_Item, Ada.Streams.Stream_IO.In_File, Local_Path);
         Size_Value := Ada.Streams.Stream_IO.Size (File_Item);
         Ada.Streams.Stream_IO.Close (File_Item);
      exception
         when others =>
            if Ada.Streams.Stream_IO.Is_Open (File_Item) then
               Ada.Streams.Stream_IO.Close (File_Item);
            end if;
            return CryptoLib.Errors.Read_Failed;
      end;

      if Size_Value > Ada.Streams.Stream_IO.Count (Natural'Last) then
         return CryptoLib.Errors.Read_Failed;
      end if;

      Size := Natural (Size_Value);
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Size := 0;
         return CryptoLib.Errors.Read_Failed;
   end Local_File_Ready;

   function To_Stream (Value : String) return Ada.Streams.Stream_Element_Array
   is
      Result :
        Ada.Streams.Stream_Element_Array
          (Ada.Streams.Stream_Element_Offset'(1)
           .. Ada.Streams.Stream_Element_Offset (Value'Length));
      Cursor : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      for Character_Value of Value loop
         Result (Cursor) :=
           Ada.Streams.Stream_Element (Character'Pos (Character_Value));
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end To_Stream;

   function Build_File_Frame
     (File_Name : String;
      Size      : Natural;
      Mode      : String;
      Data      : Ada.Streams.Stream_Element_Array;
      Frame     : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
      Header_Text  : Unbounded_String;
      Status_Value : CryptoLib.Errors.Status;
   begin
      if Data'Length /= Size then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value := Build_File_Header (File_Name, Size, Mode, Header_Text);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      declare
         Header_Data : constant Ada.Streams.Stream_Element_Array :=
           To_Stream (To_String (Header_Text));
         Cursor      : Ada.Streams.Stream_Element_Offset := Frame'First;
      begin
         if Frame'Length /= Header_Data'Length + Data'Length + 1 then
            return CryptoLib.Errors.Invalid_Command;
         end if;

         for Byte_Value of Header_Data loop
            Frame (Cursor) := Byte_Value;
            Cursor := Cursor + 1;
         end loop;
         for Byte_Value of Data loop
            Frame (Cursor) := Byte_Value;
            Cursor := Cursor + 1;
         end loop;
         Frame (Cursor) := 0;
      end;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         return CryptoLib.Errors.Invalid_Command;
   end Build_File_Frame;

   function Read_Ack
     (Channel : in out SSH_Lib.Channels.Channel) return CryptoLib.Errors.Status
   is
      Buffer       : Ada.Streams.Stream_Element_Array (1 .. 1);
      Last         : Ada.Streams.Stream_Element_Offset;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.Channels.Read_Some (Channel, Buffer, Last);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      elsif Last /= Buffer'First then
         return CryptoLib.Errors.Read_Failed;
      elsif Buffer (Buffer'First) /= 0 then
         return CryptoLib.Errors.Write_Failed;
      else
         return CryptoLib.Errors.Ok;
      end if;
   exception
      when others =>
         return CryptoLib.Errors.Read_Failed;
   end Read_Ack;

   function Safe_Remote_Path (Remote_Path : String) return Boolean is
   begin
      if Remote_Path'Length = 0
        or else Remote_Path'Length > Maximum_Remote_Path_Length
      then
         return False;
      end if;

      for Path_Character of Remote_Path loop
         if Path_Character = Character'Val (0)
           or else Path_Character = Character'Val (10)
           or else Path_Character = Character'Val (13)
         then
            return False;
         end if;
      end loop;

      return True;
   end Safe_Remote_Path;

   function Safe_File_Name (File_Name : String) return Boolean is
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
   end Safe_File_Name;

   function Safe_Mode (Mode : String) return Boolean is
   begin
      if Mode'Length /= 4 then
         return False;
      end if;

      for Mode_Character of Mode loop
         if Mode_Character not in '0' .. '7' then
            return False;
         end if;
      end loop;

      return True;
   end Safe_Mode;

   function Quote_For_Remote_Command
     (Remote_Path : String; Quoted_Text : out Unbounded_String)
      return CryptoLib.Errors.Status is
   begin
      Quoted_Text := Null_Unbounded_String;

      if not Safe_Remote_Path (Remote_Path) then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Append (Quoted_Text, "'");
      for Path_Character of Remote_Path loop
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

   function Build_Upload_Command
     (Remote_Path : String; Command : out Unbounded_String)
      return CryptoLib.Errors.Status
   is
      Quoted_Text  : Unbounded_String;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Command := Null_Unbounded_String;
      Status_Value := Quote_For_Remote_Command (Remote_Path, Quoted_Text);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      declare
         Candidate : constant String := "scp -t -- " & To_String (Quoted_Text);
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
   end Build_Upload_Command;

   function Build_File_Header
     (File_Name : String;
      Size      : Natural;
      Mode      : String;
      Header    : out Unbounded_String) return CryptoLib.Errors.Status
   is
      Size_Image : constant String := Natural'Image (Size);
   begin
      Header := Null_Unbounded_String;

      if not Safe_File_Name (File_Name) or else not Safe_Mode (Mode) then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Header :=
        To_Unbounded_String
          ("C"
           & Mode
           & " "
           & Size_Image (Size_Image'First + 1 .. Size_Image'Last)
           & " "
           & File_Name
           & Character'Val (10));
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Header := Null_Unbounded_String;
         return CryptoLib.Errors.Invalid_Command;
   end Build_File_Header;

   function Write_String
     (Channel : in out SSH_Lib.Channels.Channel; Value : String)
      return CryptoLib.Errors.Status is
   begin
      return SSH_Lib.Channels.Write (Channel, To_Stream (Value));
   exception
      when others =>
         return CryptoLib.Errors.Write_Failed;
   end Write_String;

   function Upload_File_Stream
     (Channel    : in out SSH_Lib.Channels.Channel;
      Local_Path : String;
      File_Name  : String;
      Size       : Natural;
      Mode       : String) return CryptoLib.Errors.Status
   is
      Header_Text  : Unbounded_String;
      Status_Value : CryptoLib.Errors.Status;
      File_Item    : Ada.Streams.Stream_IO.File_Type;
      Remaining    : Natural := Size;
      Terminator   : constant Ada.Streams.Stream_Element_Array (1 .. 1) :=
        [1 => 0];
   begin
      Status_Value := Build_File_Header (File_Name, Size, Mode, Header_Text);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Ada.Streams.Stream_IO.Open
        (File_Item, Ada.Streams.Stream_IO.In_File, Local_Path);

      Status_Value := Read_Ack (Channel);
      if Status_Value /= CryptoLib.Errors.Ok then
         Ada.Streams.Stream_IO.Close (File_Item);
         return Status_Value;
      end if;

      Status_Value := Write_String (Channel, To_String (Header_Text));
      if Status_Value /= CryptoLib.Errors.Ok then
         Ada.Streams.Stream_IO.Close (File_Item);
         return Status_Value;
      end if;

      while Remaining > 0 loop
         declare
            Read_Count : constant Natural :=
              (if Remaining < Upload_Chunk_Size
               then Remaining
               else Upload_Chunk_Size);
            Buffer     :
              Ada.Streams.Stream_Element_Array
                (1 .. Ada.Streams.Stream_Element_Offset (Read_Count));
            Last       : Ada.Streams.Stream_Element_Offset;
         begin
            Ada.Streams.Stream_IO.Read (File_Item, Buffer, Last);
            if Last /= Buffer'Last then
               Ada.Streams.Stream_IO.Close (File_Item);
               return CryptoLib.Errors.Read_Failed;
            end if;

            Status_Value := SSH_Lib.Channels.Write (Channel, Buffer);
            if Status_Value /= CryptoLib.Errors.Ok then
               Ada.Streams.Stream_IO.Close (File_Item);
               return Status_Value;
            end if;
            Remaining := Remaining - Read_Count;
         end;
      end loop;

      Ada.Streams.Stream_IO.Close (File_Item);

      Status_Value := SSH_Lib.Channels.Write (Channel, Terminator);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value := Read_Ack (Channel);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      return SSH_Lib.Channels.Send_EOF (Channel);
   exception
      when others =>
         if Ada.Streams.Stream_IO.Is_Open (File_Item) then
            Ada.Streams.Stream_IO.Close (File_Item);
         end if;
         return CryptoLib.Errors.Read_Failed;
   end Upload_File_Stream;

   function Upload_Data
     (Channel   : in out SSH_Lib.Channels.Channel;
      File_Name : String;
      Data      : Ada.Streams.Stream_Element_Array;
      Mode      : String := "0644") return CryptoLib.Errors.Status
   is
      Header_Text  : Unbounded_String;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value :=
        Build_File_Header (File_Name, Data'Length, Mode, Header_Text);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value := Read_Ack (Channel);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      declare
         Frame :
           Ada.Streams.Stream_Element_Array
             (1
              ..
                Ada.Streams.Stream_Element_Offset
                  (Length (Header_Text) + Data'Length + 1));
      begin
         Status_Value :=
           Build_File_Frame (File_Name, Data'Length, Mode, Data, Frame);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;

         Status_Value := SSH_Lib.Channels.Write (Channel, Frame);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
      end;

      Status_Value := Read_Ack (Channel);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      return SSH_Lib.Channels.Send_EOF (Channel);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Upload_Data;

   function Upload_Data
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      File_Name   : String;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644") return CryptoLib.Errors.Status
   is
      Command_Text : Unbounded_String;
      Header_Text  : Unbounded_String;
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
   begin
      Status_Value :=
        Build_File_Header (File_Name, Data'Length, Mode, Header_Text);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value := Build_Upload_Command (Remote_Path, Command_Text);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Channels.Open_Exec
          (Session, To_String (Command_Text), Channel_Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;

      Status_Value := Upload_Data (Channel_Item, File_Name, Data, Mode);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      else
         return Close_Status;
      end if;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Upload_Data;

   function Upload_File
     (Channel    : in out SSH_Lib.Channels.Channel;
      Local_Path : String;
      Mode       : String := "0644") return CryptoLib.Errors.Status is
   begin
      return
        Upload_File (Channel, Local_Path, Local_File_Name (Local_Path), Mode);
   end Upload_File;

   function Upload_File
     (Channel    : in out SSH_Lib.Channels.Channel;
      Local_Path : String;
      File_Name  : String;
      Mode       : String := "0644") return CryptoLib.Errors.Status
   is
      Header_Text  : Unbounded_String;
      Size_Value   : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := Build_File_Header (File_Name, 0, Mode, Header_Text);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value := Local_File_Ready (Local_Path, Size_Value);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      return
        Upload_File_Stream (Channel, Local_Path, File_Name, Size_Value, Mode);
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Upload_File;

   function Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644") return CryptoLib.Errors.Status is
   begin
      return
        Upload_File
          (Session,
           Remote_Path,
           Local_Path,
           Local_File_Name (Local_Path),
           Mode);
   end Upload_File;

   function Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      File_Name   : String;
      Mode        : String := "0644") return CryptoLib.Errors.Status
   is
      Command_Text : Unbounded_String;
      Header_Text  : Unbounded_String;
      Channel_Item : SSH_Lib.Channels.Channel;
      Size_Value   : Natural := 0;
      Status_Value : CryptoLib.Errors.Status;
      Close_Status : CryptoLib.Errors.Status;
      Opened       : Boolean := False;
   begin
      Status_Value := Build_File_Header (File_Name, 0, Mode, Header_Text);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value := Build_Upload_Command (Remote_Path, Command_Text);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value := Local_File_Ready (Local_Path, Size_Value);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Channels.Open_Exec
          (Session, To_String (Command_Text), Channel_Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;
      Opened := True;

      Status_Value :=
        Upload_File_Stream
          (Channel_Item, Local_Path, File_Name, Size_Value, Mode);
      Close_Status := SSH_Lib.Channels.Close (Channel_Item);
      Opened := False;
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      else
         return Close_Status;
      end if;
   exception
      when others =>
         if Opened then
            Close_Status := SSH_Lib.Channels.Close (Channel_Item);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Upload_File;
end SSH_Lib.SCP;
