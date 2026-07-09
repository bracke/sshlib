with Ada.Streams; use Ada.Streams;
with Ada.Characters.Handling;
with Ada.Text_IO;
with CryptoLib.Constant_Time;
with CryptoLib.Fingerprints;

package body SSH_Lib.Keys is
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;

   Max_Public_Identity_Line_Length : constant Natural := 16 * 1024;

   function Is_Space (Value : Character) return Boolean is
   begin
      return Value = ' ' or else Value = Character'Val (9);
   end Is_Space;

   function Is_Base64_Character (Value : Character) return Boolean is
   begin
      return (Value >= 'A' and then Value <= 'Z')
        or else (Value >= 'a' and then Value <= 'z')
        or else (Value >= '0' and then Value <= '9')
        or else Value = '+'
        or else Value = '/'
        or else Value = '=';
   end Is_Base64_Character;

   function Public_Key_Kind_For (Algorithm_Name : String) return Public_Key_Algorithm is
   begin
      if Algorithm_Name = "ssh-rsa" then
         return Ssh_Rsa;
      elsif Algorithm_Name = "rsa-sha2-256" then
         return Rsa_Sha2_256;
      elsif Algorithm_Name = "rsa-sha2-512" then
         return Rsa_Sha2_512;
      elsif Algorithm_Name = "ssh-ed25519" then
         return Ssh_Ed25519;
      elsif Algorithm_Name = "ecdsa-sha2-nistp256" then
         return Ecdsa_Sha2_Nistp256;
      elsif Algorithm_Name = "ecdsa-sha2-nistp384" then
         return Ecdsa_Sha2_Nistp384;
      elsif Algorithm_Name = "ecdsa-sha2-nistp521" then
         return Ecdsa_Sha2_Nistp521;
      elsif Algorithm_Name = "sk-ssh-ed25519@openssh.com" then
         return Sk_Ssh_Ed25519;
      elsif Algorithm_Name = "sk-ecdsa-sha2-nistp256@openssh.com" then
         return Sk_Ecdsa_Sha2_Nistp256;
      else
         return Unknown;
      end if;
   end Public_Key_Kind_For;

   function Valid_Public_Key_Text
     (Value          : String;
      Algorithm_Name : out Unbounded_String;
      Encoded_Key    : out Unbounded_String)
      return Boolean
   is
      Cursor       : Natural := Value'First;
      First_Alg    : Natural;
      Last_Alg     : Natural;
      First_Key    : Natural;
      Last_Key     : Natural;
      Padding_Seen : Boolean := False;
   begin
      Algorithm_Name := Null_Unbounded_String;
      Encoded_Key := Null_Unbounded_String;

      if Value'Length = 0 or else Value'Length > Max_Public_Identity_Line_Length then
         return False;
      end if;

      while Cursor <= Value'Last and then Is_Space (Value (Cursor)) loop
         Cursor := Cursor + 1;
      end loop;
      if Cursor > Value'Last then
         return False;
      end if;

      First_Alg := Cursor;
      while Cursor <= Value'Last and then not Is_Space (Value (Cursor)) loop
         Cursor := Cursor + 1;
      end loop;
      Last_Alg := Cursor - 1;

      while Cursor <= Value'Last and then Is_Space (Value (Cursor)) loop
         Cursor := Cursor + 1;
      end loop;
      if Cursor > Value'Last then
         return False;
      end if;

      First_Key := Cursor;
      while Cursor <= Value'Last and then not Is_Space (Value (Cursor)) loop
         if not Is_Base64_Character (Value (Cursor)) then
            return False;
         end if;
         if Value (Cursor) = '=' then
            Padding_Seen := True;
         elsif Padding_Seen then
            return False;
         end if;
         Cursor := Cursor + 1;
      end loop;
      Last_Key := Cursor - 1;

      if Last_Alg < First_Alg or else Last_Key < First_Key then
         return False;
      end if;
      declare
         Key_Length : constant Natural := Last_Key - First_Key + 1;
      begin
         if Padding_Seen and then Key_Length mod 4 /= 0 then
            return False;
         elsif (not Padding_Seen) and then Key_Length mod 4 = 1 then
            return False;
         end if;
      end;

      declare
         Alg_Text : constant String := Value (First_Alg .. Last_Alg);
         Key_Text : constant String := Value (First_Key .. Last_Key);
      begin
         if Public_Key_Kind_For (Alg_Text) = Unknown then
            return False;
         end if;
         if Key_Text'Length < 8 then
            return False;
         end if;
         Algorithm_Name := To_Unbounded_String (Alg_Text);
         Encoded_Key := To_Unbounded_String (Key_Text);
      end;

      return True;
   exception
      when others =>
         Algorithm_Name := Null_Unbounded_String;
         Encoded_Key := Null_Unbounded_String;
         return False;
   end Valid_Public_Key_Text;

   function Load_Public_Identity
     (Path : String;
      Item : out Identity)
      return Status
   is
      File_Item : Ada.Text_IO.File_Type;
      Line_Text : Unbounded_String := Null_Unbounded_String;
      Algorithm_Name : Unbounded_String;
      Encoded_Key : Unbounded_String;
   begin
      Item.Kind := Unknown;
      Item.Text := Null_Unbounded_String;

      if Path'Length = 0 then
         return Authentication_Failed;
      end if;

      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Segment : constant String := Ada.Text_IO.Get_Line (File_Item);
         begin
            if Segment'Length > Max_Public_Identity_Line_Length then
               Ada.Text_IO.Close (File_Item);
               return Authentication_Failed;
            end if;
            if Segment'Length > 0 then
               Line_Text := To_Unbounded_String (Segment);
               exit;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);

      if not Valid_Public_Key_Text
        (To_String (Line_Text), Algorithm_Name, Encoded_Key)
      then
         return Authentication_Failed;
      end if;

      Item.Kind := Public_Key_Kind_For (To_String (Algorithm_Name));
      Item.Text := To_Unbounded_String
        (To_String (Algorithm_Name) & " " & To_String (Encoded_Key));
      return Ok;
   exception
      when Ada.Text_IO.Name_Error | Ada.Text_IO.Use_Error | Ada.Text_IO.Device_Error |
           Ada.Text_IO.Data_Error | Ada.Text_IO.End_Error | Constraint_Error =>
         begin
            if Ada.Text_IO.Is_Open (File_Item) then
               Ada.Text_IO.Close (File_Item);
            end if;
         exception
            when others =>
               null;
         end;
         Item.Kind := Unknown;
         Item.Text := Null_Unbounded_String;
         return Authentication_Failed;
      when others =>
         begin
            if Ada.Text_IO.Is_Open (File_Item) then
               Ada.Text_IO.Close (File_Item);
            end if;
         exception
            when others =>
               null;
         end;
         Item.Kind := Unknown;
         Item.Text := Null_Unbounded_String;
         return Internal_Error;
   end Load_Public_Identity;

   function Algorithm (Item : Identity) return Public_Key_Algorithm is
   begin
      return Item.Kind;
   end Algorithm;

   function Public_Text (Item : Identity) return String is
   begin
      return To_String (Item.Text);
   end Public_Text;

   function Algorithm (Item : Public_Key) return String is
   begin
      return To_String (Item.Algorithm_Text);
   end Algorithm;

   function Is_Valid (Item : Public_Key) return Boolean is
   begin
      return Item.Present;
   end Is_Valid;

   function SHA256_Fingerprint
     (Item  : Public_Key;
      Value : out Fingerprint)
      return Status
   is
      Status_Value : Status;
   begin
      Value.Text := Null_Unbounded_String;
      if not Item.Present then
         return Handshake_Failed;
      end if;

      declare
         Blob : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Item.Blob_Data);
      begin
         Status_Value := CryptoLib.Fingerprints.SHA256_OpenSSH
           (Blob, Value.Text);
      end;
      return Status_Value;
   exception
      when others =>
         Value.Text := Null_Unbounded_String;
         return Internal_Error;
   end SHA256_Fingerprint;

   function MD5_Fingerprint
     (Item  : Public_Key;
      Value : out Fingerprint)
      return Status
   is
      Status_Value : Status;
   begin
      Value.Text := Null_Unbounded_String;
      if not Item.Present then
         return Handshake_Failed;
      end if;

      declare
         Blob : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Item.Blob_Data);
      begin
         Status_Value := CryptoLib.Fingerprints.MD5_OpenSSH
           (Blob, Value.Text);
      end;
      return Status_Value;
   exception
      when others =>
         Value.Text := Null_Unbounded_String;
         return Internal_Error;
   end MD5_Fingerprint;

   function Fingerprint_With_Hash
     (Item      : Public_Key;
      Hash_Name : String;
      Value     : out Fingerprint)
      return Status
   is
      Lower_Name : constant String :=
        Ada.Characters.Handling.To_Lower (Hash_Name);
   begin
      if Lower_Name'Length = 0 or else Lower_Name = "sha256" then
         return SHA256_Fingerprint (Item, Value);
      elsif Lower_Name = "md5" then
         return MD5_Fingerprint (Item, Value);
      end if;

      Value.Text := Null_Unbounded_String;
      return Invalid_Command;
   exception
      when others =>
         Value.Text := Null_Unbounded_String;
         return Internal_Error;
   end Fingerprint_With_Hash;

   function Image (Item : Fingerprint) return String is
   begin
      return To_String (Item.Text);
   end Image;

   function Equal
     (Left_Item  : Fingerprint;
      Right_Item : Fingerprint)
      return Boolean
   is
      Left_Text  : constant String := To_String (Left_Item.Text);
      Right_Text : constant String := To_String (Right_Item.Text);

      function To_Bytes (Value : String) return Ada.Streams.Stream_Element_Array is
         Result : Ada.Streams.Stream_Element_Array
           (Ada.Streams.Stream_Element_Offset'(1) ..
            Ada.Streams.Stream_Element_Offset (Value'Length));
         Cursor : Ada.Streams.Stream_Element_Offset := Result'First;
      begin
         for Character_Value of Value loop
            Result (Cursor) := Ada.Streams.Stream_Element
              (Character'Pos (Character_Value));
            Cursor := Cursor + 1;
         end loop;
         return Result;
      end To_Bytes;
   begin
      if Left_Text'Length = 0 or else Right_Text'Length = 0 then
         return False;
      end if;

      return CryptoLib.Constant_Time.Equal
        (To_Bytes (Left_Text), To_Bytes (Right_Text));
   exception
      when others =>
         return False;
   end Equal;

end SSH_Lib.Keys;
