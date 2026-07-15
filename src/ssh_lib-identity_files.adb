with Hostkit.Fs;
with Ada.Directories;
with Ada.Streams.Stream_IO;
with Ada.Text_IO;
with Interfaces;
with SSH_Lib.Protocol.Certificates;
with SSH_Lib.Protocol.Numbers;
with CryptoLib.BCrypt_PBKDF;
with CryptoLib.Ciphers;
with SSH_Lib.ECDSA;
with CryptoLib.Macs;

package body SSH_Lib.Identity_Files is
   use Ada.Streams;
   use type Ada.Streams.Stream_IO.Count;
   use Ada.Strings.Unbounded;
   use Interfaces;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;

   OpenSSH_Begin : constant String := "-----BEGIN OPENSSH PRIVATE KEY-----";
   OpenSSH_End   : constant String := "-----END OPENSSH PRIVATE KEY-----";

   Max_OpenSSH_BCrypt_Salt_Length : constant Natural :=
     CryptoLib.BCrypt_PBKDF.Max_Salt_Length;
   Max_OpenSSH_BCrypt_Rounds      : constant Unsigned_32 :=
     CryptoLib.BCrypt_PBKDF.Max_Rounds;
   Max_OpenSSH_BCrypt_Output_Size : constant Natural :=
     CryptoLib.BCrypt_PBKDF.Max_Output_Length;

   procedure Clear (Item : out Identity_Key) is
   begin
      Item.Key_Type := No_Key;
      Item.Algorithm := Null_Unbounded_String;
      SSH_Lib.Protocol.Buffers.Clear (Item.Public_Blob);
      SSH_Lib.Protocol.Buffers.Clear (Item.Ed25519_Seed);
      SSH_Lib.Protocol.Buffers.Clear (Item.Ed25519_Public);
      SSH_Lib.Protocol.Buffers.Clear (Item.RSA_Exponent);
      SSH_Lib.Protocol.Buffers.Clear (Item.RSA_Modulus);
      SSH_Lib.Protocol.Buffers.Clear (Item.RSA_Private_Exponent);
      SSH_Lib.Protocol.Buffers.Clear (Item.RSA_Prime_P);
      SSH_Lib.Protocol.Buffers.Clear (Item.RSA_Prime_Q);
      SSH_Lib.Protocol.Buffers.Clear (Item.RSA_Exponent_DMP1);
      SSH_Lib.Protocol.Buffers.Clear (Item.RSA_Exponent_DMQ1);
      SSH_Lib.Protocol.Buffers.Clear (Item.RSA_Coefficient_IQMP);
      SSH_Lib.Protocol.Buffers.Clear (Item.ECDSA_Curve);
      SSH_Lib.Protocol.Buffers.Clear (Item.ECDSA_Public);
      SSH_Lib.Protocol.Buffers.Clear (Item.ECDSA_Private);
      Item.Has_Certificate := False;
      Item.Certificate_Algorithm := Null_Unbounded_String;
      SSH_Lib.Protocol.Buffers.Clear (Item.Certificate_Blob);
   end Clear;

   function Kind (Item : Identity_Key) return Key_Kind is
   begin
      return Item.Key_Type;
   end Kind;

   function Algorithm_Name (Item : Identity_Key) return String is
   begin
      return To_String (Item.Algorithm);
   end Algorithm_Name;

   function Has_Public_Certificate (Item : Identity_Key) return Boolean is
   begin
      return
        Item.Has_Certificate
        and then Length (Item.Certificate_Blob) > 0
        and then Length (Item.Certificate_Algorithm) > 0;
   exception
      when others =>
         return False;
   end Has_Public_Certificate;

   function Certificate_Algorithm_Name (Item : Identity_Key) return String is
   begin
      if Has_Public_Certificate (Item) then
         return To_String (Item.Certificate_Algorithm);
      else
         return "";
      end if;
   exception
      when others =>
         return "";
   end Certificate_Algorithm_Name;

   function Certificate_Public_Key_Blob
     (Item : Identity_Key) return Stream_Element_Array is
   begin
      if Has_Public_Certificate (Item) then
         return To_Array (Item.Certificate_Blob);
      else
         declare
            Empty : constant Stream_Element_Array (1 .. 0) := [others => 0];
         begin
            return Empty;
         end;
      end if;
   exception
      when others =>
         declare
            Empty : constant Stream_Element_Array (1 .. 0) := [others => 0];
         begin
            return Empty;
         end;
   end Certificate_Public_Key_Blob;

   function Public_Key_Blob (Item : Identity_Key) return Stream_Element_Array
   is
   begin
      return To_Array (Item.Public_Blob);
   end Public_Key_Blob;

   function Contains_Text (Text : String; Needle : String) return Boolean is
   begin
      if Needle'Length = 0 then
         return True;
      end if;
      if Text'Length < Needle'Length then
         return False;
      end if;
      for Index_Value in Text'First .. Text'Last - Needle'Length + 1 loop
         if Text (Index_Value .. Index_Value + Needle'Length - 1) = Needle then
            return True;
         end if;
      end loop;
      return False;
   end Contains_Text;

   function Is_Legacy_PEM_Armor (Text : String) return Boolean is
   begin
      return
        Contains_Text (Text, "-----BEGIN RSA PRIVATE KEY-----")
        or else Contains_Text (Text, "-----BEGIN EC PRIVATE KEY-----")
        or else Contains_Text (Text, "-----BEGIN PRIVATE KEY-----")
        or else Contains_Text (Text, "-----BEGIN ENCRYPTED PRIVATE KEY-----");
   end Is_Legacy_PEM_Armor;

   function Is_Encrypted_PEM_Armor (Text : String) return Boolean is
   begin
      return
        Contains_Text (Text, "-----BEGIN ENCRYPTED PRIVATE KEY-----")
        or else Contains_Text (Text, "Proc-Type: 4,ENCRYPTED")
        or else Contains_Text (Text, "DEK-Info:");
   end Is_Encrypted_PEM_Armor;

   function Contains_Line (Text : String; Line : String) return Boolean is
      Cursor     : Positive := Text'First;
      Line_Start : Positive;
      Line_Stop  : Natural;
   begin
      if Text'Length = 0 then
         return False;
      end if;

      while Cursor <= Text'Last loop
         Line_Start := Cursor;
         Line_Stop := Cursor - 1;
         while Cursor <= Text'Last
           and then Text (Cursor) /= Character'Val (10)
           and then Text (Cursor) /= Character'Val (13)
         loop
            Line_Stop := Cursor;
            Cursor := Cursor + 1;
         end loop;

         if Line_Stop >= Line_Start
           and then Text (Line_Start .. Line_Stop) = Line
         then
            return True;
         end if;

         if Cursor <= Text'Last then
            declare
               First_EOL : constant Character := Text (Cursor);
            begin
               Cursor := Cursor + 1;
               if Cursor <= Text'Last
                 and then
                   ((First_EOL = Character'Val (13)
                     and then Text (Cursor) = Character'Val (10))
                    or else
                    (First_EOL = Character'Val (10)
                     and then Text (Cursor) = Character'Val (13)))
               then
                  Cursor := Cursor + 1;
               end if;
            end;
         end if;
      end loop;
      return False;
   end Contains_Line;

   function Is_Base64_Char (Value : Character) return Boolean is
   begin
      return
        (Value >= 'A' and then Value <= 'Z')
        or else (Value >= 'a' and then Value <= 'z')
        or else (Value >= '0' and then Value <= '9')
        or else Value = '+'
        or else Value = '/'
        or else Value = '=';
   end Is_Base64_Char;

   function Base64_Value (Value : Character; Data : out Natural) return Boolean
   is
   begin
      if Value >= 'A' and then Value <= 'Z' then
         Data := Character'Pos (Value) - Character'Pos ('A');
         return True;
      elsif Value >= 'a' and then Value <= 'z' then
         Data := 26 + Character'Pos (Value) - Character'Pos ('a');
         return True;
      elsif Value >= '0' and then Value <= '9' then
         Data := 52 + Character'Pos (Value) - Character'Pos ('0');
         return True;
      elsif Value = '+' then
         Data := 62;
         return True;
      elsif Value = '/' then
         Data := 63;
         return True;
      else
         Data := 0;
         return False;
      end if;
   end Base64_Value;

   function Extract_OpenSSH_Base64
     (Text : String; Encoded : out Unbounded_String) return Status
   is
      Cursor     : Positive := Text'First;
      Line_Start : Positive;
      Line_Stop  : Natural;
      In_Body    : Boolean := False;
      Saw_End    : Boolean := False;
   begin
      Encoded := Null_Unbounded_String;
      if Text'Length = 0 then
         return Authentication_Failed;
      end if;

      while Cursor <= Text'Last loop
         Line_Start := Cursor;
         Line_Stop := Cursor - 1;
         while Cursor <= Text'Last
           and then Text (Cursor) /= Character'Val (10)
           and then Text (Cursor) /= Character'Val (13)
         loop
            Line_Stop := Cursor;
            Cursor := Cursor + 1;
         end loop;

         declare
            Line_Text : constant String :=
              (if Line_Stop >= Line_Start
               then Text (Line_Start .. Line_Stop)
               else "");
         begin
            if not In_Body then
               if Line_Text = OpenSSH_Begin then
                  In_Body := True;
               elsif Line_Text'Length /= 0 then
                  return Authentication_Failed;
               end if;
            else
               if Line_Text = OpenSSH_End then
                  Saw_End := True;
                  exit;
               elsif Line_Text'Length = 0 then
                  null;
               else
                  for Character_Value of Line_Text loop
                     if not Is_Base64_Char (Character_Value) then
                        return Authentication_Failed;
                     end if;
                     Append (Encoded, Character_Value);
                  end loop;
               end if;
            end if;
         end;

         if Cursor <= Text'Last then
            declare
               First_EOL : constant Character := Text (Cursor);
            begin
               Cursor := Cursor + 1;
               if Cursor <= Text'Last
                 and then
                   ((First_EOL = Character'Val (13)
                     and then Text (Cursor) = Character'Val (10))
                    or else
                    (First_EOL = Character'Val (10)
                     and then Text (Cursor) = Character'Val (13)))
               then
                  Cursor := Cursor + 1;
               end if;
            end;
         end if;
      end loop;

      if Saw_End then
         --  Only line terminators are accepted after the END marker.  Extra
         --  non-empty text after the footer is treated as corrupt armor rather
         --  than ignored.
         while Cursor <= Text'Last loop
            if Text (Cursor) /= Character'Val (10)
              and then Text (Cursor) /= Character'Val (13)
            then
               return Authentication_Failed;
            end if;
            Cursor := Cursor + 1;
         end loop;
      end if;

      if not In_Body or else not Saw_End or else Length (Encoded) = 0 then
         return Authentication_Failed;
      end if;
      return Ok;
   end Extract_OpenSSH_Base64;

   function Decode_Base64
     (Encoded : String; Decoded : out Packet_Buffer) return Status
   is
      Status_Value : Status;
      First_Value  : Natural;
      Second_Value : Natural;
      Third_Value  : Natural;
      Fourth_Value : Natural;
      Byte_Data    : Stream_Element_Array (1 .. 3);
      Index_Value  : Positive := Encoded'First;

      function Finish (Result : Status) return Status is
      begin
         if Result /= Ok then
            Clear (Decoded);
         end if;
         Byte_Data := [others => 0];
         return Result;
      end Finish;
   begin
      Clear (Decoded);
      if Encoded'Length = 0 or else Encoded'Length mod 4 /= 0 then
         return Finish (Authentication_Failed);
      end if;

      while Index_Value <= Encoded'Last loop
         if not Base64_Value (Encoded (Index_Value), First_Value)
           or else not Base64_Value (Encoded (Index_Value + 1), Second_Value)
         then
            return Finish (Authentication_Failed);
         end if;

         if Encoded (Index_Value + 2) = '=' then
            if Encoded (Index_Value + 3) /= '='
              or else Index_Value + 3 /= Encoded'Last
            then
               return Finish (Authentication_Failed);
            end if;
            --  RFC 4648 canonical padding: unused low bits must be zero.
            --  Rejecting non-canonical pad bits prevents multiple textual
            --  encodings from decoding to the same private-key bytes.
            if Second_Value mod 16 /= 0 then
               return Finish (Authentication_Failed);
            end if;
            Byte_Data (1) :=
              Stream_Element ((First_Value * 4) + (Second_Value / 16));
            Status_Value := Append (Decoded, Byte_Data (1 .. 1));
            if Status_Value /= Ok then
               return Finish (Status_Value);
            end if;
         elsif Encoded (Index_Value + 3) = '=' then
            if Index_Value + 3 /= Encoded'Last
              or else not Base64_Value (Encoded (Index_Value + 2), Third_Value)
            then
               return Finish (Authentication_Failed);
            end if;
            if Third_Value mod 4 /= 0 then
               return Finish (Authentication_Failed);
            end if;
            Byte_Data (1) :=
              Stream_Element ((First_Value * 4) + (Second_Value / 16));
            Byte_Data (2) :=
              Stream_Element
                (((Second_Value mod 16) * 16) + (Third_Value / 4));
            Status_Value := Append (Decoded, Byte_Data (1 .. 2));
            if Status_Value /= Ok then
               return Finish (Status_Value);
            end if;
         else
            if not Base64_Value (Encoded (Index_Value + 2), Third_Value)
              or else
                not Base64_Value (Encoded (Index_Value + 3), Fourth_Value)
            then
               return Finish (Authentication_Failed);
            end if;
            Byte_Data (1) :=
              Stream_Element ((First_Value * 4) + (Second_Value / 16));
            Byte_Data (2) :=
              Stream_Element
                (((Second_Value mod 16) * 16) + (Third_Value / 4));
            Byte_Data (3) :=
              Stream_Element (((Third_Value mod 4) * 64) + Fourth_Value);
            Status_Value := Append (Decoded, Byte_Data);
            if Status_Value /= Ok then
               return Finish (Status_Value);
            end if;
         end if;
         Index_Value := Index_Value + 4;
      end loop;
      return Finish (Ok);
   exception
      when others =>
         Clear (Decoded);
         return Finish (Internal_Error);
   end Decode_Base64;

   function Bytes_To_String (Data : Stream_Element_Array) return String is
      Result : String (1 .. Data'Length);
      Cursor : Positive := Result'First;
   begin
      for Byte_Value of Data loop
         if Byte_Value > 127 then
            return "";
         end if;
         Result (Cursor) := Character'Val (Natural (Byte_Value));
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end Bytes_To_String;

   function Is_Certificate_Algorithm_Name (Value : String) return Boolean is
   begin
      return
        Value = "ssh-ed25519-cert-v01@openssh.com"
        or else Value = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
        or else Value = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
        or else Value = "ecdsa-sha2-nistp521-cert-v01@openssh.com"
        or else Value = "rsa-sha2-512-cert-v01@openssh.com"
        or else Value = "rsa-sha2-256-cert-v01@openssh.com"
        or else Value = "ssh-rsa-cert-v01@openssh.com";
   exception
      when others =>
         return False;
   end Is_Certificate_Algorithm_Name;

   function Signing_Algorithm_Matches_Certificate
     (Key_Algorithm : String; Certificate_Algorithm : String) return Boolean is
   begin
      if Key_Algorithm = "ssh-ed25519" then
         return Certificate_Algorithm = "ssh-ed25519-cert-v01@openssh.com";
      elsif Key_Algorithm = "ecdsa-sha2-nistp256" then
         return
           Certificate_Algorithm = "ecdsa-sha2-nistp256-cert-v01@openssh.com";
      elsif Key_Algorithm = "ecdsa-sha2-nistp384" then
         return
           Certificate_Algorithm = "ecdsa-sha2-nistp384-cert-v01@openssh.com";
      elsif Key_Algorithm = "ecdsa-sha2-nistp521" then
         return
           Certificate_Algorithm = "ecdsa-sha2-nistp521-cert-v01@openssh.com";
      elsif Key_Algorithm = "ssh-rsa" then
         return
           Certificate_Algorithm = "rsa-sha2-512-cert-v01@openssh.com"
           or else Certificate_Algorithm = "rsa-sha2-256-cert-v01@openssh.com"
           or else Certificate_Algorithm = "ssh-rsa-cert-v01@openssh.com";
      else
         return False;
      end if;
   exception
      when others =>
         return False;
   end Signing_Algorithm_Matches_Certificate;

   function Is_ECDSA_Algorithm (Value : String) return Boolean is
   begin
      return
        Value = "ecdsa-sha2-nistp256"
        or else Value = "ecdsa-sha2-nistp384"
        or else Value = "ecdsa-sha2-nistp521";
   end Is_ECDSA_Algorithm;

   function ECDSA_Curve_Name (Algorithm_Name : String) return String is
   begin
      if Algorithm_Name = "ecdsa-sha2-nistp256" then
         return "nistp256";
      elsif Algorithm_Name = "ecdsa-sha2-nistp384" then
         return "nistp384";
      elsif Algorithm_Name = "ecdsa-sha2-nistp521" then
         return "nistp521";
      else
         return "";
      end if;
   end ECDSA_Curve_Name;

   function ECDSA_Public_Point_Length (Algorithm_Name : String) return Natural is
   begin
      if Algorithm_Name = "ecdsa-sha2-nistp256" then
         return 65;
      elsif Algorithm_Name = "ecdsa-sha2-nistp384" then
         return 97;
      elsif Algorithm_Name = "ecdsa-sha2-nistp521" then
         return 133;
      else
         return 0;
      end if;
   end ECDSA_Public_Point_Length;

   function Validate_ECDSA_Raw_Point
     (Algorithm_Name : String; Public_Point : Stream_Element_Array)
      return Status is
   begin
      if Algorithm_Name = "ecdsa-sha2-nistp256" then
         return SSH_Lib.ECDSA.Validate_Raw_Point_Nistp256 (Public_Point);
      elsif Algorithm_Name = "ecdsa-sha2-nistp384" then
         return SSH_Lib.ECDSA.Validate_Raw_Point_Nistp384 (Public_Point);
      elsif Algorithm_Name = "ecdsa-sha2-nistp521" then
         return SSH_Lib.ECDSA.Validate_Raw_Point_Nistp521 (Public_Point);
      else
         return Unsupported_Feature;
      end if;
   end Validate_ECDSA_Raw_Point;

   function ECDSA_Public_Matches_Private
     (Algorithm_Name       : String;
      Public_Key_Blob      : Stream_Element_Array;
      Private_Scalar_Mpint : Stream_Element_Array) return Status is
   begin
      if Algorithm_Name = "ecdsa-sha2-nistp256" then
         return
           SSH_Lib.ECDSA.Public_Matches_Private_Nistp256
             (Public_Key_Blob, Private_Scalar_Mpint);
      elsif Algorithm_Name = "ecdsa-sha2-nistp384" then
         return
           SSH_Lib.ECDSA.Public_Matches_Private_Nistp384
             (Public_Key_Blob, Private_Scalar_Mpint);
      elsif Algorithm_Name = "ecdsa-sha2-nistp521" then
         return
           SSH_Lib.ECDSA.Public_Matches_Private_Nistp521
             (Public_Key_Blob, Private_Scalar_Mpint);
      else
         return Unsupported_Feature;
      end if;
   end ECDSA_Public_Matches_Private;

   function ECDSA_Key_Kind_For (Algorithm_Name : String) return Key_Kind is
   begin
      if Algorithm_Name = "ecdsa-sha2-nistp256" then
         return ECDSA_Nistp256_Key;
      elsif Algorithm_Name = "ecdsa-sha2-nistp384" then
         return ECDSA_Nistp384_Key;
      elsif Algorithm_Name = "ecdsa-sha2-nistp521" then
         return ECDSA_Nistp521_Key;
      else
         return Unsupported_Key;
      end if;
   end ECDSA_Key_Kind_For;

   function Extract_Public_Line_Fields
     (Line_Text      : String;
      Algorithm_Text : out Unbounded_String;
      Encoded_Text   : out Unbounded_String) return Status
   is
      Cursor          : Natural := Line_Text'First;
      First_Algorithm : Natural;
      Last_Algorithm  : Natural;
      First_Encoded   : Natural;
      Last_Encoded    : Natural;
      Padding_Seen    : Boolean := False;
   begin
      Algorithm_Text := Null_Unbounded_String;
      Encoded_Text := Null_Unbounded_String;
      if Line_Text'Length = 0 then
         return Authentication_Failed;
      end if;
      while Cursor <= Line_Text'Last
        and then
          (Line_Text (Cursor) = ' '
           or else Line_Text (Cursor) = Character'Val (9))
      loop
         Cursor := Cursor + 1;
      end loop;
      if Cursor > Line_Text'Last then
         return Authentication_Failed;
      end if;
      First_Algorithm := Cursor;
      while Cursor <= Line_Text'Last
        and then Line_Text (Cursor) /= ' '
        and then Line_Text (Cursor) /= Character'Val (9)
      loop
         Cursor := Cursor + 1;
      end loop;
      Last_Algorithm := Cursor - 1;
      while Cursor <= Line_Text'Last
        and then
          (Line_Text (Cursor) = ' '
           or else Line_Text (Cursor) = Character'Val (9))
      loop
         Cursor := Cursor + 1;
      end loop;
      if Cursor > Line_Text'Last then
         return Authentication_Failed;
      end if;
      First_Encoded := Cursor;
      while Cursor <= Line_Text'Last
        and then Line_Text (Cursor) /= ' '
        and then Line_Text (Cursor) /= Character'Val (9)
      loop
         if not Is_Base64_Char (Line_Text (Cursor)) then
            return Authentication_Failed;
         end if;
         if Line_Text (Cursor) = '=' then
            Padding_Seen := True;
         elsif Padding_Seen then
            return Authentication_Failed;
         end if;
         Cursor := Cursor + 1;
      end loop;
      Last_Encoded := Cursor - 1;
      if Last_Algorithm < First_Algorithm or else Last_Encoded < First_Encoded
      then
         return Authentication_Failed;
      end if;
      declare
         Encoded_Length : constant Natural := Last_Encoded - First_Encoded + 1;
      begin
         if Encoded_Length mod 4 /= 0 then
            return Authentication_Failed;
         end if;
      end;
      Algorithm_Text :=
        To_Unbounded_String (Line_Text (First_Algorithm .. Last_Algorithm));
      Encoded_Text :=
        To_Unbounded_String (Line_Text (First_Encoded .. Last_Encoded));
      return Ok;
   exception
      when others =>
         Algorithm_Text := Null_Unbounded_String;
         Encoded_Text := Null_Unbounded_String;
         return Internal_Error;
   end Extract_Public_Line_Fields;

   function Attach_Public_Certificate
     (Path : String; Item : in out Identity_Key) return Status
   is
      File_Item        : Ada.Text_IO.File_Type;
      Algorithm_Text   : Unbounded_String;
      Encoded_Text     : Unbounded_String;
      Certificate_Data : Packet_Buffer;
      Name_Buffer      : Packet_Buffer;
      Next_Index       : Stream_Element_Offset;
      Status_Value     : Status;
   begin
      Item.Has_Certificate := False;
      Item.Certificate_Algorithm := Null_Unbounded_String;
      Clear (Item.Certificate_Blob);

      if Path'Length = 0 or else Item.Key_Type = No_Key then
         return Authentication_Failed;
      end if;

      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      if Ada.Text_IO.End_Of_File (File_Item) then
         Ada.Text_IO.Close (File_Item);
         return Authentication_Failed;
      end if;

      declare
         Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
      begin
         Ada.Text_IO.Close (File_Item);
         Status_Value :=
           Extract_Public_Line_Fields
             (Line_Text, Algorithm_Text, Encoded_Text);
      end;
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if not Is_Certificate_Algorithm_Name (To_String (Algorithm_Text))
        or else
          not Signing_Algorithm_Matches_Certificate
                (To_String (Item.Algorithm), To_String (Algorithm_Text))
      then
         return Authentication_Failed;
      end if;

      Status_Value :=
        Decode_Base64 (To_String (Encoded_Text), Certificate_Data);
      if Status_Value /= Ok then
         Clear (Certificate_Data);
         return Status_Value;
      end if;

      declare
         Certificate_Array : constant Stream_Element_Array :=
           To_Array (Certificate_Data);
      begin
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Certificate_Array,
              Certificate_Array'First,
              Name_Buffer,
              Next_Index);
      end;
      if Status_Value /= Ok then
         Clear (Certificate_Data);
         return Status_Value;
      end if;
      if Bytes_To_String (To_Array (Name_Buffer)) /= To_String (Algorithm_Text)
      then
         Clear (Certificate_Data);
         return Authentication_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Certificates.Certificate_Matches_Signing_Key
          (To_Array (Certificate_Data),
           To_String (Algorithm_Text),
           To_Array (Item.Public_Blob));
      if Status_Value /= Ok then
         Clear (Certificate_Data);
         return Status_Value;
      end if;

      Status_Value := Set (Item.Certificate_Blob, To_Array (Certificate_Data));
      Clear (Certificate_Data);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Item.Certificate_Algorithm := Algorithm_Text;
      Item.Has_Certificate := True;
      return Ok;
   exception
      when
        Ada.Text_IO.Name_Error
        | Ada.Text_IO.Use_Error
        | Ada.Text_IO.Device_Error
        | Ada.Text_IO.Data_Error
        | Ada.Text_IO.End_Error
        | Constraint_Error
      =>
         begin
            if Ada.Text_IO.Is_Open (File_Item) then
               Ada.Text_IO.Close (File_Item);
            end if;
         exception
            when others =>
               null;
         end;
         Item.Has_Certificate := False;
         Item.Certificate_Algorithm := Null_Unbounded_String;
         Clear (Item.Certificate_Blob);
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
         Item.Has_Certificate := False;
         Item.Certificate_Algorithm := Null_Unbounded_String;
         Clear (Item.Certificate_Blob);
         return Internal_Error;
   end Attach_Public_Certificate;

   function Same_Bytes
     (Left_Value : Stream_Element_Array; Right_Value : Stream_Element_Array)
      return Boolean is
   begin
      if Left_Value'Length /= Right_Value'Length then
         return False;
      end if;
      for Offset_Value in 0 .. Left_Value'Length - 1 loop
         if Left_Value
              (Left_Value'First + Stream_Element_Offset (Offset_Value))
           /= Right_Value
                (Right_Value'First + Stream_Element_Offset (Offset_Value))
         then
            return False;
         end if;
      end loop;
      return True;
   end Same_Bytes;

   function Cipher_Key_Length (Cipher_Name : String) return Natural is
   begin
      if Cipher_Name = "aes128-ctr" or else Cipher_Name = "aes128-cbc" then
         return 16;
      elsif Cipher_Name = "aes192-ctr" or else Cipher_Name = "aes192-cbc" then
         return 24;
      elsif Cipher_Name = "aes256-ctr" or else Cipher_Name = "aes256-cbc" then
         return 32;
      elsif Cipher_Name = "3des-cbc" then
         return 24;
      else
         return 0;
      end if;
   end Cipher_Key_Length;

   function Cipher_Block_Length (Cipher_Name : String) return Natural is
   begin
      if Cipher_Name = "3des-cbc" or else Cipher_Name = "des-cbc" then
         return 8;
      elsif Cipher_Key_Length (Cipher_Name) /= 0 then
         return 16;
      else
         return 0;
      end if;
   end Cipher_Block_Length;

   function Cipher_IV_Length (Cipher_Name : String) return Natural is
   begin
      return Cipher_Block_Length (Cipher_Name);
   end Cipher_IV_Length;

   function Is_OpenSSH_CBC_Cipher (Cipher_Name : String) return Boolean is
   begin
      return
        Cipher_Name = "aes128-cbc"
        or else Cipher_Name = "aes192-cbc"
        or else Cipher_Name = "aes256-cbc"
        or else Cipher_Name = "3des-cbc";
   end Is_OpenSSH_CBC_Cipher;

   function Decode_OpenSSH_BCrypt_KDF_Options
     (Data      : Stream_Element_Array;
      Salt_Data : out Packet_Buffer;
      Rounds    : out Unsigned_32) return Status
   is
      Cursor       : Stream_Element_Offset := Data'First;
      Next_Index   : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Clear (Salt_Data);
      Rounds := 0;
      if Data'Length = 0 then
         return Authentication_Failed;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Data, Cursor, Salt_Data, Next_Index);
      if Status_Value /= Ok or else Length (Salt_Data) = 0 then
         Clear (Salt_Data);
         return Authentication_Failed;
      end if;
      if Length (Salt_Data) > Max_OpenSSH_BCrypt_Salt_Length then
         Clear (Salt_Data);
         return Unsupported_Feature;
      end if;
      Cursor := Next_Index;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor, Rounds, Next_Index);
      if Status_Value /= Ok
        or else Next_Index /= Data'Last + 1
        or else Rounds = 0
      then
         Clear (Salt_Data);
         return Authentication_Failed;
      end if;
      if Rounds > Max_OpenSSH_BCrypt_Rounds then
         Clear (Salt_Data);
         Rounds := 0;
         return Unsupported_Feature;
      end if;
      return Ok;
   exception
      when others =>
         Clear (Salt_Data);
         Rounds := 0;
         return Internal_Error;
   end Decode_OpenSSH_BCrypt_KDF_Options;

   function Decrypt_OpenSSH_Encrypted_Section
     (Cipher_Name : String;
      Kdf_Options : Stream_Element_Array;
      Passphrase  : String;
      Ciphertext  : Stream_Element_Array;
      Plaintext   : out Packet_Buffer) return Status
   is
      Key_Length   : constant Natural := Cipher_Key_Length (Cipher_Name);
      IV_Length    : constant Natural := Cipher_IV_Length (Cipher_Name);
      Block_Length : constant Natural := Cipher_Block_Length (Cipher_Name);
      Salt_Buffer  : Packet_Buffer;
      Rounds       : Unsigned_32 := 0;
      Status_Value : Status;
   begin
      Clear (Plaintext);
      if Key_Length = 0 then
         return Unsupported_Feature;
      end if;
      if Ciphertext'Length = 0
        or else Block_Length = 0
        or else Ciphertext'Length mod Block_Length /= 0
      then
         return Authentication_Failed;
      end if;
      if Passphrase'Length = 0 then
         return Authentication_Failed;
      end if;
      Status_Value :=
        Decode_OpenSSH_BCrypt_KDF_Options (Kdf_Options, Salt_Buffer, Rounds);
      if Status_Value /= Ok then
         Clear (Salt_Buffer);
         return Status_Value;
      end if;

      --  OpenSSH encrypted private keys use bcrypt_pbkdf, not a generic
      --  SHA-2 stretcher.  Route through the dedicated Ada bcrypt_pbkdf
      --  implementation so this code cannot accidentally substitute PBKDF2
      --  or a SHA-only placeholder.
      declare
         Derived_Length : constant Natural := Key_Length + IV_Length;
         Derived_Data   :
           Stream_Element_Array
             (1 .. Stream_Element_Offset (Derived_Length)) := [others => 0];
         Key_Data       :
           Stream_Element_Array (1 .. Stream_Element_Offset (Key_Length)) :=
             [others => 0];
         IV_Data        :
           Stream_Element_Array (1 .. Stream_Element_Offset (IV_Length)) :=
             [others => 0];
         Decrypted_Data : Stream_Element_Array (Ciphertext'Range) :=
           [others => 0];
         Cipher_State   : CryptoLib.Ciphers.Cipher_State;
      begin
         if Derived_Length > Max_OpenSSH_BCrypt_Output_Size then
            Clear (Salt_Buffer);
            Derived_Data := [others => 0];
            Key_Data := [others => 0];
            IV_Data := [others => 0];
            Decrypted_Data := [others => 0];
            Clear (Plaintext);
            return Unsupported_Feature;
         end if;

         Status_Value :=
           CryptoLib.BCrypt_PBKDF.Derive
             (Passphrase => Passphrase,
              Salt_Data  => To_Array (Salt_Buffer),
              Rounds     => Rounds,
              Output     => Derived_Data);
         Clear (Salt_Buffer);
         if Status_Value /= Ok then
            Derived_Data := [others => 0];
            Key_Data := [others => 0];
            IV_Data := [others => 0];
            Decrypted_Data := [others => 0];
            Clear (Plaintext);
            return Status_Value;
         end if;

         for Offset_Value in 0 .. Key_Length - 1 loop
            Key_Data (Key_Data'First + Stream_Element_Offset (Offset_Value)) :=
              Derived_Data
                (Derived_Data'First + Stream_Element_Offset (Offset_Value));
         end loop;
         for Offset_Value in 0 .. IV_Length - 1 loop
            IV_Data (IV_Data'First + Stream_Element_Offset (Offset_Value)) :=
              Derived_Data
                (Derived_Data'First
                 + Stream_Element_Offset (Key_Length + Offset_Value));
         end loop;

         if Is_OpenSSH_CBC_Cipher (Cipher_Name) then
            Status_Value :=
              CryptoLib.Ciphers.Decrypt_CBC_Raw
                (Algorithm_Name => Cipher_Name,
                 Key_Data       => Key_Data,
                 IV_Data        => IV_Data,
                 Ciphertext     => Ciphertext,
                 Plaintext      => Decrypted_Data);
         else
            Status_Value :=
              CryptoLib.Ciphers.Initialize
                (Item           => Cipher_State,
                 Algorithm_Name => Cipher_Name,
                 Direction_Item => CryptoLib.Ciphers.Client_To_Server,
                 Key_Data       => Key_Data,
                 IV_Data        => IV_Data);
            if Status_Value = Ok then
               Status_Value :=
                 CryptoLib.Ciphers.Decrypt
                   (Cipher_State, Ciphertext, Decrypted_Data);
            end if;

            CryptoLib.Ciphers.Reset (Cipher_State);
         end if;
         Derived_Data := [others => 0];
         Key_Data := [others => 0];
         IV_Data := [others => 0];

         if Status_Value /= Ok then
            Decrypted_Data := [others => 0];
            Clear (Plaintext);
            return Status_Value;
         end if;

         Status_Value := Set (Plaintext, Decrypted_Data);
         Decrypted_Data := [others => 0];
         if Status_Value /= Ok then
            Clear (Plaintext);
            return Status_Value;
         end if;
      end;

      return Ok;
   exception
      when others =>
         Clear (Plaintext);
         Clear (Salt_Buffer);
         return Internal_Error;
   end Decrypt_OpenSSH_Encrypted_Section;

   function Parse_OpenSSH_Binary
     (Data       : Stream_Element_Array;
      Passphrase : String;
      Item       : out Identity_Key) return Status
   is
      Magic                : constant Stream_Element_Array :=
        [1  => Character'Pos ('o'),
         2  => Character'Pos ('p'),
         3  => Character'Pos ('e'),
         4  => Character'Pos ('n'),
         5  => Character'Pos ('s'),
         6  => Character'Pos ('s'),
         7  => Character'Pos ('h'),
         8  => Character'Pos ('-'),
         9  => Character'Pos ('k'),
         10 => Character'Pos ('e'),
         11 => Character'Pos ('y'),
         12 => Character'Pos ('-'),
         13 => Character'Pos ('v'),
         14 => Character'Pos ('1'),
         15 => 0];
      Cursor               : Stream_Element_Offset := Data'First;
      Next_Index           : Stream_Element_Offset;
      Cipher_Buffer        : Packet_Buffer;
      Kdf_Buffer           : Packet_Buffer;
      Kdf_Options_Buffer   : Packet_Buffer;
      Public_Buffer        : Packet_Buffer;
      Section_Buffer       : Packet_Buffer;
      Algorithm_Buffer     : Packet_Buffer;
      Public_Field_Buffer  : Packet_Buffer;
      Private_Field_Buffer : Packet_Buffer;
      RSA_D_Buffer         : Packet_Buffer;
      RSA_Iqmp_Buffer      : Packet_Buffer;
      RSA_P_Buffer         : Packet_Buffer;
      RSA_Q_Buffer         : Packet_Buffer;
      Comment_Buffer       : Packet_Buffer;
      Key_Count            : Unsigned_32;
      Check_One            : Unsigned_32;
      Check_Two            : Unsigned_32;
      Status_Value         : Status;

      procedure Clear_Working_Buffers is
      begin
         Clear (Cipher_Buffer);
         Clear (Kdf_Buffer);
         Clear (Kdf_Options_Buffer);
         Clear (Public_Buffer);
         Clear (Section_Buffer);
         Clear (Algorithm_Buffer);
         Clear (Public_Field_Buffer);
         Clear (Private_Field_Buffer);
         Clear (RSA_D_Buffer);
         Clear (RSA_Iqmp_Buffer);
         Clear (RSA_P_Buffer);
         Clear (RSA_Q_Buffer);
         Clear (Comment_Buffer);
      end Clear_Working_Buffers;

      function Finish (Result : Status) return Status is
      begin
         Clear_Working_Buffers;
         if Result /= Ok then
            Clear (Item);
         end if;
         return Result;
      end Finish;
   begin
      Clear (Item);
      if Data'Length < Magic'Length then
         return Finish (Authentication_Failed);
      end if;
      for Offset_Value in 0 .. Magic'Length - 1 loop
         if Data (Data'First + Stream_Element_Offset (Offset_Value))
           /= Magic (Magic'First + Stream_Element_Offset (Offset_Value))
         then
            return Finish (Authentication_Failed);
         end if;
      end loop;
      Cursor := Data'First + Stream_Element_Offset (Magic'Length);

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Data, Cursor, Cipher_Buffer, Next_Index);
      if Status_Value /= Ok then
         return Finish (Authentication_Failed);
      end if;
      Cursor := Next_Index;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Data, Cursor, Kdf_Buffer, Next_Index);
      if Status_Value /= Ok then
         return Finish (Authentication_Failed);
      end if;
      Cursor := Next_Index;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Data, Cursor, Kdf_Options_Buffer, Next_Index);
      if Status_Value /= Ok then
         return Finish (Authentication_Failed);
      end if;
      Cursor := Next_Index;

      declare
         Cipher_Name : constant String :=
           Bytes_To_String (To_Array (Cipher_Buffer));
         Kdf_Name    : constant String :=
           Bytes_To_String (To_Array (Kdf_Buffer));
      begin
         if Cipher_Name = "none" then
            if Kdf_Name /= "none" or else Length (Kdf_Options_Buffer) /= 0 then
               return Finish (Unsupported_Feature);
            end if;
         elsif Cipher_Key_Length (Cipher_Name) /= 0 then
            if Kdf_Name /= "bcrypt" then
               return Finish (Unsupported_Feature);
            end if;
         else
            return Finish (Unsupported_Feature);
         end if;
      end;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, Cursor, Key_Count, Next_Index);
      if Status_Value /= Ok then
         return Finish (Authentication_Failed);
      end if;
      Cursor := Next_Index;
      if Key_Count = 0 then
         return Finish (Authentication_Failed);
      elsif Key_Count /= 1 then
         return Finish (Unsupported_Feature);
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Data, Cursor, Public_Buffer, Next_Index);
      if Status_Value /= Ok or else Length (Public_Buffer) = 0 then
         return Finish (Authentication_Failed);
      end if;
      Cursor := Next_Index;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Data, Cursor, Section_Buffer, Next_Index);
      if Status_Value /= Ok or else Length (Section_Buffer) = 0 then
         return Finish (Authentication_Failed);
      end if;
      if Next_Index /= Data'Last + 1 then
         return Finish (Authentication_Failed);
      end if;

      declare
         Cipher_Name : constant String :=
           Bytes_To_String (To_Array (Cipher_Buffer));
         Kdf_Name    : constant String :=
           Bytes_To_String (To_Array (Kdf_Buffer));
      begin
         if Cipher_Name /= "none" then
            declare
               Decrypted_Buffer : Packet_Buffer;
               Decrypt_Status   : Status;
            begin
               if Passphrase'Length = 0 then
                  return Finish (Authentication_Failed);
               end if;
               if Kdf_Name /= "bcrypt" then
                  return Finish (Unsupported_Feature);
               end if;
               Decrypt_Status :=
                 Decrypt_OpenSSH_Encrypted_Section
                   (Cipher_Name,
                    To_Array (Kdf_Options_Buffer),
                    Passphrase,
                    To_Array (Section_Buffer),
                    Decrypted_Buffer);
               if Decrypt_Status /= Ok then
                  Clear (Decrypted_Buffer);
                  return Finish (Decrypt_Status);
               end if;
               Clear (Section_Buffer);
               Status_Value :=
                 Set (Section_Buffer, To_Array (Decrypted_Buffer));
               Clear (Decrypted_Buffer);
               if Status_Value /= Ok then
                  return Finish (Status_Value);
               end if;
            end;
         end if;
      end;

      declare
         Section_Data   : Stream_Element_Array := To_Array (Section_Buffer);
         Section_Cursor : Stream_Element_Offset := Section_Data'First;
         Section_Next   : Stream_Element_Offset;

         function Finish_Section (Result : Status) return Status is
         begin
            Section_Data := [others => 0];
            return Finish (Result);
         end Finish_Section;
      begin
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Section_Data, Section_Cursor, Check_One, Section_Next);
         if Status_Value /= Ok then
            return Finish_Section (Authentication_Failed);
         end if;
         Section_Cursor := Section_Next;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_Uint32
             (Section_Data, Section_Cursor, Check_Two, Section_Next);
         if Status_Value /= Ok or else Check_One /= Check_Two then
            return Finish_Section (Authentication_Failed);
         end if;
         Section_Cursor := Section_Next;

         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Section_Data, Section_Cursor, Algorithm_Buffer, Section_Next);
         if Status_Value /= Ok or else Length (Algorithm_Buffer) = 0 then
            return Finish_Section (Authentication_Failed);
         end if;
         Section_Cursor := Section_Next;

         declare
            Algorithm_Text : constant String :=
              Bytes_To_String (To_Array (Algorithm_Buffer));
         begin
            if Algorithm_Text = "ssh-ed25519" then
               null;
            elsif Algorithm_Text = "ssh-rsa" then
               null;
            elsif Is_ECDSA_Algorithm (Algorithm_Text) then
               null;
            else
               return Finish_Section (Unsupported_Feature);
            end if;
            Item.Algorithm := To_Unbounded_String (Algorithm_Text);
         end;

         if To_String (Item.Algorithm) = "ssh-ed25519" then
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Section_Data,
                 Section_Cursor,
                 Public_Field_Buffer,
                 Section_Next);
            if Status_Value /= Ok then
               return Finish_Section (Authentication_Failed);
            end if;
            Section_Cursor := Section_Next;
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Section_Data,
                 Section_Cursor,
                 Private_Field_Buffer,
                 Section_Next);
            if Status_Value /= Ok then
               return Finish_Section (Authentication_Failed);
            end if;
            Section_Cursor := Section_Next;
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Section_Data, Section_Cursor, Comment_Buffer, Section_Next);
            if Status_Value /= Ok
              or else Length (Comment_Buffer) > Max_Identity_Comment_Length
            then
               return Finish_Section (Authentication_Failed);
            end if;
            Section_Cursor := Section_Next;

            if Length (Public_Field_Buffer) /= 32
              or else Length (Private_Field_Buffer) /= 64
            then
               return Finish_Section (Authentication_Failed);
            end if;
            declare
               Public_Data  : constant Stream_Element_Array :=
                 To_Array (Public_Field_Buffer);
               Private_Data : Stream_Element_Array :=
                 To_Array (Private_Field_Buffer);

               function Finish_Private (Result : Status) return Status is
               begin
                  Private_Data := [others => 0];
                  return Finish_Section (Result);
               end Finish_Private;
            begin
               if not Same_Bytes
                        (Public_Data,
                         Private_Data
                           (Private_Data'First + 32 .. Private_Data'Last))
               then
                  return Finish_Private (Authentication_Failed);
               end if;
               Status_Value :=
                 Set
                   (Item.Ed25519_Seed,
                    Private_Data
                      (Private_Data'First .. Private_Data'First + 31));
               if Status_Value /= Ok then
                  return Finish_Private (Status_Value);
               end if;
               Status_Value := Set (Item.Ed25519_Public, Public_Data);
               if Status_Value /= Ok then
                  return Finish_Private (Status_Value);
               end if;
               Private_Data := [others => 0];
            end;
         elsif Is_ECDSA_Algorithm (To_String (Item.Algorithm)) then
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Section_Data,
                 Section_Cursor,
                 Public_Field_Buffer,
                 Section_Next);
            if Status_Value /= Ok
              or else
                Bytes_To_String (To_Array (Public_Field_Buffer))
                  /= ECDSA_Curve_Name (To_String (Item.Algorithm))
            then
               return Finish_Section (Authentication_Failed);
            end if;
            Section_Cursor := Section_Next;
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Section_Data,
                 Section_Cursor,
                 Private_Field_Buffer,
                 Section_Next);
            if Status_Value /= Ok
              or else Length (Private_Field_Buffer)
                /= ECDSA_Public_Point_Length (To_String (Item.Algorithm))
            then
               return Finish_Section (Authentication_Failed);
            end if;
            Section_Cursor := Section_Next;
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Section_Data, Section_Cursor, RSA_D_Buffer, Section_Next);
            if Status_Value /= Ok or else Length (RSA_D_Buffer) = 0 then
               return Finish_Section (Authentication_Failed);
            end if;
            Section_Cursor := Section_Next;
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Section_Data, Section_Cursor, Comment_Buffer, Section_Next);
            if Status_Value /= Ok
              or else Length (Comment_Buffer) > Max_Identity_Comment_Length
            then
               return Finish_Section (Authentication_Failed);
            end if;
            Section_Cursor := Section_Next;
            Status_Value :=
              Set (Item.ECDSA_Curve, To_Array (Public_Field_Buffer));
            if Status_Value /= Ok then
               return Finish_Section (Status_Value);
            end if;
            Status_Value :=
              Set (Item.ECDSA_Public, To_Array (Private_Field_Buffer));
            if Status_Value /= Ok then
               return Finish_Section (Status_Value);
            end if;
            Status_Value := Set (Item.ECDSA_Private, To_Array (RSA_D_Buffer));
            if Status_Value /= Ok then
               return Finish_Section (Status_Value);
            end if;
         else
            --  OpenSSH RSA private-key fields are mpint n, e, d, iqmp, p, q,
            --  followed by the comment string.  Preserve the private exponent
            --  only for local signing; p/q/iqmp are retained when present so
            --  RSA signing can use CRT acceleration.
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Section_Data,
                 Section_Cursor,
                 Public_Field_Buffer,
                 Section_Next);
            if Status_Value /= Ok or else Length (Public_Field_Buffer) = 0 then
               return Finish_Section (Authentication_Failed);
            end if;
            Section_Cursor := Section_Next;
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Section_Data,
                 Section_Cursor,
                 Private_Field_Buffer,
                 Section_Next);
            if Status_Value /= Ok or else Length (Private_Field_Buffer) = 0
            then
               return Finish_Section (Authentication_Failed);
            end if;
            Section_Cursor := Section_Next;
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Section_Data, Section_Cursor, RSA_D_Buffer, Section_Next);
            if Status_Value /= Ok or else Length (RSA_D_Buffer) = 0 then
               return Finish_Section (Authentication_Failed);
            end if;
            Section_Cursor := Section_Next;
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Section_Data, Section_Cursor, RSA_Iqmp_Buffer, Section_Next);
            if Status_Value /= Ok or else Length (RSA_Iqmp_Buffer) = 0 then
               return Finish_Section (Authentication_Failed);
            end if;
            Section_Cursor := Section_Next;
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Section_Data, Section_Cursor, RSA_P_Buffer, Section_Next);
            if Status_Value /= Ok or else Length (RSA_P_Buffer) = 0 then
               return Finish_Section (Authentication_Failed);
            end if;
            Section_Cursor := Section_Next;
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Section_Data, Section_Cursor, RSA_Q_Buffer, Section_Next);
            if Status_Value /= Ok or else Length (RSA_Q_Buffer) = 0 then
               return Finish_Section (Authentication_Failed);
            end if;
            Section_Cursor := Section_Next;
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Section_Data, Section_Cursor, Comment_Buffer, Section_Next);
            if Status_Value /= Ok
              or else Length (Comment_Buffer) > Max_Identity_Comment_Length
            then
               return Finish_Section (Authentication_Failed);
            end if;
            Section_Cursor := Section_Next;

            Status_Value :=
              Set (Item.RSA_Modulus, To_Array (Public_Field_Buffer));
            if Status_Value /= Ok then
               return Finish_Section (Status_Value);
            end if;
            Status_Value :=
              Set (Item.RSA_Exponent, To_Array (Private_Field_Buffer));
            if Status_Value /= Ok then
               return Finish_Section (Status_Value);
            end if;
            Status_Value :=
              Set (Item.RSA_Private_Exponent, To_Array (RSA_D_Buffer));
            if Status_Value /= Ok then
               return Finish_Section (Status_Value);
            end if;
            Status_Value :=
              Set (Item.RSA_Coefficient_IQMP, To_Array (RSA_Iqmp_Buffer));
            if Status_Value /= Ok then
               return Finish_Section (Status_Value);
            end if;
            Status_Value := Set (Item.RSA_Prime_P, To_Array (RSA_P_Buffer));
            if Status_Value /= Ok then
               return Finish_Section (Status_Value);
            end if;
            Status_Value := Set (Item.RSA_Prime_Q, To_Array (RSA_Q_Buffer));
            if Status_Value /= Ok then
               return Finish_Section (Status_Value);
            end if;
         end if;

         --  Validate the public key blob is the exact OpenSSH public key for the
         --  private-key record: string "ssh-ed25519" || string public_key.
         declare
            Blob_Data      : constant Stream_Element_Array :=
              To_Array (Public_Buffer);
            Blob_Cursor    : Stream_Element_Offset := Blob_Data'First;
            Blob_Next      : Stream_Element_Offset;
            Blob_Algorithm : Packet_Buffer;
            Blob_Public    : Packet_Buffer;

            function Finish_Blob (Result : Status) return Status is
            begin
               Clear (Blob_Algorithm);
               Clear (Blob_Public);
               if Result = Ok then
                  return Ok;
               end if;
               return Finish_Section (Result);
            end Finish_Blob;
         begin
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Blob_Data, Blob_Cursor, Blob_Algorithm, Blob_Next);
            if Status_Value /= Ok then
               return Finish_Blob (Authentication_Failed);
            end if;
            Blob_Cursor := Blob_Next;
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Blob_Data, Blob_Cursor, Blob_Public, Blob_Next);
            if Status_Value /= Ok then
               return Finish_Blob (Authentication_Failed);
            end if;
            if Bytes_To_String (To_Array (Blob_Algorithm))
              /= To_String (Item.Algorithm)
            then
               return Finish_Blob (Authentication_Failed);
            end if;
            if To_String (Item.Algorithm) = "ssh-ed25519" then
               if Blob_Next /= Blob_Data'Last + 1
                 or else
                   not Same_Bytes
                         (To_Array (Blob_Public),
                          To_Array (Public_Field_Buffer))
               then
                  return Finish_Blob (Authentication_Failed);
               end if;
            elsif Is_ECDSA_Algorithm (To_String (Item.Algorithm)) then
               declare
                  Blob_Public_Point : Packet_Buffer;
                  Blob_Next_Two     : Stream_Element_Offset;
               begin
                  Status_Value :=
                    SSH_Lib.Protocol.Numbers.Decode_SSH_String
                      (Blob_Data, Blob_Next, Blob_Public_Point, Blob_Next_Two);
                  if Status_Value /= Ok
                    or else Blob_Next_Two /= Blob_Data'Last + 1
                  then
                     Clear (Blob_Public_Point);
                     return Finish_Blob (Authentication_Failed);
                  end if;
                  if Bytes_To_String (To_Array (Blob_Public))
                       /= ECDSA_Curve_Name (To_String (Item.Algorithm))
                    or else
                      not Same_Bytes
                            (To_Array (Blob_Public_Point),
                             To_Array (Private_Field_Buffer))
                  then
                     Clear (Blob_Public_Point);
                     return Finish_Blob (Authentication_Failed);
                  end if;
                  Clear (Blob_Public_Point);
               end;
            else
               declare
                  Blob_Modulus  : Packet_Buffer;
                  Blob_Next_Two : Stream_Element_Offset;
               begin
                  Status_Value :=
                    SSH_Lib.Protocol.Numbers.Decode_SSH_String
                      (Blob_Data, Blob_Next, Blob_Modulus, Blob_Next_Two);
                  if Status_Value /= Ok
                    or else Blob_Next_Two /= Blob_Data'Last + 1
                  then
                     Clear (Blob_Modulus);
                     return Finish_Blob (Authentication_Failed);
                  end if;
                  if not Same_Bytes
                           (To_Array (Blob_Public),
                            To_Array (Private_Field_Buffer))
                    or else
                      not Same_Bytes
                            (To_Array (Blob_Modulus),
                             To_Array (Public_Field_Buffer))
                  then
                     Clear (Blob_Modulus);
                     return Finish_Blob (Authentication_Failed);
                  end if;
                  Clear (Blob_Modulus);
               end;
            end if;
            Clear (Blob_Algorithm);
            Clear (Blob_Public);
         end;

         declare
            Expected_Padding : Stream_Element := 1;
            Padding_Count    : Natural := 0;
            Parsed_Cipher    : constant String :=
              Bytes_To_String (To_Array (Cipher_Buffer));
            Padding_Limit    : constant Natural :=
              (if Parsed_Cipher = "none" then 8 else 16);
         begin
            while Section_Cursor <= Section_Data'Last loop
               Padding_Count := Padding_Count + 1;
               --  OpenSSH pads the private-list with the byte sequence
               --  1, 2, 3, ... up to the cipher block padding.  Unencrypted
               --  fixtures keep the historical small-padding guard; encrypted
               --  AES-CTR/AES-CBC private sections may legitimately need the
               --  full AES block padding range.
               if Padding_Count > Padding_Limit then
                  return Finish_Section (Authentication_Failed);
               end if;
               if Section_Data (Section_Cursor) /= Expected_Padding then
                  return Finish_Section (Authentication_Failed);
               end if;
               Expected_Padding := Expected_Padding + 1;
               Section_Cursor := Section_Cursor + 1;
            end loop;
         end;
         Section_Data := [others => 0];
      end;

      Status_Value := Set (Item.Public_Blob, To_Array (Public_Buffer));
      if Status_Value /= Ok then
         Clear (Item);
         return Finish (Status_Value);
      end if;
      if To_String (Item.Algorithm) = "ssh-rsa" then
         Item.Key_Type := RSA_Key;
      elsif Is_ECDSA_Algorithm (To_String (Item.Algorithm)) then
         declare
            Match_Status : constant Status :=
              ECDSA_Public_Matches_Private
                (To_String (Item.Algorithm),
                 To_Array (Public_Buffer),
                 To_Array (Item.ECDSA_Private));
         begin
            if Match_Status /= Ok then
               Clear (Item);
               return Finish (Match_Status);
            end if;
         end;
         Item.Key_Type := ECDSA_Key_Kind_For (To_String (Item.Algorithm));
      else
         Item.Key_Type := Ed25519_Key;
      end if;
      return Finish (Ok);
   exception
      when others =>
         Clear (Item);
         return Finish (Internal_Error);
   end Parse_OpenSSH_Binary;

   function Extract_PEM_Base64
     (Text       : String;
      Begin_Line : String;
      End_Line   : String;
      Encoded    : out Unbounded_String) return Status
   is
      Cursor     : Positive := Text'First;
      Line_Start : Positive;
      Line_Stop  : Natural;
      In_Body    : Boolean := False;
      Saw_End    : Boolean := False;
   begin
      Encoded := Null_Unbounded_String;
      if Text'Length = 0 then
         return Authentication_Failed;
      end if;

      while Cursor <= Text'Last loop
         Line_Start := Cursor;
         Line_Stop := Cursor - 1;
         while Cursor <= Text'Last
           and then Text (Cursor) /= Character'Val (10)
           and then Text (Cursor) /= Character'Val (13)
         loop
            Line_Stop := Cursor;
            Cursor := Cursor + 1;
         end loop;

         declare
            Line_Text : constant String :=
              (if Line_Stop >= Line_Start
               then Text (Line_Start .. Line_Stop)
               else "");
         begin
            if not In_Body then
               if Line_Text = Begin_Line then
                  In_Body := True;
               elsif Line_Text'Length /= 0 then
                  return Authentication_Failed;
               end if;
            else
               if Line_Text = End_Line then
                  Saw_End := True;
                  exit;
               elsif Line_Text'Length = 0 then
                  null;
               else
                  for Character_Value of Line_Text loop
                     if not Is_Base64_Char (Character_Value) then
                        return Authentication_Failed;
                     end if;
                     Append (Encoded, Character_Value);
                  end loop;
               end if;
            end if;
         end;

         if Cursor <= Text'Last then
            declare
               First_EOL : constant Character := Text (Cursor);
            begin
               Cursor := Cursor + 1;
               if Cursor <= Text'Last
                 and then
                   ((First_EOL = Character'Val (13)
                     and then Text (Cursor) = Character'Val (10))
                    or else
                    (First_EOL = Character'Val (10)
                     and then Text (Cursor) = Character'Val (13)))
               then
                  Cursor := Cursor + 1;
               end if;
            end;
         end if;
      end loop;

      if Saw_End then
         while Cursor <= Text'Last loop
            if Text (Cursor) /= Character'Val (10)
              and then Text (Cursor) /= Character'Val (13)
            then
               return Authentication_Failed;
            end if;
            Cursor := Cursor + 1;
         end loop;
      end if;

      if not In_Body or else not Saw_End or else Length (Encoded) = 0 then
         return Authentication_Failed;
      end if;
      return Ok;
   end Extract_PEM_Base64;

   function Decode_DER_Length
     (Data        : Stream_Element_Array;
      Cursor      : Stream_Element_Offset;
      Length_Data : out Natural;
      Next_Index  : out Stream_Element_Offset) return Status
   is
      Octet_Count : Natural;
      Result      : Natural := 0;
   begin
      Length_Data := 0;
      Next_Index := Cursor;
      if Cursor > Data'Last then
         return Authentication_Failed;
      end if;

      if Data (Cursor) < 16#80# then
         Length_Data := Natural (Data (Cursor));
         Next_Index := Cursor + 1;
         return Ok;
      end if;

      Octet_Count := Natural (Data (Cursor) - 16#80#);
      if Octet_Count = 0 or else Octet_Count > 4 then
         return Authentication_Failed;
      end if;
      if Cursor + Stream_Element_Offset (Octet_Count) > Data'Last then
         return Authentication_Failed;
      end if;
      if Data (Cursor + 1) = 0 then
         return Authentication_Failed;
      end if;

      for Offset_Value in 1 .. Octet_Count loop
         Result :=
           Result
           * 256
           + Natural (Data (Cursor + Stream_Element_Offset (Offset_Value)));
      end loop;
      if Result < 128 then
         return Authentication_Failed;
      end if;
      Length_Data := Result;
      Next_Index := Cursor + Stream_Element_Offset (Octet_Count) + 1;
      return Ok;
   exception
      when others =>
         Length_Data := 0;
         Next_Index := Cursor;
         return Internal_Error;
   end Decode_DER_Length;

   function Decode_DER_Header
     (Data       : Stream_Element_Array;
      Cursor     : Stream_Element_Offset;
      Tag_Value  : Stream_Element;
      Body_First : out Stream_Element_Offset;
      Body_Last  : out Stream_Element_Offset) return Status
   is
      Length_Data  : Natural;
      After_Length : Stream_Element_Offset;
   begin
      Body_First := Cursor;
      Body_Last := Cursor - 1;
      if Cursor > Data'Last or else Data (Cursor) /= Tag_Value then
         return Authentication_Failed;
      end if;
      declare
         Status_Value : constant Status :=
           Decode_DER_Length (Data, Cursor + 1, Length_Data, After_Length);
      begin
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end;
      if Length_Data = 0 then
         return Authentication_Failed;
      end if;
      Body_First := After_Length;
      Body_Last := After_Length + Stream_Element_Offset (Length_Data) - 1;
      if Body_Last > Data'Last or else Body_Last < Body_First then
         return Authentication_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Body_First := Cursor;
         Body_Last := Cursor - 1;
         return Internal_Error;
   end Decode_DER_Header;

   function Decode_DER_Integer
     (Data       : Stream_Element_Array;
      Cursor     : in out Stream_Element_Offset;
      Value_Data : out Packet_Buffer) return Status
   is
      Body_First   : Stream_Element_Offset;
      Body_Last    : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Clear (Value_Data);
      Status_Value :=
        Decode_DER_Header (Data, Cursor, 16#02#, Body_First, Body_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if Data (Body_First) >= 16#80# then
         return Authentication_Failed;
      end if;
      if Body_Last > Body_First
        and then Data (Body_First) = 0
        and then Data (Body_First + 1) < 16#80#
      then
         return Authentication_Failed;
      end if;
      Status_Value := Set (Value_Data, Data (Body_First .. Body_Last));
      if Status_Value /= Ok then
         Clear (Value_Data);
         return Status_Value;
      end if;
      Cursor := Body_Last + 1;
      return Ok;
   exception
      when others =>
         Clear (Value_Data);
         return Internal_Error;
   end Decode_DER_Integer;

   function Parse_Legacy_RSA_PEM_Binary
     (Data : Stream_Element_Array; Item : out Identity_Key) return Status
   is
      Seq_First       : Stream_Element_Offset;
      Seq_Last        : Stream_Element_Offset;
      Cursor          : Stream_Element_Offset;
      Version_Buffer  : Packet_Buffer;
      Modulus_Buffer  : Packet_Buffer;
      Exponent_Buffer : Packet_Buffer;
      Private_Buffer  : Packet_Buffer;
      Prime_P_Buffer  : Packet_Buffer;
      Prime_Q_Buffer  : Packet_Buffer;
      DMP1_Buffer     : Packet_Buffer;
      DMQ1_Buffer     : Packet_Buffer;
      IQMP_Buffer     : Packet_Buffer;
      Status_Value    : Status;

      function Finish (Result : Status) return Status is
      begin
         Clear (Version_Buffer);
         Clear (Modulus_Buffer);
         Clear (Exponent_Buffer);
         Clear (Private_Buffer);
         Clear (Prime_P_Buffer);
         Clear (Prime_Q_Buffer);
         Clear (DMP1_Buffer);
         Clear (DMQ1_Buffer);
         Clear (IQMP_Buffer);
         if Result /= Ok then
            Clear (Item);
         end if;
         return Result;
      end Finish;
   begin
      Clear (Item);
      Status_Value :=
        Decode_DER_Header (Data, Data'First, 16#30#, Seq_First, Seq_Last);
      if Status_Value /= Ok then
         return Finish (Authentication_Failed);
      end if;
      if Seq_Last /= Data'Last then
         return Finish (Authentication_Failed);
      end if;

      Cursor := Seq_First;
      Status_Value := Decode_DER_Integer (Data, Cursor, Version_Buffer);
      if Status_Value /= Ok then
         return Finish (Authentication_Failed);
      end if;
      declare
         Version_Data : constant Stream_Element_Array :=
           To_Array (Version_Buffer);
      begin
         if Version_Data'Length /= 1
           or else Version_Data (Version_Data'First) not in 0 | 1
         then
            return Finish (Unsupported_Feature);
         end if;
      end;

      Status_Value := Decode_DER_Integer (Data, Cursor, Modulus_Buffer);
      if Status_Value /= Ok or else Length (Modulus_Buffer) = 0 then
         return Finish (Authentication_Failed);
      end if;
      Status_Value := Decode_DER_Integer (Data, Cursor, Exponent_Buffer);
      if Status_Value /= Ok or else Length (Exponent_Buffer) = 0 then
         return Finish (Authentication_Failed);
      end if;
      Status_Value := Decode_DER_Integer (Data, Cursor, Private_Buffer);
      if Status_Value /= Ok or else Length (Private_Buffer) = 0 then
         return Finish (Authentication_Failed);
      end if;

      Status_Value := Decode_DER_Integer (Data, Cursor, Prime_P_Buffer);
      if Status_Value /= Ok or else Length (Prime_P_Buffer) = 0 then
         return Finish (Authentication_Failed);
      end if;
      Status_Value := Decode_DER_Integer (Data, Cursor, Prime_Q_Buffer);
      if Status_Value /= Ok or else Length (Prime_Q_Buffer) = 0 then
         return Finish (Authentication_Failed);
      end if;
      Status_Value := Decode_DER_Integer (Data, Cursor, DMP1_Buffer);
      if Status_Value /= Ok or else Length (DMP1_Buffer) = 0 then
         return Finish (Authentication_Failed);
      end if;
      Status_Value := Decode_DER_Integer (Data, Cursor, DMQ1_Buffer);
      if Status_Value /= Ok or else Length (DMQ1_Buffer) = 0 then
         return Finish (Authentication_Failed);
      end if;
      Status_Value := Decode_DER_Integer (Data, Cursor, IQMP_Buffer);
      if Status_Value /= Ok or else Length (IQMP_Buffer) = 0 then
         return Finish (Authentication_Failed);
      end if;
      if Cursor /= Seq_Last + 1 then
         return Finish (Authentication_Failed);
      end if;

      declare
         Algorithm_Buffer : constant Packet_Buffer :=
           SSH_Lib.Protocol.Numbers.Encode_SSH_String
             ([1 => Character'Pos ('s'),
               2 => Character'Pos ('s'),
               3 => Character'Pos ('h'),
               4 => Character'Pos ('-'),
               5 => Character'Pos ('r'),
               6 => Character'Pos ('s'),
               7 => Character'Pos ('a')]);
         Encoded_Exponent : constant Packet_Buffer :=
           SSH_Lib.Protocol.Numbers.Encode_SSH_String
             (To_Array (Exponent_Buffer));
         Encoded_Modulus  : constant Packet_Buffer :=
           SSH_Lib.Protocol.Numbers.Encode_SSH_String
             (To_Array (Modulus_Buffer));
      begin
         Status_Value :=
           Append (Item.Public_Blob, To_Array (Algorithm_Buffer));
         if Status_Value /= Ok then
            return Finish (Status_Value);
         end if;
         Status_Value :=
           Append (Item.Public_Blob, To_Array (Encoded_Exponent));
         if Status_Value /= Ok then
            return Finish (Status_Value);
         end if;
         Status_Value := Append (Item.Public_Blob, To_Array (Encoded_Modulus));
         if Status_Value /= Ok then
            return Finish (Status_Value);
         end if;
      end;

      Status_Value := Set (Item.RSA_Modulus, To_Array (Modulus_Buffer));
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;
      Status_Value := Set (Item.RSA_Exponent, To_Array (Exponent_Buffer));
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;
      Status_Value :=
        Set (Item.RSA_Private_Exponent, To_Array (Private_Buffer));
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;
      Status_Value := Set (Item.RSA_Prime_P, To_Array (Prime_P_Buffer));
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;
      Status_Value := Set (Item.RSA_Prime_Q, To_Array (Prime_Q_Buffer));
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;
      Status_Value := Set (Item.RSA_Exponent_DMP1, To_Array (DMP1_Buffer));
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;
      Status_Value := Set (Item.RSA_Exponent_DMQ1, To_Array (DMQ1_Buffer));
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;
      Status_Value := Set (Item.RSA_Coefficient_IQMP, To_Array (IQMP_Buffer));
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;
      Item.Algorithm := To_Unbounded_String ("ssh-rsa");
      Item.Key_Type := RSA_Key;
      return Finish (Ok);
   exception
      when others =>
         Clear (Item);
         return Finish (Internal_Error);
   end Parse_Legacy_RSA_PEM_Binary;

   function Parse_Legacy_RSA_PEM
     (Text : String; Item : out Identity_Key) return Status
   is
      Encoded       : Unbounded_String;
      Binary_Buffer : Packet_Buffer;
      Status_Value  : Status;
   begin
      Clear (Item);
      Status_Value :=
        Extract_PEM_Base64
          (Text,
           "-----BEGIN RSA PRIVATE KEY-----",
           "-----END RSA PRIVATE KEY-----",
           Encoded);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Decode_Base64 (To_String (Encoded), Binary_Buffer);
      Encoded := Null_Unbounded_String;
      if Status_Value /= Ok then
         Clear (Binary_Buffer);
         return Status_Value;
      end if;
      Status_Value :=
        Parse_Legacy_RSA_PEM_Binary (To_Array (Binary_Buffer), Item);
      Clear (Binary_Buffer);
      if Status_Value /= Ok then
         Clear (Item);
      end if;
      return Status_Value;
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Parse_Legacy_RSA_PEM;

   function Parse_PKCS8_Private_Key_Binary
     (Data : Stream_Element_Array; Item : out Identity_Key) return Status;

   function String_To_Bytes (Text : String) return Stream_Element_Array is
      Result : Stream_Element_Array (1 .. Stream_Element_Offset (Text'Length));
      Cursor : Stream_Element_Offset := Result'First;
   begin
      for Character_Value of Text loop
         Result (Cursor) := Character'Pos (Character_Value);
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end String_To_Bytes;

   function Bytes_Equal
     (Data        : Stream_Element_Array;
      First_Index : Stream_Element_Offset;
      Pattern     : Stream_Element_Array) return Boolean is
   begin
      if Pattern'Length = 0 then
         return True;
      end if;
      if First_Index < Data'First
        or else
          First_Index + Stream_Element_Offset (Pattern'Length) - 1 > Data'Last
      then
         return False;
      end if;
      for Offset_Value in 0 .. Pattern'Length - 1 loop
         if Data (First_Index + Stream_Element_Offset (Offset_Value))
           /= Pattern (Pattern'First + Stream_Element_Offset (Offset_Value))
         then
            return False;
         end if;
      end loop;
      return True;
   end Bytes_Equal;

   function Is_Hex_Char (Value : Character) return Boolean is
   begin
      return
        (Value >= '0' and then Value <= '9')
        or else (Value >= 'A' and then Value <= 'F')
        or else (Value >= 'a' and then Value <= 'f');
   end Is_Hex_Char;

   function Hex_Value (Value : Character) return Natural is
   begin
      if Value >= '0' and then Value <= '9' then
         return Character'Pos (Value) - Character'Pos ('0');
      elsif Value >= 'A' and then Value <= 'F' then
         return 10 + Character'Pos (Value) - Character'Pos ('A');
      else
         return 10 + Character'Pos (Value) - Character'Pos ('a');
      end if;
   end Hex_Value;

   function Decode_Hex (Text : String; Data : out Packet_Buffer) return Status
   is
      Byte_Data    : Stream_Element_Array (1 .. 1) := [others => 0];
      Status_Value : Status;
   begin
      Clear (Data);
      if Text'Length = 0 or else Text'Length mod 2 /= 0 then
         return Authentication_Failed;
      end if;
      for Index_Value in Text'First .. Text'Last loop
         if not Is_Hex_Char (Text (Index_Value)) then
            Clear (Data);
            return Authentication_Failed;
         end if;
      end loop;
      declare
         Cursor : Integer := Text'First;
      begin
         while Cursor <= Text'Last loop
            Byte_Data (1) :=
              Stream_Element
                (Hex_Value (Text (Cursor))
                 * 16
                 + Hex_Value (Text (Cursor + 1)));
            Status_Value := Append (Data, Byte_Data);
            if Status_Value /= Ok then
               Clear (Data);
               return Status_Value;
            end if;
            Cursor := Cursor + 2;
         end loop;
      end;
      Byte_Data := [others => 0];
      return Ok;
   exception
      when others =>
         Clear (Data);
         return Internal_Error;
   end Decode_Hex;

   function Extract_Encrypted_Legacy_PEM
     (Text       : String;
      Begin_Line : String;
      End_Line   : String;
      Dek_Name   : out Unbounded_String;
      Dek_IV_Hex : out Unbounded_String;
      Encoded    : out Unbounded_String) return Status
   is
      Cursor      : Positive := Text'First;
      Line_Start  : Positive;
      Line_Stop   : Natural;
      In_Body     : Boolean := False;
      Saw_End     : Boolean := False;
      Saw_Proc    : Boolean := False;
      Saw_DEK     : Boolean := False;
      Header_Mode : Boolean := True;
   begin
      Dek_Name := Null_Unbounded_String;
      Dek_IV_Hex := Null_Unbounded_String;
      Encoded := Null_Unbounded_String;
      if Text'Length = 0 then
         return Authentication_Failed;
      end if;

      while Cursor <= Text'Last loop
         Line_Start := Cursor;
         Line_Stop := Cursor - 1;
         while Cursor <= Text'Last
           and then Text (Cursor) /= Character'Val (10)
           and then Text (Cursor) /= Character'Val (13)
         loop
            Line_Stop := Cursor;
            Cursor := Cursor + 1;
         end loop;

         declare
            Line_Text : constant String :=
              (if Line_Stop >= Line_Start
               then Text (Line_Start .. Line_Stop)
               else "");
         begin
            if not In_Body then
               if Line_Text = Begin_Line then
                  In_Body := True;
               elsif Line_Text'Length /= 0 then
                  return Authentication_Failed;
               end if;
            else
               if Line_Text = End_Line then
                  Saw_End := True;
                  exit;
               elsif Header_Mode then
                  if Line_Text'Length = 0 then
                     Header_Mode := False;
                  elsif Line_Text = "Proc-Type: 4,ENCRYPTED" then
                     Saw_Proc := True;
                  elsif Line_Text'Length > 9
                    and then
                      Line_Text (Line_Text'First .. Line_Text'First + 8)
                      = "DEK-Info:"
                  then
                     declare
                        Value_First : Positive := Line_Text'First + 10;
                        Comma_Index : Natural := 0;
                     begin
                        while Value_First <= Line_Text'Last
                          and then Line_Text (Value_First) = ' '
                        loop
                           Value_First := Value_First + 1;
                        end loop;
                        for Index_Value in Value_First .. Line_Text'Last loop
                           if Line_Text (Index_Value) = ',' then
                              Comma_Index := Index_Value;
                              exit;
                           end if;
                        end loop;
                        if Comma_Index = 0
                          or else Comma_Index = Value_First
                          or else Comma_Index = Line_Text'Last
                        then
                           return Authentication_Failed;
                        end if;
                        Dek_Name :=
                          To_Unbounded_String
                            (Line_Text (Value_First .. Comma_Index - 1));
                        Dek_IV_Hex :=
                          To_Unbounded_String
                            (Line_Text (Comma_Index + 1 .. Line_Text'Last));
                        Saw_DEK := True;
                     end;
                  else
                     return Unsupported_Feature;
                  end if;
               else
                  if Line_Text'Length = 0 then
                     null;
                  else
                     for Character_Value of Line_Text loop
                        if not Is_Base64_Char (Character_Value) then
                           return Authentication_Failed;
                        end if;
                        Append (Encoded, Character_Value);
                     end loop;
                  end if;
               end if;
            end if;
         end;

         if Cursor <= Text'Last then
            declare
               First_EOL : constant Character := Text (Cursor);
            begin
               Cursor := Cursor + 1;
               if Cursor <= Text'Last
                 and then
                   ((First_EOL = Character'Val (13)
                     and then Text (Cursor) = Character'Val (10))
                    or else
                    (First_EOL = Character'Val (10)
                     and then Text (Cursor) = Character'Val (13)))
               then
                  Cursor := Cursor + 1;
               end if;
            end;
         end if;
      end loop;

      if Saw_End then
         while Cursor <= Text'Last loop
            if Text (Cursor) /= Character'Val (10)
              and then Text (Cursor) /= Character'Val (13)
            then
               return Authentication_Failed;
            end if;
            Cursor := Cursor + 1;
         end loop;
      end if;

      if not In_Body
        or else not Saw_End
        or else not Saw_Proc
        or else not Saw_DEK
        or else Length (Encoded) = 0
      then
         return Authentication_Failed;
      end if;
      return Ok;
   end Extract_Encrypted_Legacy_PEM;

   function PKCS7_Unpad
     (Data       : Stream_Element_Array;
      Output     : out Packet_Buffer;
      Block_Size : Natural := 16) return Status
   is
      Pad_Length : Natural;
   begin
      Clear (Output);
      if Data'Length = 0
        or else Block_Size = 0
        or else Data'Length mod Block_Size /= 0
      then
         return Authentication_Failed;
      end if;
      Pad_Length := Natural (Data (Data'Last));
      if Pad_Length = 0
        or else Pad_Length > Block_Size
        or else Pad_Length > Data'Length
      then
         return Authentication_Failed;
      end if;
      for Offset_Value in 0 .. Pad_Length - 1 loop
         if Natural (Data (Data'Last - Stream_Element_Offset (Offset_Value)))
           /= Pad_Length
         then
            return Authentication_Failed;
         end if;
      end loop;
      if Pad_Length = Data'Length then
         return Authentication_Failed;
      end if;
      return
        Set
          (Output,
           Data
             (Data'First .. Data'Last - Stream_Element_Offset (Pad_Length)));
   exception
      when others =>
         Clear (Output);
         return Internal_Error;
   end PKCS7_Unpad;

   function Legacy_DEK_To_AES_CBC
     (Dek_Name       : String;
      Algorithm_Name : out Unbounded_String;
      Key_Length     : out Natural) return Status is
   begin
      Algorithm_Name := Null_Unbounded_String;
      Key_Length := 0;
      if Dek_Name = "AES-128-CBC" then
         Algorithm_Name := To_Unbounded_String ("aes128-cbc");
         Key_Length := 16;
      elsif Dek_Name = "AES-192-CBC" then
         Algorithm_Name := To_Unbounded_String ("aes192-cbc");
         Key_Length := 24;
      elsif Dek_Name = "AES-256-CBC" then
         Algorithm_Name := To_Unbounded_String ("aes256-cbc");
         Key_Length := 32;
      elsif Dek_Name = "DES-EDE3-CBC" then
         Algorithm_Name := To_Unbounded_String ("3des-cbc");
         Key_Length := 24;
      elsif Dek_Name = "DES-CBC" then
         Algorithm_Name := To_Unbounded_String ("des-cbc");
         Key_Length := 8;
      else
         return Unsupported_Feature;
      end if;
      return Ok;
   end Legacy_DEK_To_AES_CBC;

   function Decrypt_Legacy_PEM_Ciphertext
     (Dek_Name   : String;
      IV_Hex     : String;
      Passphrase : String;
      Ciphertext : Stream_Element_Array;
      Plaintext  : out Packet_Buffer) return Status
   is
      IV_Buffer      : Packet_Buffer;
      Algorithm_Name : Unbounded_String;
      Key_Length     : Natural := 0;
      Status_Value   : Status;
   begin
      Clear (Plaintext);
      if Passphrase'Length = 0 then
         return Authentication_Failed;
      end if;
      Status_Value :=
        Legacy_DEK_To_AES_CBC (Dek_Name, Algorithm_Name, Key_Length);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Decode_Hex (IV_Hex, IV_Buffer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      declare
         Block_Length : constant Natural :=
           Cipher_Block_Length (To_String (Algorithm_Name));
      begin
         if Length (IV_Buffer) /= Block_Length
           or else Ciphertext'Length = 0
           or else Ciphertext'Length mod Block_Length /= 0
         then
            Clear (IV_Buffer);
            return Authentication_Failed;
         end if;
      end;
      declare
         IV_Data        : constant Stream_Element_Array :=
           To_Array (IV_Buffer);
         Salt_Data      : constant Stream_Element_Array :=
           IV_Data (IV_Data'First .. IV_Data'First + 7);
         Pass_Data      : Stream_Element_Array := String_To_Bytes (Passphrase);
         Key_Data       : Stream_Element_Array :=
           CryptoLib.Macs.EVP_Bytes_To_Key_MD5
             (Pass_Data, Salt_Data, Key_Length);
         Decrypted_Data : Stream_Element_Array (Ciphertext'Range) :=
           [others => 0];
      begin
         Pass_Data := [others => 0];
         Status_Value :=
           CryptoLib.Ciphers.Decrypt_CBC_Raw
             (To_String (Algorithm_Name),
              Key_Data,
              IV_Data,
              Ciphertext,
              Decrypted_Data);
         Key_Data := [others => 0];
         Clear (IV_Buffer);
         if Status_Value /= Ok then
            Decrypted_Data := [others => 0];
            return Status_Value;
         end if;
         Status_Value :=
           PKCS7_Unpad
             (Decrypted_Data,
              Plaintext,
              Cipher_Block_Length (To_String (Algorithm_Name)));
         Decrypted_Data := [others => 0];
         return Status_Value;
      end;
   exception
      when others =>
         Clear (IV_Buffer);
         Clear (Plaintext);
         return Internal_Error;
   end Decrypt_Legacy_PEM_Ciphertext;

   function Parse_Encrypted_Legacy_RSA_PEM
     (Text : String; Passphrase : String; Item : out Identity_Key)
      return Status
   is
      Dek_Name      : Unbounded_String;
      IV_Hex        : Unbounded_String;
      Encoded       : Unbounded_String;
      Cipher_Buffer : Packet_Buffer;
      Plain_Buffer  : Packet_Buffer;
      Status_Value  : Status;
   begin
      Clear (Item);
      Status_Value :=
        Extract_Encrypted_Legacy_PEM
          (Text,
           "-----BEGIN RSA PRIVATE KEY-----",
           "-----END RSA PRIVATE KEY-----",
           Dek_Name,
           IV_Hex,
           Encoded);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Decode_Base64 (To_String (Encoded), Cipher_Buffer);
      Encoded := Null_Unbounded_String;
      if Status_Value /= Ok then
         Clear (Cipher_Buffer);
         return Status_Value;
      end if;
      Status_Value :=
        Decrypt_Legacy_PEM_Ciphertext
          (To_String (Dek_Name),
           To_String (IV_Hex),
           Passphrase,
           To_Array (Cipher_Buffer),
           Plain_Buffer);
      Clear (Cipher_Buffer);
      Dek_Name := Null_Unbounded_String;
      IV_Hex := Null_Unbounded_String;
      if Status_Value /= Ok then
         Clear (Plain_Buffer);
         if Status_Value = Unsupported_Feature then
            return Authentication_Failed;
         end if;
         return Status_Value;
      end if;
      Status_Value :=
        Parse_Legacy_RSA_PEM_Binary (To_Array (Plain_Buffer), Item);
      Clear (Plain_Buffer);
      if Status_Value /= Ok then
         Clear (Item);
         return Authentication_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Parse_Encrypted_Legacy_RSA_PEM;

   function DER_Octet_String
     (Data   : Stream_Element_Array;
      Cursor : in out Stream_Element_Offset;
      Value  : out Packet_Buffer) return Status;

   function DER_Bit_String
     (Data   : Stream_Element_Array;
      Cursor : in out Stream_Element_Offset;
      Value  : out Packet_Buffer) return Status
   is
      Body_First   : Stream_Element_Offset;
      Body_Last    : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Clear (Value);
      Status_Value :=
        Decode_DER_Header (Data, Cursor, 16#03#, Body_First, Body_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if Body_Last < Body_First or else Data (Body_First) /= 0 then
         return Authentication_Failed;
      end if;
      if Body_First = Body_Last then
         return Authentication_Failed;
      end if;
      Status_Value := Set (Value, Data (Body_First + 1 .. Body_Last));
      if Status_Value /= Ok then
         Clear (Value);
         return Status_Value;
      end if;
      Cursor := Body_Last + 1;
      return Ok;
   exception
      when others =>
         Clear (Value);
         return Internal_Error;
   end DER_Bit_String;

   function Build_ECDSA_Public_Blob
     (Algorithm_Name : String;
      Curve_Name     : String;
      Public_Point   : Stream_Element_Array;
      Blob           : out Packet_Buffer)
      return Status
   is
      Algorithm_Buffer : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String
          (String_To_Bytes (Algorithm_Name));
      Curve_Buffer     : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String
          (String_To_Bytes (Curve_Name));
      Point_Buffer     : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String (Public_Point);
      Status_Value     : Status;
   begin
      Clear (Blob);
      Status_Value := Append (Blob, To_Array (Algorithm_Buffer));
      if Status_Value /= Ok then
         Clear (Blob);
         return Status_Value;
      end if;
      Status_Value := Append (Blob, To_Array (Curve_Buffer));
      if Status_Value /= Ok then
         Clear (Blob);
         return Status_Value;
      end if;
      Status_Value := Append (Blob, To_Array (Point_Buffer));
      if Status_Value /= Ok then
         Clear (Blob);
         return Status_Value;
      end if;
      return Ok;
   exception
      when others =>
         Clear (Blob);
         return Internal_Error;
   end Build_ECDSA_Public_Blob;

   function Parse_SEC1_EC_PEM_Binary
     (Data : Stream_Element_Array;
      Item : out Identity_Key;
      Expected_Algorithm_Name : String := "") return Status
   is
      P256_OID            : constant Stream_Element_Array (1 .. 10) :=
        [16#06#,
         16#08#,
         16#2A#,
         16#86#,
         16#48#,
         16#CE#,
         16#3D#,
         16#03#,
         16#01#,
         16#07#];
      P384_OID            : constant Stream_Element_Array (1 .. 7) :=
        [16#06#, 16#05#, 16#2B#, 16#81#, 16#04#, 16#00#, 16#22#];
      P521_OID            : constant Stream_Element_Array (1 .. 7) :=
        [16#06#, 16#05#, 16#2B#, 16#81#, 16#04#, 16#00#, 16#23#];
      Seq_First, Seq_Last : Stream_Element_Offset;
      Cursor              : Stream_Element_Offset;
      Ctx_First, Ctx_Last : Stream_Element_Offset;
      Ctx_Cursor          : Stream_Element_Offset;
      Version_Buffer      : Packet_Buffer;
      Private_Buffer      : Packet_Buffer;
      Public_Buffer       : Packet_Buffer;
      Public_Blob         : Packet_Buffer;
      Saw_Public          : Boolean := False;
      Algorithm_Name      : Unbounded_String :=
        To_Unbounded_String (Expected_Algorithm_Name);
      Status_Value        : Status;

      function Finish (Result : Status) return Status is
      begin
         Clear (Version_Buffer);
         Clear (Private_Buffer);
         Clear (Public_Buffer);
         Clear (Public_Blob);
         if Result /= Ok then
            Clear (Item);
         end if;
         return Result;
      end Finish;
   begin
      Clear (Item);
      Status_Value :=
        Decode_DER_Header (Data, Data'First, 16#30#, Seq_First, Seq_Last);
      if Status_Value /= Ok or else Seq_Last /= Data'Last then
         return Finish (Authentication_Failed);
      end if;

      Cursor := Seq_First;
      Status_Value := Decode_DER_Integer (Data, Cursor, Version_Buffer);
      if Status_Value /= Ok then
         return Finish (Authentication_Failed);
      end if;
      declare
         Version_Data : constant Stream_Element_Array :=
           To_Array (Version_Buffer);
      begin
         if Version_Data'Length /= 1
           or else Version_Data (Version_Data'First) /= 1
         then
            return Finish (Unsupported_Feature);
         end if;
      end;

      Status_Value := DER_Octet_String (Data, Cursor, Private_Buffer);
      if Status_Value /= Ok
        or else Length (Private_Buffer) = 0
        or else Length (Private_Buffer) > 67
      then
         return Finish (Authentication_Failed);
      end if;

      while Cursor <= Seq_Last loop
         if Data (Cursor) = 16#A0# then
            Status_Value :=
              Decode_DER_Header (Data, Cursor, 16#A0#, Ctx_First, Ctx_Last);
            if Status_Value /= Ok then
               return Finish (Authentication_Failed);
            end if;
            if Ctx_Last - Ctx_First + 1
                 = Stream_Element_Offset (P256_OID'Length)
              and then Bytes_Equal (Data, Ctx_First, P256_OID)
            then
               if Length (Algorithm_Name) > 0
                 and then To_String (Algorithm_Name) /= "ecdsa-sha2-nistp256"
               then
                  return Finish (Authentication_Failed);
               end if;
               Algorithm_Name := To_Unbounded_String ("ecdsa-sha2-nistp256");
            elsif Ctx_Last - Ctx_First + 1
                    = Stream_Element_Offset (P384_OID'Length)
              and then Bytes_Equal (Data, Ctx_First, P384_OID)
            then
               if Length (Algorithm_Name) > 0
                 and then To_String (Algorithm_Name) /= "ecdsa-sha2-nistp384"
               then
                  return Finish (Authentication_Failed);
               end if;
               Algorithm_Name := To_Unbounded_String ("ecdsa-sha2-nistp384");
            elsif Ctx_Last - Ctx_First + 1
                    = Stream_Element_Offset (P521_OID'Length)
              and then Bytes_Equal (Data, Ctx_First, P521_OID)
            then
               if Length (Algorithm_Name) > 0
                 and then To_String (Algorithm_Name) /= "ecdsa-sha2-nistp521"
               then
                  return Finish (Authentication_Failed);
               end if;
               Algorithm_Name := To_Unbounded_String ("ecdsa-sha2-nistp521");
            else
               return Finish (Unsupported_Feature);
            end if;
            Cursor := Ctx_Last + 1;
         elsif Data (Cursor) = 16#A1# then
            Status_Value :=
              Decode_DER_Header (Data, Cursor, 16#A1#, Ctx_First, Ctx_Last);
            if Status_Value /= Ok then
               return Finish (Authentication_Failed);
            end if;
            Ctx_Cursor := Ctx_First;
            Status_Value := DER_Bit_String (Data, Ctx_Cursor, Public_Buffer);
            if Status_Value /= Ok or else Ctx_Cursor /= Ctx_Last + 1 then
               return Finish (Authentication_Failed);
            end if;
            if Length (Algorithm_Name) = 0
              or else Length (Public_Buffer)
                /= ECDSA_Public_Point_Length (To_String (Algorithm_Name))
            then
               return Finish (Authentication_Failed);
            end if;
            Saw_Public := True;
            Cursor := Ctx_Last + 1;
         else
            return Finish (Unsupported_Feature);
         end if;
      end loop;

      if not Saw_Public then
         return Finish (Unsupported_Feature);
      end if;
      if Length (Algorithm_Name) = 0 then
         return Finish (Unsupported_Feature);
      end if;
      Status_Value :=
        Validate_ECDSA_Raw_Point
          (To_String (Algorithm_Name), To_Array (Public_Buffer));
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;
      Status_Value :=
        Build_ECDSA_Public_Blob
          (To_String (Algorithm_Name),
           ECDSA_Curve_Name (To_String (Algorithm_Name)),
           To_Array (Public_Buffer),
           Public_Blob);
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;
      Status_Value := Set (Item.Public_Blob, To_Array (Public_Blob));
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;
      Status_Value :=
        Set
          (Item.ECDSA_Curve,
           String_To_Bytes (ECDSA_Curve_Name (To_String (Algorithm_Name))));
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;
      Status_Value := Set (Item.ECDSA_Public, To_Array (Public_Buffer));
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;
      declare
         Private_Data : constant Stream_Element_Array :=
           To_Array (Private_Buffer);
      begin
         if Private_Data (Private_Data'First) >= 16#80# then
            declare
               Mpint_Data :
                 Stream_Element_Array
                   (1 .. Stream_Element_Offset (Private_Data'Length + 1)) :=
                   [others => 0];
            begin
               for Offset_Value in 0 .. Private_Data'Length - 1 loop
                  Mpint_Data
                    (Mpint_Data'First
                     + Stream_Element_Offset (Offset_Value + 1)) :=
                    Private_Data
                      (Private_Data'First
                       + Stream_Element_Offset (Offset_Value));
               end loop;
               Status_Value := Set (Item.ECDSA_Private, Mpint_Data);
               Mpint_Data := [others => 0];
            end;
         else
            Status_Value := Set (Item.ECDSA_Private, Private_Data);
         end if;
      end;
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;
      Status_Value :=
        ECDSA_Public_Matches_Private
          (To_String (Algorithm_Name),
           To_Array (Item.Public_Blob),
           To_Array (Item.ECDSA_Private));
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;
      Item.Key_Type := ECDSA_Key_Kind_For (To_String (Algorithm_Name));
      Item.Algorithm := Algorithm_Name;
      return Finish (Ok);
   exception
      when others =>
         Clear (Item);
         return Finish (Internal_Error);
   end Parse_SEC1_EC_PEM_Binary;

   function Parse_Legacy_EC_PEM
     (Text : String; Item : out Identity_Key) return Status
   is
      Encoded       : Unbounded_String;
      Binary_Buffer : Packet_Buffer;
      Status_Value  : Status;
   begin
      Clear (Item);
      Status_Value :=
        Extract_PEM_Base64
          (Text,
           "-----BEGIN EC PRIVATE KEY-----",
           "-----END EC PRIVATE KEY-----",
           Encoded);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Decode_Base64 (To_String (Encoded), Binary_Buffer);
      Encoded := Null_Unbounded_String;
      if Status_Value /= Ok then
         Clear (Binary_Buffer);
         return Status_Value;
      end if;
      Status_Value :=
        Parse_SEC1_EC_PEM_Binary (To_Array (Binary_Buffer), Item);
      Clear (Binary_Buffer);
      if Status_Value /= Ok then
         Clear (Item);
      end if;
      return Status_Value;
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Parse_Legacy_EC_PEM;

   function Parse_Encrypted_Legacy_EC_PEM
     (Text : String; Passphrase : String; Item : out Identity_Key)
      return Status
   is
      Dek_Name      : Unbounded_String;
      IV_Hex        : Unbounded_String;
      Encoded       : Unbounded_String;
      Cipher_Buffer : Packet_Buffer;
      Plain_Buffer  : Packet_Buffer;
      Status_Value  : Status;
   begin
      Clear (Item);
      Status_Value :=
        Extract_Encrypted_Legacy_PEM
          (Text,
           "-----BEGIN EC PRIVATE KEY-----",
           "-----END EC PRIVATE KEY-----",
           Dek_Name,
           IV_Hex,
           Encoded);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Decode_Base64 (To_String (Encoded), Cipher_Buffer);
      Encoded := Null_Unbounded_String;
      if Status_Value /= Ok then
         Clear (Cipher_Buffer);
         return Status_Value;
      end if;
      Status_Value :=
        Decrypt_Legacy_PEM_Ciphertext
          (To_String (Dek_Name),
           To_String (IV_Hex),
           Passphrase,
           To_Array (Cipher_Buffer),
           Plain_Buffer);
      Clear (Cipher_Buffer);
      Dek_Name := Null_Unbounded_String;
      IV_Hex := Null_Unbounded_String;
      if Status_Value /= Ok then
         Clear (Plain_Buffer);
         if Status_Value = Unsupported_Feature then
            return Authentication_Failed;
         end if;
         return Status_Value;
      end if;
      Status_Value :=
        Parse_SEC1_EC_PEM_Binary (To_Array (Plain_Buffer), Item);
      Clear (Plain_Buffer);
      if Status_Value /= Ok then
         Clear (Item);
         return Authentication_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Parse_Encrypted_Legacy_EC_PEM;

   function DER_Integer_Natural
     (Data   : Stream_Element_Array;
      Cursor : in out Stream_Element_Offset;
      Value  : out Natural) return Status
   is
      Buffer       : Packet_Buffer;
      Status_Value : Status;
   begin
      Value := 0;
      Status_Value := Decode_DER_Integer (Data, Cursor, Buffer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      declare
         Integer_Data : constant Stream_Element_Array := To_Array (Buffer);
      begin
         if Integer_Data'Length = 0 or else Integer_Data'Length > 4 then
            Clear (Buffer);
            return Unsupported_Feature;
         end if;
         for Byte_Value of Integer_Data loop
            Value := Value * 256 + Natural (Byte_Value);
         end loop;
      end;
      Clear (Buffer);
      return Ok;
   exception
      when others =>
         Clear (Buffer);
         Value := 0;
         return Internal_Error;
   end DER_Integer_Natural;

   function DER_Octet_String
     (Data   : Stream_Element_Array;
      Cursor : in out Stream_Element_Offset;
      Value  : out Packet_Buffer) return Status
   is
      Body_First   : Stream_Element_Offset;
      Body_Last    : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Clear (Value);
      Status_Value :=
        Decode_DER_Header (Data, Cursor, 16#04#, Body_First, Body_Last);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Set (Value, Data (Body_First .. Body_Last));
      if Status_Value /= Ok then
         Clear (Value);
         return Status_Value;
      end if;
      Cursor := Body_Last + 1;
      return Ok;
   exception
      when others =>
         Clear (Value);
         return Internal_Error;
   end DER_Octet_String;

   type PBKDF2_PRF is
     (PBKDF2_HMAC_SHA1,
      PBKDF2_HMAC_SHA256,
      PBKDF2_HMAC_SHA384,
      PBKDF2_HMAC_SHA512);

   function PBKDF2_HMAC
     (Passphrase  : String;
      Salt_Data   : Stream_Element_Array;
      Iterations  : Natural;
      Output_Size : Natural;
      Prf_Kind    : PBKDF2_PRF) return Stream_Element_Array
   is
      Pass_Data : Stream_Element_Array := String_To_Bytes (Passphrase);
      Result    :
        Stream_Element_Array (1 .. Stream_Element_Offset (Output_Size)) :=
        [others => 0];
   begin
      if Iterations = 0 or else Output_Size = 0 then
         Pass_Data := [others => 0];
         return Result;
      end if;
      case Prf_Kind is
         when PBKDF2_HMAC_SHA1 =>
            Result :=
              CryptoLib.Macs.PBKDF2_HMAC_SHA1
                (Pass_Data, Salt_Data, Positive (Iterations), Output_Size);

         when PBKDF2_HMAC_SHA256 =>
            Result :=
              CryptoLib.Macs.PBKDF2_HMAC_SHA256
                (Pass_Data, Salt_Data, Positive (Iterations), Output_Size);

         when PBKDF2_HMAC_SHA384 =>
            Result :=
              CryptoLib.Macs.PBKDF2_HMAC_SHA384
                (Pass_Data, Salt_Data, Positive (Iterations), Output_Size);

         when PBKDF2_HMAC_SHA512 =>
            Result :=
              CryptoLib.Macs.PBKDF2_HMAC_SHA512
                (Pass_Data, Salt_Data, Positive (Iterations), Output_Size);
      end case;
      Pass_Data := [others => 0];
      return Result;
   exception
      when others =>
         return [1 .. Stream_Element_Offset (Output_Size) => 0];
   end PBKDF2_HMAC;

   type PBKDF1_Hash is (PBKDF1_MD5, PBKDF1_SHA1);

   function PBKDF1
     (Passphrase  : String;
      Salt_Data   : Stream_Element_Array;
      Iterations  : Natural;
      Output_Size : Natural;
      Hash_Kind   : PBKDF1_Hash) return Stream_Element_Array
   is
      Pass_Data : Stream_Element_Array := String_To_Bytes (Passphrase);
      Result    :
        Stream_Element_Array (1 .. Stream_Element_Offset (Output_Size)) :=
        [others => 0];
   begin
      if Iterations = 0 or else Output_Size = 0 then
         Pass_Data := [others => 0];
         return Result;
      end if;
      case Hash_Kind is
         when PBKDF1_MD5 =>
            Result :=
              CryptoLib.Macs.PBKDF1_MD5
                (Pass_Data, Salt_Data, Positive (Iterations), Output_Size);

         when PBKDF1_SHA1 =>
            Result :=
              CryptoLib.Macs.PBKDF1_SHA1
                (Pass_Data, Salt_Data, Positive (Iterations), Output_Size);
      end case;
      Pass_Data := [others => 0];
      return Result;
   exception
      when others =>
         return [1 .. Stream_Element_Offset (Output_Size) => 0];
   end PBKDF1;

   function PKCS12_KDF_SHA1
     (Passphrase  : String;
      Salt_Data   : Stream_Element_Array;
      Iterations  : Natural;
      Id_Byte     : Stream_Element;
      Output_Size : Natural) return Stream_Element_Array
   is
      Pass_Data : Stream_Element_Array := String_To_Bytes (Passphrase);
      Result    :
        Stream_Element_Array (1 .. Stream_Element_Offset (Output_Size)) :=
        [others => 0];
   begin
      if Iterations = 0 or else Output_Size = 0 then
         Pass_Data := [others => 0];
         return Result;
      end if;
      Result :=
        CryptoLib.Macs.PKCS12_KDF_SHA1
          (Pass_Data, Salt_Data, Positive (Iterations), Id_Byte, Output_Size);
      Pass_Data := [others => 0];
      return Result;
   exception
      when others =>
         return [1 .. Stream_Element_Offset (Output_Size) => 0];
   end PKCS12_KDF_SHA1;

   function Scrypt_SHA256
     (Passphrase  : String;
      Salt_Data   : Stream_Element_Array;
      N_Value     : Natural;
      R_Value     : Natural;
      P_Value     : Natural;
      Output_Size : Natural) return Stream_Element_Array
   is
      Pass_Data : Stream_Element_Array := String_To_Bytes (Passphrase);
      Result    :
        Stream_Element_Array (1 .. Stream_Element_Offset (Output_Size)) :=
        [others => 0];
   begin
      if N_Value = 0
        or else R_Value = 0
        or else P_Value = 0
        or else Output_Size = 0
      then
         Pass_Data := [others => 0];
         return Result;
      end if;
      Result :=
        CryptoLib.Macs.Scrypt_SHA256
          (Pass_Data,
           Salt_Data,
           Positive (N_Value),
           Positive (R_Value),
           Positive (P_Value),
           Output_Size);
      Pass_Data := [others => 0];
      return Result;
   exception
      when others =>
         return [1 .. Stream_Element_Offset (Output_Size) => 0];
   end Scrypt_SHA256;

   function Decrypt_PKCS8_Encrypted_Binary
     (Data       : Stream_Element_Array;
      Passphrase : String;
      Plaintext  : out Packet_Buffer) return Status
   is
      PBES1_MD5_DES_CBC_OID                   :
        constant Stream_Element_Array (1 .. 11) :=
          [16#06#,
           16#09#,
           16#2A#,
           16#86#,
           16#48#,
           16#86#,
           16#F7#,
           16#0D#,
           16#01#,
           16#05#,
           16#03#];
      PBES1_SHA1_DES_CBC_OID                  :
        constant Stream_Element_Array (1 .. 11) :=
          [16#06#,
           16#09#,
           16#2A#,
           16#86#,
           16#48#,
           16#86#,
           16#F7#,
           16#0D#,
           16#01#,
           16#05#,
           16#0A#];
      PKCS12_SHA1_3DES_CBC_OID                :
        constant Stream_Element_Array (1 .. 12) :=
          [16#06#,
           16#0A#,
           16#2A#,
           16#86#,
           16#48#,
           16#86#,
           16#F7#,
           16#0D#,
           16#01#,
           16#0C#,
           16#01#,
           16#03#];
      PKCS12_SHA1_2DES_CBC_OID                :
        constant Stream_Element_Array (1 .. 12) :=
          [16#06#,
           16#0A#,
           16#2A#,
           16#86#,
           16#48#,
           16#86#,
           16#F7#,
           16#0D#,
           16#01#,
           16#0C#,
           16#01#,
           16#04#];
      PKCS12_SHA1_RC2_40_CBC_OID              :
        constant Stream_Element_Array (1 .. 12) :=
          [16#06#,
           16#0A#,
           16#2A#,
           16#86#,
           16#48#,
           16#86#,
           16#F7#,
           16#0D#,
           16#01#,
           16#0C#,
           16#01#,
           16#06#];
      PKCS12_SHA1_RC2_128_CBC_OID             :
        constant Stream_Element_Array (1 .. 12) :=
          [16#06#,
           16#0A#,
           16#2A#,
           16#86#,
           16#48#,
           16#86#,
           16#F7#,
           16#0D#,
           16#01#,
           16#0C#,
           16#01#,
           16#05#];
      PBES2_OID                               :
        constant Stream_Element_Array (1 .. 11) :=
          [16#06#,
           16#09#,
           16#2A#,
           16#86#,
           16#48#,
           16#86#,
           16#F7#,
           16#0D#,
           16#01#,
           16#05#,
           16#0D#];
      PBKDF2_OID                              :
        constant Stream_Element_Array (1 .. 11) :=
          [16#06#,
           16#09#,
           16#2A#,
           16#86#,
           16#48#,
           16#86#,
           16#F7#,
           16#0D#,
           16#01#,
           16#05#,
           16#0C#];
      SCRYPT_OID                              :
        constant Stream_Element_Array (1 .. 11) :=
          [16#06#,
           16#09#,
           16#2B#,
           16#06#,
           16#01#,
           16#04#,
           16#01#,
           16#DA#,
           16#47#,
           16#04#,
           16#0B#];
      HMAC_SHA1_OID                           :
        constant Stream_Element_Array (1 .. 10) :=
          [16#06#,
           16#08#,
           16#2A#,
           16#86#,
           16#48#,
           16#86#,
           16#F7#,
           16#0D#,
           16#02#,
           16#07#];
      HMAC_SHA256_OID                         :
        constant Stream_Element_Array (1 .. 10) :=
          [16#06#,
           16#08#,
           16#2A#,
           16#86#,
           16#48#,
           16#86#,
           16#F7#,
           16#0D#,
           16#02#,
           16#09#];
      HMAC_SHA384_OID                         :
        constant Stream_Element_Array (1 .. 10) :=
          [16#06#,
           16#08#,
           16#2A#,
           16#86#,
           16#48#,
           16#86#,
           16#F7#,
           16#0D#,
           16#02#,
           16#0A#];
      HMAC_SHA512_OID                         :
        constant Stream_Element_Array (1 .. 10) :=
          [16#06#,
           16#08#,
           16#2A#,
           16#86#,
           16#48#,
           16#86#,
           16#F7#,
           16#0D#,
           16#02#,
           16#0B#];
      AES128_CBC_OID                          :
        constant Stream_Element_Array (1 .. 11) :=
          [16#06#,
           16#09#,
           16#60#,
           16#86#,
           16#48#,
           16#01#,
           16#65#,
           16#03#,
           16#04#,
           16#01#,
           16#02#];
      AES192_CBC_OID                          :
        constant Stream_Element_Array (1 .. 11) :=
          [16#06#,
           16#09#,
           16#60#,
           16#86#,
           16#48#,
           16#01#,
           16#65#,
           16#03#,
           16#04#,
           16#01#,
           16#16#];
      AES256_CBC_OID                          :
        constant Stream_Element_Array (1 .. 11) :=
          [16#06#,
           16#09#,
           16#60#,
           16#86#,
           16#48#,
           16#01#,
           16#65#,
           16#03#,
           16#04#,
           16#01#,
           16#2A#];
      DES_EDE3_CBC_OID                        :
        constant Stream_Element_Array (1 .. 10) :=
          [16#06#,
           16#08#,
           16#2A#,
           16#86#,
           16#48#,
           16#86#,
           16#F7#,
           16#0D#,
           16#03#,
           16#07#];
      DES_CBC_OID                             :
        constant Stream_Element_Array (1 .. 7) :=
          [16#06#, 16#05#, 16#2B#, 16#0E#, 16#03#, 16#02#, 16#07#];
      RC2_CBC_OID                             :
        constant Stream_Element_Array (1 .. 10) :=
          [16#06#,
           16#08#,
           16#2A#,
           16#86#,
           16#48#,
           16#86#,
           16#F7#,
           16#0D#,
           16#03#,
           16#02#];
      Seq_First, Seq_Last                     : Stream_Element_Offset;
      Alg_First, Alg_Last                     : Stream_Element_Offset;
      Params_First, Params_Last               : Stream_Element_Offset;
      Kdf_First, Kdf_Last                     : Stream_Element_Offset;
      Kdf_Params_First, Kdf_Params_Last       : Stream_Element_Offset;
      Enc_First, Enc_Last                     : Stream_Element_Offset;
      Scheme_Params_First, Scheme_Params_Last : Stream_Element_Offset;
      Cursor                                  : Stream_Element_Offset;
      Params_Cursor                           : Stream_Element_Offset;
      Kdf_Cursor                              : Stream_Element_Offset;
      Kdf_Params_Cursor                       : Stream_Element_Offset;
      Scheme_Cursor                           : Stream_Element_Offset;
      Salt_Buffer                             : Packet_Buffer;
      IV_Buffer                               : Packet_Buffer;
      Cipher_Buffer                           : Packet_Buffer;
      Iterations                              : Natural := 0;
      Key_Length                              : Natural := 0;
      Block_Length                            : Natural := 16;
      Prf_Kind                                : PBKDF2_PRF := PBKDF2_HMAC_SHA1;
      Use_Scrypt                              : Boolean := False;
      Scrypt_N                                : Natural := 0;
      Scrypt_R                                : Natural := 0;
      Scrypt_P                                : Natural := 0;
      Algorithm_Name                          : Unbounded_String;
      Status_Value                            : Status;
   begin
      Clear (Plaintext);
      if Passphrase'Length = 0 then
         return Authentication_Failed;
      end if;
      Status_Value :=
        Decode_DER_Header (Data, Data'First, 16#30#, Seq_First, Seq_Last);
      if Status_Value /= Ok or else Seq_Last /= Data'Last then
         return Authentication_Failed;
      end if;
      Cursor := Seq_First;
      Status_Value :=
        Decode_DER_Header (Data, Cursor, 16#30#, Alg_First, Alg_Last);
      if Status_Value /= Ok then
         return Authentication_Failed;
      end if;
      Cursor := Alg_Last + 1;
      Status_Value := DER_Octet_String (Data, Cursor, Cipher_Buffer);
      if Status_Value /= Ok or else Cursor /= Seq_Last + 1 then
         Clear (Cipher_Buffer);
         return Authentication_Failed;
      end if;

      if Bytes_Equal (Data, Alg_First, PBES1_MD5_DES_CBC_OID)
        or else Bytes_Equal (Data, Alg_First, PBES1_SHA1_DES_CBC_OID)
      then
         declare
            PBES1_Params_Cursor : Stream_Element_Offset :=
              Alg_First
              + (if Bytes_Equal (Data, Alg_First, PBES1_MD5_DES_CBC_OID)
                 then Stream_Element_Offset (PBES1_MD5_DES_CBC_OID'Length)
                 else Stream_Element_Offset
                   (PBES1_SHA1_DES_CBC_OID'Length));
            Hash_Kind           : constant PBKDF1_Hash :=
              (if Bytes_Equal (Data, Alg_First, PBES1_MD5_DES_CBC_OID)
               then PBKDF1_MD5
               else PBKDF1_SHA1);
            PBES1_Params_First  : Stream_Element_Offset;
            PBES1_Params_Last   : Stream_Element_Offset;
         begin
            Status_Value :=
              Decode_DER_Header
                (Data,
                 PBES1_Params_Cursor,
                 16#30#,
                 PBES1_Params_First,
                 PBES1_Params_Last);
            if Status_Value /= Ok or else PBES1_Params_Last /= Alg_Last then
               Clear (Cipher_Buffer);
               return Authentication_Failed;
            end if;

            PBES1_Params_Cursor := PBES1_Params_First;
            Status_Value :=
              DER_Octet_String (Data, PBES1_Params_Cursor, Salt_Buffer);
            if Status_Value /= Ok then
               Clear (Cipher_Buffer);
               Clear (Salt_Buffer);
               return Status_Value;
            end if;
            Status_Value :=
              DER_Integer_Natural (Data, PBES1_Params_Cursor, Iterations);
            if Status_Value /= Ok
              or else PBES1_Params_Cursor /= PBES1_Params_Last + 1
            then
               Clear (Cipher_Buffer);
               Clear (Salt_Buffer);
               return Authentication_Failed;
            end if;
            if Iterations = 0
              or else Iterations > 2_000_000
              or else Length (Salt_Buffer) /= 8
            then
               Clear (Cipher_Buffer);
               Clear (Salt_Buffer);
               return Unsupported_Feature;
            end if;

            declare
               Salt_Data      : constant Stream_Element_Array :=
                 To_Array (Salt_Buffer);
               Cipher_Data    : constant Stream_Element_Array :=
                 To_Array (Cipher_Buffer);
               Derived_Data   : Stream_Element_Array :=
                 PBKDF1 (Passphrase, Salt_Data, Iterations, 16, Hash_Kind);
               Key_Data       : Stream_Element_Array (1 .. 8) :=
                 Derived_Data (1 .. 8);
               IV_Data        : Stream_Element_Array (1 .. 8) :=
                 Derived_Data (9 .. 16);
               Decrypted_Data : Stream_Element_Array (Cipher_Data'Range) :=
                 [others => 0];
            begin
               Status_Value :=
                 CryptoLib.Ciphers.Decrypt_CBC_Raw
                   ("des-cbc",
                    Key_Data,
                    IV_Data,
                    Cipher_Data,
                    Decrypted_Data);
               Derived_Data := [others => 0];
               Key_Data := [others => 0];
               IV_Data := [others => 0];
               Clear (Salt_Buffer);
               Clear (Cipher_Buffer);
               if Status_Value /= Ok then
                  Decrypted_Data := [others => 0];
                  return Status_Value;
               end if;
               Status_Value := PKCS7_Unpad (Decrypted_Data, Plaintext, 8);
               Decrypted_Data := [others => 0];
               return Status_Value;
            end;
         end;
      elsif Bytes_Equal (Data, Alg_First, PKCS12_SHA1_3DES_CBC_OID)
        or else Bytes_Equal (Data, Alg_First, PKCS12_SHA1_2DES_CBC_OID)
        or else Bytes_Equal (Data, Alg_First, PKCS12_SHA1_RC2_40_CBC_OID)
        or else Bytes_Equal (Data, Alg_First, PKCS12_SHA1_RC2_128_CBC_OID)
      then
         declare
            PKCS12_Params_Cursor : Stream_Element_Offset :=
              Alg_First
              + (if Bytes_Equal (Data, Alg_First, PKCS12_SHA1_3DES_CBC_OID)
                 then Stream_Element_Offset
                   (PKCS12_SHA1_3DES_CBC_OID'Length)
                 elsif Bytes_Equal (Data, Alg_First, PKCS12_SHA1_2DES_CBC_OID)
                 then Stream_Element_Offset
                   (PKCS12_SHA1_2DES_CBC_OID'Length)
                 elsif Bytes_Equal
                   (Data, Alg_First, PKCS12_SHA1_RC2_40_CBC_OID)
                 then Stream_Element_Offset
                   (PKCS12_SHA1_RC2_40_CBC_OID'Length)
                 else Stream_Element_Offset
                   (PKCS12_SHA1_RC2_128_CBC_OID'Length));
            Raw_Key_Length       : constant Natural :=
              (if Bytes_Equal (Data, Alg_First, PKCS12_SHA1_3DES_CBC_OID)
               then 24
               elsif Bytes_Equal (Data, Alg_First, PKCS12_SHA1_2DES_CBC_OID)
               then 16
               elsif Bytes_Equal (Data, Alg_First, PKCS12_SHA1_RC2_40_CBC_OID)
               then 5
               else 16);
            PKCS12_Algorithm     : constant Unbounded_String :=
              (if Bytes_Equal (Data, Alg_First, PKCS12_SHA1_RC2_40_CBC_OID)
               then To_Unbounded_String ("rc2-40-cbc")
               elsif Bytes_Equal
                 (Data, Alg_First, PKCS12_SHA1_RC2_128_CBC_OID)
               then To_Unbounded_String ("rc2-128-cbc")
               else To_Unbounded_String ("3des-cbc"));
            PKCS12_Key_Length    : constant Natural :=
              (if Bytes_Equal (Data, Alg_First, PKCS12_SHA1_RC2_40_CBC_OID)
               then 5
               elsif Bytes_Equal
                 (Data, Alg_First, PKCS12_SHA1_RC2_128_CBC_OID)
               then 16
               else 24);
            PKCS12_Params_First  : Stream_Element_Offset;
            PKCS12_Params_Last   : Stream_Element_Offset;
         begin
            Status_Value :=
              Decode_DER_Header
                (Data,
                 PKCS12_Params_Cursor,
                 16#30#,
                 PKCS12_Params_First,
                 PKCS12_Params_Last);
            if Status_Value /= Ok or else PKCS12_Params_Last /= Alg_Last then
               Clear (Cipher_Buffer);
               return Authentication_Failed;
            end if;

            PKCS12_Params_Cursor := PKCS12_Params_First;
            Status_Value :=
              DER_Octet_String (Data, PKCS12_Params_Cursor, Salt_Buffer);
            if Status_Value /= Ok then
               Clear (Cipher_Buffer);
               Clear (Salt_Buffer);
               return Status_Value;
            end if;
            Status_Value :=
              DER_Integer_Natural (Data, PKCS12_Params_Cursor, Iterations);
            if Status_Value /= Ok
              or else PKCS12_Params_Cursor /= PKCS12_Params_Last + 1
            then
               Clear (Cipher_Buffer);
               Clear (Salt_Buffer);
               return Authentication_Failed;
            end if;
            if Iterations = 0
              or else Iterations > 2_000_000
              or else Length (Salt_Buffer) /= 8
            then
               Clear (Cipher_Buffer);
               Clear (Salt_Buffer);
               return Unsupported_Feature;
            end if;

            declare
               Salt_Data      : constant Stream_Element_Array :=
                 To_Array (Salt_Buffer);
               Cipher_Data    : constant Stream_Element_Array :=
                 To_Array (Cipher_Buffer);
               Raw_Key_Data   : Stream_Element_Array :=
                 PKCS12_KDF_SHA1
                   (Passphrase,
                    Salt_Data,
                    Iterations,
                    1,
                    (if To_String (PKCS12_Algorithm) = "rc2-40-cbc"
                     then 5
                     else Raw_Key_Length));
               Key_Data       :
                 Stream_Element_Array (1 .. Stream_Element_Offset (PKCS12_Key_Length)) :=
                 [others => 0];
               IV_Data        : Stream_Element_Array :=
                 PKCS12_KDF_SHA1 (Passphrase, Salt_Data, Iterations, 2, 8);
               Decrypted_Data : Stream_Element_Array (Cipher_Data'Range) :=
                 [others => 0];
            begin
               Key_Data (1 .. Stream_Element_Offset (Raw_Key_Data'Length)) :=
                 Raw_Key_Data;
               if To_String (PKCS12_Algorithm) = "3des-cbc"
                 and then Raw_Key_Length = 16
               then
                  Key_Data (17 .. 24) := Raw_Key_Data (1 .. 8);
               end if;
               Status_Value :=
                 CryptoLib.Ciphers.Decrypt_CBC_Raw
                   (To_String (PKCS12_Algorithm),
                    Key_Data,
                    IV_Data,
                    Cipher_Data,
                    Decrypted_Data);
               Raw_Key_Data := [others => 0];
               Key_Data := [others => 0];
               IV_Data := [others => 0];
               Clear (Salt_Buffer);
               Clear (Cipher_Buffer);
               if Status_Value /= Ok then
                  Decrypted_Data := [others => 0];
                  return Status_Value;
               end if;
               Status_Value := PKCS7_Unpad (Decrypted_Data, Plaintext, 8);
               Decrypted_Data := [others => 0];
               return Status_Value;
            end;
         end;
      elsif not Bytes_Equal (Data, Alg_First, PBES2_OID) then
         Clear (Cipher_Buffer);
         return Unsupported_Feature;
      end if;
      Params_Cursor := Alg_First + Stream_Element_Offset (PBES2_OID'Length);
      Status_Value :=
        Decode_DER_Header
          (Data, Params_Cursor, 16#30#, Params_First, Params_Last);
      if Status_Value /= Ok or else Params_Last /= Alg_Last then
         Clear (Cipher_Buffer);
         return Authentication_Failed;
      end if;

      Params_Cursor := Params_First;
      Status_Value :=
        Decode_DER_Header (Data, Params_Cursor, 16#30#, Kdf_First, Kdf_Last);
      if Status_Value /= Ok then
         Clear (Cipher_Buffer);
         return Authentication_Failed;
      end if;
      Params_Cursor := Kdf_Last + 1;
      Status_Value :=
        Decode_DER_Header (Data, Params_Cursor, 16#30#, Enc_First, Enc_Last);
      if Status_Value /= Ok or else Enc_Last /= Params_Last then
         Clear (Cipher_Buffer);
         return Authentication_Failed;
      end if;

      if Bytes_Equal (Data, Kdf_First, PBKDF2_OID) then
         Kdf_Cursor := Kdf_First + Stream_Element_Offset (PBKDF2_OID'Length);
         Status_Value :=
           Decode_DER_Header
             (Data, Kdf_Cursor, 16#30#, Kdf_Params_First, Kdf_Params_Last);
         if Status_Value /= Ok or else Kdf_Params_Last /= Kdf_Last then
            Clear (Cipher_Buffer);
            return Authentication_Failed;
         end if;
         Kdf_Params_Cursor := Kdf_Params_First;
         Status_Value := DER_Octet_String (Data, Kdf_Params_Cursor, Salt_Buffer);
         if Status_Value /= Ok then
            Clear (Cipher_Buffer);
            return Status_Value;
         end if;
         Status_Value :=
           DER_Integer_Natural (Data, Kdf_Params_Cursor, Iterations);
         if Status_Value /= Ok then
            Clear (Cipher_Buffer);
            Clear (Salt_Buffer);
            return Status_Value;
         end if;
         if Iterations = 0 or else Iterations > 2_000_000 then
            Clear (Cipher_Buffer);
            Clear (Salt_Buffer);
            return Unsupported_Feature;
         end if;
         if Kdf_Params_Cursor <= Kdf_Params_Last
           and then Data (Kdf_Params_Cursor) = 16#02#
         then
            Status_Value :=
              DER_Integer_Natural (Data, Kdf_Params_Cursor, Key_Length);
            if Status_Value /= Ok then
               Clear (Cipher_Buffer);
               Clear (Salt_Buffer);
               return Status_Value;
            end if;
         end if;
         if Kdf_Params_Cursor <= Kdf_Params_Last then
            declare
               Prf_First, Prf_Last : Stream_Element_Offset;
            begin
               Status_Value :=
                 Decode_DER_Header
                   (Data, Kdf_Params_Cursor, 16#30#, Prf_First, Prf_Last);
               if Status_Value /= Ok or else Prf_Last /= Kdf_Params_Last then
                  Clear (Cipher_Buffer);
                  Clear (Salt_Buffer);
                  return Authentication_Failed;
               end if;
               if Bytes_Equal (Data, Prf_First, HMAC_SHA1_OID) then
                  Prf_Kind := PBKDF2_HMAC_SHA1;
               elsif Bytes_Equal (Data, Prf_First, HMAC_SHA256_OID) then
                  Prf_Kind := PBKDF2_HMAC_SHA256;
               elsif Bytes_Equal (Data, Prf_First, HMAC_SHA384_OID) then
                  Prf_Kind := PBKDF2_HMAC_SHA384;
               elsif Bytes_Equal (Data, Prf_First, HMAC_SHA512_OID) then
                  Prf_Kind := PBKDF2_HMAC_SHA512;
               else
                  Clear (Cipher_Buffer);
                  Clear (Salt_Buffer);
                  return Unsupported_Feature;
               end if;
            end;
         else
            Prf_Kind := PBKDF2_HMAC_SHA1;
         end if;
      elsif Bytes_Equal (Data, Kdf_First, SCRYPT_OID) then
         Use_Scrypt := True;
         Kdf_Cursor := Kdf_First + Stream_Element_Offset (SCRYPT_OID'Length);
         Status_Value :=
           Decode_DER_Header
             (Data, Kdf_Cursor, 16#30#, Kdf_Params_First, Kdf_Params_Last);
         if Status_Value /= Ok or else Kdf_Params_Last /= Kdf_Last then
            Clear (Cipher_Buffer);
            return Authentication_Failed;
         end if;
         Kdf_Params_Cursor := Kdf_Params_First;
         Status_Value := DER_Octet_String (Data, Kdf_Params_Cursor, Salt_Buffer);
         if Status_Value /= Ok then
            Clear (Cipher_Buffer);
            return Status_Value;
         end if;
         Status_Value := DER_Integer_Natural (Data, Kdf_Params_Cursor, Scrypt_N);
         if Status_Value = Ok then
            Status_Value :=
              DER_Integer_Natural (Data, Kdf_Params_Cursor, Scrypt_R);
         end if;
         if Status_Value = Ok then
            Status_Value :=
              DER_Integer_Natural (Data, Kdf_Params_Cursor, Scrypt_P);
         end if;
         if Status_Value /= Ok then
            Clear (Cipher_Buffer);
            Clear (Salt_Buffer);
            return Status_Value;
         end if;
         if Kdf_Params_Cursor <= Kdf_Params_Last then
            Status_Value :=
              DER_Integer_Natural (Data, Kdf_Params_Cursor, Key_Length);
            if Status_Value /= Ok then
               Clear (Cipher_Buffer);
               Clear (Salt_Buffer);
               return Status_Value;
            end if;
         end if;
         if Kdf_Params_Cursor /= Kdf_Params_Last + 1
           or else Scrypt_N = 0
           or else Scrypt_N > 16_384
           or else Scrypt_R = 0
           or else Scrypt_R > 32
           or else Scrypt_P = 0
           or else Scrypt_P > 32
         then
            Clear (Cipher_Buffer);
            Clear (Salt_Buffer);
            return Unsupported_Feature;
         end if;
      else
         Clear (Cipher_Buffer);
         return Unsupported_Feature;
      end if;

      Scheme_Cursor := Enc_First;
      if Bytes_Equal (Data, Scheme_Cursor, AES128_CBC_OID) then
         Algorithm_Name := To_Unbounded_String ("aes128-cbc");
         if Key_Length = 0 then
            Key_Length := 16;
         end if;
         Scheme_Cursor :=
           Scheme_Cursor + Stream_Element_Offset (AES128_CBC_OID'Length);
      elsif Bytes_Equal (Data, Scheme_Cursor, AES192_CBC_OID) then
         Algorithm_Name := To_Unbounded_String ("aes192-cbc");
         if Key_Length = 0 then
            Key_Length := 24;
         end if;
         Scheme_Cursor :=
           Scheme_Cursor + Stream_Element_Offset (AES192_CBC_OID'Length);
      elsif Bytes_Equal (Data, Scheme_Cursor, AES256_CBC_OID) then
         Algorithm_Name := To_Unbounded_String ("aes256-cbc");
         if Key_Length = 0 then
            Key_Length := 32;
         end if;
         Scheme_Cursor :=
           Scheme_Cursor + Stream_Element_Offset (AES256_CBC_OID'Length);
      elsif Bytes_Equal (Data, Scheme_Cursor, DES_EDE3_CBC_OID) then
         Algorithm_Name := To_Unbounded_String ("3des-cbc");
         if Key_Length = 0 then
            Key_Length := 24;
         end if;
         Block_Length := 8;
         Scheme_Cursor :=
           Scheme_Cursor + Stream_Element_Offset (DES_EDE3_CBC_OID'Length);
      elsif Bytes_Equal (Data, Scheme_Cursor, DES_CBC_OID) then
         Algorithm_Name := To_Unbounded_String ("des-cbc");
         if Key_Length = 0 then
            Key_Length := 8;
         end if;
         Block_Length := 8;
         Scheme_Cursor :=
           Scheme_Cursor + Stream_Element_Offset (DES_CBC_OID'Length);
      elsif Bytes_Equal (Data, Scheme_Cursor, RC2_CBC_OID) then
         Algorithm_Name := To_Unbounded_String ("rc2-40-cbc");
         Block_Length := 8;
         Scheme_Cursor :=
           Scheme_Cursor + Stream_Element_Offset (RC2_CBC_OID'Length);
      else
         Clear (Cipher_Buffer);
         Clear (Salt_Buffer);
         return Unsupported_Feature;
      end if;
      if Key_Length /= 0 and then Key_Length not in 5 | 8 | 16 | 24 | 32 then
         Clear (Cipher_Buffer);
         Clear (Salt_Buffer);
         return Unsupported_Feature;
      end if;
      if To_String (Algorithm_Name) = "rc2-40-cbc" then
         declare
            RC2_Params_Cursor : Stream_Element_Offset := Scheme_Cursor;
            RC2_First         : Stream_Element_Offset;
            RC2_Last          : Stream_Element_Offset;
            RC2_Version       : Natural := 0;
            Expected_Length   : Natural := 0;
         begin
            Status_Value :=
              Decode_DER_Header
                (Data, RC2_Params_Cursor, 16#30#, RC2_First, RC2_Last);
            if Status_Value /= Ok or else RC2_Last /= Enc_Last then
               Clear (Cipher_Buffer);
               Clear (Salt_Buffer);
               return Authentication_Failed;
            end if;
            RC2_Params_Cursor := RC2_First;
            Status_Value :=
              DER_Integer_Natural (Data, RC2_Params_Cursor, RC2_Version);
            if Status_Value /= Ok then
               Clear (Cipher_Buffer);
               Clear (Salt_Buffer);
               return Unsupported_Feature;
            end if;
            case RC2_Version is
               when 160 =>
                  Algorithm_Name := To_Unbounded_String ("rc2-40-cbc");
                  Expected_Length := 5;
               when 120 =>
                  Algorithm_Name := To_Unbounded_String ("rc2-64-cbc");
                  Expected_Length := 8;
               when 58 =>
                  Algorithm_Name := To_Unbounded_String ("rc2-128-cbc");
                  Expected_Length := 16;
               when others =>
                  Clear (Cipher_Buffer);
                  Clear (Salt_Buffer);
                  return Unsupported_Feature;
            end case;
            if Key_Length = 0 then
               Key_Length := Expected_Length;
            elsif Key_Length /= Expected_Length then
               Clear (Cipher_Buffer);
               Clear (Salt_Buffer);
               return Unsupported_Feature;
            end if;
            Status_Value :=
              DER_Octet_String (Data, RC2_Params_Cursor, IV_Buffer);
            if Status_Value /= Ok or else RC2_Params_Cursor /= RC2_Last + 1 then
               Clear (Cipher_Buffer);
               Clear (Salt_Buffer);
               Clear (IV_Buffer);
               return Authentication_Failed;
            end if;
         end;
      else
         Status_Value :=
           Decode_DER_Header
             (Data,
              Scheme_Cursor,
              16#04#,
              Scheme_Params_First,
              Scheme_Params_Last);
         if Status_Value /= Ok or else Scheme_Params_Last /= Enc_Last then
            Clear (Cipher_Buffer);
            Clear (Salt_Buffer);
            return Authentication_Failed;
         end if;
         Status_Value :=
           Set (IV_Buffer, Data (Scheme_Params_First .. Scheme_Params_Last));
      end if;
      if Status_Value /= Ok or else Length (IV_Buffer) /= Block_Length then
         Clear (Cipher_Buffer);
         Clear (Salt_Buffer);
         Clear (IV_Buffer);
         return Authentication_Failed;
      end if;
      if Key_Length not in 5 | 8 | 16 | 24 | 32 then
         Clear (Cipher_Buffer);
         Clear (Salt_Buffer);
         Clear (IV_Buffer);
         return Unsupported_Feature;
      end if;

      declare
         Salt_Data      : constant Stream_Element_Array :=
           To_Array (Salt_Buffer);
         IV_Data        : constant Stream_Element_Array :=
           To_Array (IV_Buffer);
         Cipher_Data    : constant Stream_Element_Array :=
           To_Array (Cipher_Buffer);
         Key_Data       :
           Stream_Element_Array (1 .. Stream_Element_Offset (Key_Length)) :=
           [others => 0];
         Decrypted_Data : Stream_Element_Array (Cipher_Data'Range) :=
           [others => 0];
      begin
         if Use_Scrypt then
            Key_Data :=
              Scrypt_SHA256
                (Passphrase,
                 Salt_Data,
                 Scrypt_N,
                 Scrypt_R,
                 Scrypt_P,
                 Key_Length);
         else
            Key_Data :=
              PBKDF2_HMAC
                (Passphrase, Salt_Data, Iterations, Key_Length, Prf_Kind);
         end if;
         Status_Value :=
           CryptoLib.Ciphers.Decrypt_CBC_Raw
             (To_String (Algorithm_Name),
              Key_Data,
              IV_Data,
              Cipher_Data,
              Decrypted_Data);
         Key_Data := [others => 0];
         Clear (Salt_Buffer);
         Clear (IV_Buffer);
         Clear (Cipher_Buffer);
         if Status_Value /= Ok then
            Decrypted_Data := [others => 0];
            return Status_Value;
         end if;
         Status_Value := PKCS7_Unpad (Decrypted_Data, Plaintext, Block_Length);
         Decrypted_Data := [others => 0];
         return Status_Value;
      end;
   exception
      when others =>
         Clear (Plaintext);
         Clear (Salt_Buffer);
         Clear (IV_Buffer);
         Clear (Cipher_Buffer);
         return Internal_Error;
   end Decrypt_PKCS8_Encrypted_Binary;

   function Validate_Optional_PKCS8_Public_Key_Trailer
     (Data : Stream_Element_Array; Cursor : Stream_Element_Offset)
      return Status
   is
      Trailer_First : Stream_Element_Offset;
      Trailer_Last  : Stream_Element_Offset;
      Status_Value  : Status;
   begin
      if Cursor = Data'Last + 1 then
         return Ok;
      end if;
      if Cursor > Data'Last then
         return Authentication_Failed;
      end if;

      --  RFC 5958 OneAsymmetricKey permits an optional publicKey field
      --  after the privateKey OCTET STRING.  DER encoders seen in the wild
      --  may use either an explicitly wrapped context-specific [1]
      --  container (A1) or the implicit primitive [1] BIT STRING form (81).
      --  The identity loader already validates the real public/private pair
      --  from the inner RSA/SEC1 key material, so this compatibility field is
      --  accepted only structurally and never trusted as authoritative.
      if Data (Cursor) = 16#A1# then
         Status_Value :=
           Decode_DER_Header
             (Data, Cursor, 16#A1#, Trailer_First, Trailer_Last);
      elsif Data (Cursor) = 16#81# then
         Status_Value :=
           Decode_DER_Header
             (Data, Cursor, 16#81#, Trailer_First, Trailer_Last);
      else
         return Unsupported_Feature;
      end if;

      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if Trailer_Last /= Data'Last then
         return Authentication_Failed;
      end if;
      if Trailer_Last < Trailer_First then
         return Authentication_Failed;
      end if;
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Validate_Optional_PKCS8_Public_Key_Trailer;

   function Parse_Encrypted_PKCS8_RSA_PEM
     (Text : String; Passphrase : String; Item : out Identity_Key)
      return Status
   is
      Encoded       : Unbounded_String;
      Binary_Buffer : Packet_Buffer;
      Plain_Buffer  : Packet_Buffer;
      Status_Value  : Status;
   begin
      Clear (Item);
      Status_Value :=
        Extract_PEM_Base64
          (Text,
           "-----BEGIN ENCRYPTED PRIVATE KEY-----",
           "-----END ENCRYPTED PRIVATE KEY-----",
           Encoded);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Decode_Base64 (To_String (Encoded), Binary_Buffer);
      Encoded := Null_Unbounded_String;
      if Status_Value /= Ok then
         Clear (Binary_Buffer);
         return Status_Value;
      end if;
      Status_Value :=
        Decrypt_PKCS8_Encrypted_Binary
          (To_Array (Binary_Buffer), Passphrase, Plain_Buffer);
      Clear (Binary_Buffer);
      if Status_Value /= Ok then
         Clear (Plain_Buffer);
         if Status_Value = Internal_Error then
            return Authentication_Failed;
         end if;
         return Status_Value;
      end if;
      Status_Value :=
        Parse_PKCS8_Private_Key_Binary (To_Array (Plain_Buffer), Item);
      Clear (Plain_Buffer);
      if Status_Value = Internal_Error then
         Clear (Item);
         return Authentication_Failed;
      end if;
      return Status_Value;
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Parse_Encrypted_PKCS8_RSA_PEM;

   function Parse_PKCS8_Private_Key_Binary
     (Data : Stream_Element_Array; Item : out Identity_Key) return Status
   is
      Seq_First          : Stream_Element_Offset;
      Seq_Last           : Stream_Element_Offset;
      Alg_First          : Stream_Element_Offset;
      Alg_Last           : Stream_Element_Offset;
      Key_First          : Stream_Element_Offset;
      Key_Last           : Stream_Element_Offset;
      Cursor             : Stream_Element_Offset;
      Alg_Cursor         : Stream_Element_Offset;
      Version_Buffer     : Packet_Buffer;
      EC_Algorithm_Name  : Unbounded_String;
      Status_Value       : Status;
      RSA_Encryption_OID : constant Stream_Element_Array (1 .. 11) :=
        [1  => 16#06#,
         2  => 16#09#,
         3  => 16#2A#,
         4  => 16#86#,
         5  => 16#48#,
         6  => 16#86#,
         7  => 16#F7#,
         8  => 16#0D#,
         9  => 16#01#,
         10 => 16#01#,
         11 => 16#01#];
      EC_Public_Key_OID  : constant Stream_Element_Array (1 .. 9) :=
        [16#06#,
         16#07#,
         16#2A#,
         16#86#,
         16#48#,
         16#CE#,
         16#3D#,
         16#02#,
         16#01#];
      P256_OID           : constant Stream_Element_Array (1 .. 10) :=
        [16#06#,
         16#08#,
         16#2A#,
         16#86#,
         16#48#,
         16#CE#,
         16#3D#,
         16#03#,
         16#01#,
         16#07#];
      P384_OID           : constant Stream_Element_Array (1 .. 7) :=
        [16#06#, 16#05#, 16#2B#, 16#81#, 16#04#, 16#00#, 16#22#];
      P521_OID           : constant Stream_Element_Array (1 .. 7) :=
        [16#06#, 16#05#, 16#2B#, 16#81#, 16#04#, 16#00#, 16#23#];

      function Finish (Result : Status) return Status is
      begin
         Clear (Version_Buffer);
         if Result /= Ok then
            Clear (Item);
         end if;
         return Result;
      end Finish;
   begin
      Clear (Item);
      Status_Value :=
        Decode_DER_Header (Data, Data'First, 16#30#, Seq_First, Seq_Last);
      if Status_Value /= Ok or else Seq_Last /= Data'Last then
         return Finish (Authentication_Failed);
      end if;

      Cursor := Seq_First;
      Status_Value := Decode_DER_Integer (Data, Cursor, Version_Buffer);
      if Status_Value /= Ok then
         return Finish (Authentication_Failed);
      end if;
      declare
         Version_Data : constant Stream_Element_Array :=
           To_Array (Version_Buffer);
      begin
         if Version_Data'Length /= 1
           or else Version_Data (Version_Data'First) not in 0 | 1
         then
            return Finish (Unsupported_Feature);
         end if;
      end;

      Status_Value :=
        Decode_DER_Header (Data, Cursor, 16#30#, Alg_First, Alg_Last);
      if Status_Value /= Ok then
         return Finish (Authentication_Failed);
      end if;
      Alg_Cursor := Alg_First;

      if Bytes_Equal (Data, Alg_Cursor, RSA_Encryption_OID) then
         Alg_Cursor :=
           Alg_Cursor + Stream_Element_Offset (RSA_Encryption_OID'Length);
         if Alg_Cursor <= Alg_Last then
            if Alg_Cursor + 1 /= Alg_Last
              or else Data (Alg_Cursor) /= 16#05#
              or else Data (Alg_Cursor + 1) /= 16#00#
            then
               return Finish (Unsupported_Feature);
            end if;
         end if;
         Cursor := Alg_Last + 1;
         Status_Value :=
           Decode_DER_Header (Data, Cursor, 16#04#, Key_First, Key_Last);
         if Status_Value /= Ok or else Key_Last < Key_First then
            return Finish (Authentication_Failed);
         end if;
         Status_Value :=
           Validate_Optional_PKCS8_Public_Key_Trailer (Data, Key_Last + 1);
         if Status_Value /= Ok then
            return Finish (Status_Value);
         end if;
         Status_Value :=
           Parse_Legacy_RSA_PEM_Binary (Data (Key_First .. Key_Last), Item);
         if Status_Value /= Ok then
            return Finish (Status_Value);
         end if;
         return Finish (Ok);
      elsif Bytes_Equal (Data, Alg_Cursor, EC_Public_Key_OID) then
         Alg_Cursor :=
           Alg_Cursor + Stream_Element_Offset (EC_Public_Key_OID'Length);
         if Alg_Cursor + Stream_Element_Offset (P256_OID'Length) - 1
              = Alg_Last
           and then Bytes_Equal (Data, Alg_Cursor, P256_OID)
         then
            EC_Algorithm_Name := To_Unbounded_String ("ecdsa-sha2-nistp256");
         elsif Alg_Cursor + Stream_Element_Offset (P384_OID'Length) - 1
              = Alg_Last
           and then Bytes_Equal (Data, Alg_Cursor, P384_OID)
         then
            EC_Algorithm_Name := To_Unbounded_String ("ecdsa-sha2-nistp384");
         elsif Alg_Cursor + Stream_Element_Offset (P521_OID'Length) - 1
              = Alg_Last
           and then Bytes_Equal (Data, Alg_Cursor, P521_OID)
         then
            EC_Algorithm_Name := To_Unbounded_String ("ecdsa-sha2-nistp521");
         else
            return Finish (Unsupported_Feature);
         end if;
         if Length (EC_Algorithm_Name) = 0
         then
            return Finish (Unsupported_Feature);
         end if;
         Cursor := Alg_Last + 1;
         Status_Value :=
           Decode_DER_Header (Data, Cursor, 16#04#, Key_First, Key_Last);
         if Status_Value /= Ok or else Key_Last < Key_First then
            return Finish (Authentication_Failed);
         end if;
         Status_Value :=
           Validate_Optional_PKCS8_Public_Key_Trailer (Data, Key_Last + 1);
         if Status_Value /= Ok then
            return Finish (Status_Value);
         end if;
         Status_Value :=
           Parse_SEC1_EC_PEM_Binary
             (Data (Key_First .. Key_Last),
              Item,
              To_String (EC_Algorithm_Name));
         if Status_Value /= Ok then
            return Finish (Status_Value);
         end if;
         return Finish (Ok);
      else
         return Finish (Unsupported_Feature);
      end if;
   exception
      when others =>
         Clear (Item);
         return Finish (Internal_Error);
   end Parse_PKCS8_Private_Key_Binary;

   function Parse_PKCS8_RSA_PEM
     (Text : String; Item : out Identity_Key) return Status
   is
      Encoded       : Unbounded_String;
      Binary_Buffer : Packet_Buffer;
      Status_Value  : Status;
   begin
      Clear (Item);
      Status_Value :=
        Extract_PEM_Base64
          (Text,
           "-----BEGIN PRIVATE KEY-----",
           "-----END PRIVATE KEY-----",
           Encoded);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Decode_Base64 (To_String (Encoded), Binary_Buffer);
      Encoded := Null_Unbounded_String;
      if Status_Value /= Ok then
         Clear (Binary_Buffer);
         return Status_Value;
      end if;
      Status_Value :=
        Parse_PKCS8_Private_Key_Binary (To_Array (Binary_Buffer), Item);
      Clear (Binary_Buffer);
      if Status_Value /= Ok then
         Clear (Item);
      end if;
      return Status_Value;
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Parse_PKCS8_RSA_PEM;
   function Parse (Text : String; Item : out Identity_Key) return Status is
   begin
      return Parse (Text, "", Item);
   end Parse;

   function Parse
     (Text : String; Passphrase : String; Item : out Identity_Key)
      return Status
   is
      Encoded       : Unbounded_String;
      Binary_Buffer : Packet_Buffer;
      Status_Value  : Status;
   begin
      Clear (Item);
      if Contains_Line (Text, OpenSSH_Begin) then
         Status_Value := Extract_OpenSSH_Base64 (Text, Encoded);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         Status_Value := Decode_Base64 (To_String (Encoded), Binary_Buffer);
         Encoded := Null_Unbounded_String;
         if Status_Value /= Ok then
            Clear (Binary_Buffer);
            Clear (Item);
            return Status_Value;
         end if;
         Status_Value :=
           Parse_OpenSSH_Binary (To_Array (Binary_Buffer), Passphrase, Item);
         Clear (Binary_Buffer);
         if Status_Value /= Ok then
            Clear (Item);
         end if;
         return Status_Value;
      elsif Contains_Line (Text, "-----BEGIN RSA PRIVATE KEY-----") then
         if Is_Encrypted_PEM_Armor (Text) then
            return Parse_Encrypted_Legacy_RSA_PEM (Text, Passphrase, Item);
         end if;
         return Parse_Legacy_RSA_PEM (Text, Item);
      elsif Contains_Line (Text, "-----BEGIN EC PRIVATE KEY-----") then
         if Is_Encrypted_PEM_Armor (Text) then
            return Parse_Encrypted_Legacy_EC_PEM (Text, Passphrase, Item);
         end if;
         return Parse_Legacy_EC_PEM (Text, Item);
      elsif Contains_Line (Text, "-----BEGIN ENCRYPTED PRIVATE KEY-----") then
         return Parse_Encrypted_PKCS8_RSA_PEM (Text, Passphrase, Item);
      elsif Contains_Line (Text, "-----BEGIN PRIVATE KEY-----") then
         if Is_Encrypted_PEM_Armor (Text) then
            return Parse_Encrypted_PKCS8_RSA_PEM (Text, Passphrase, Item);
         end if;
         return Parse_PKCS8_RSA_PEM (Text, Item);
      elsif Is_Legacy_PEM_Armor (Text) then
         if Is_Encrypted_PEM_Armor (Text) then
            return Authentication_Failed;
         end if;
         return Unsupported_Feature;
      else
         return Authentication_Failed;
      end if;
   exception
      when others =>
         Clear (Item);
         return Internal_Error;
   end Parse;

   function Load (Path : String; Item : out Identity_Key) return Status is
   begin
      return Load (Path, "", Item);
   end Load;

   function Load
     (Path : String; Passphrase : String; Item : out Identity_Key)
      return Status
   is
      File_Item : Ada.Streams.Stream_IO.File_Type;
   begin
      Clear (Item);
      if Path'Length = 0 then
         return Authentication_Failed;
      end if;
      if not Ada.Directories.Exists (Path) then
         return Authentication_Failed;
      end if;

      --  A private key others can read is not a secret. Refuse it before reading it, the way
      --  OpenSSH refuses a key file that is group- or world-accessible. Hostkit answers this
      --  per host; on Windows, where access is by ACL, it does not reject (see its comment).
      if Hostkit.Fs.Accessible_By_Others (Path) then
         return Permission_Denied;
      end if;

      Ada.Streams.Stream_IO.Open
        (File_Item, Ada.Streams.Stream_IO.In_File, Path);
      declare
         Size_Value : constant Ada.Streams.Stream_IO.Count :=
           Ada.Streams.Stream_IO.Size (File_Item);
      begin
         if Size_Value > Ada.Streams.Stream_IO.Count (Max_Identity_File_Size)
         then
            Ada.Streams.Stream_IO.Close (File_Item);
            return Authentication_Failed;
         end if;
         if Size_Value = 0 then
            Ada.Streams.Stream_IO.Close (File_Item);
            return Authentication_Failed;
         end if;
         declare
            Data         :
              Stream_Element_Array (1 .. Stream_Element_Offset (Size_Value));
            Last_Index   : Stream_Element_Offset;
            Parse_Status : Status := Authentication_Failed;
         begin
            Ada.Streams.Stream_IO.Read (File_Item, Data, Last_Index);
            Ada.Streams.Stream_IO.Close (File_Item);
            if Last_Index /= Data'Last then
               Data := [others => 0];
               return Authentication_Failed;
            end if;
            declare
               Text   : String (1 .. Data'Length);
               Cursor : Positive := 1;

               function Finish_Text_Parse (Result : Status) return Status is
               begin
                  Text := [others => Character'Val (0)];
                  Data := [others => 0];
                  if Result /= Ok then
                     Clear (Item);
                  end if;
                  return Result;
               end Finish_Text_Parse;
            begin
               for Byte_Value of Data loop
                  Text (Cursor) := Character'Val (Natural (Byte_Value));
                  Cursor := Cursor + 1;
               end loop;
               Data := [others => 0];
               Parse_Status := Parse (Text, Passphrase, Item);
               return Finish_Text_Parse (Parse_Status);
            exception
               when others =>
                  return Finish_Text_Parse (Internal_Error);
            end;
         end;
      end;
   exception
      when others =>
         if Ada.Streams.Stream_IO.Is_Open (File_Item) then
            Ada.Streams.Stream_IO.Close (File_Item);
         end if;
         Clear (Item);
         return Authentication_Failed;
   end Load;

end SSH_Lib.Identity_Files;
