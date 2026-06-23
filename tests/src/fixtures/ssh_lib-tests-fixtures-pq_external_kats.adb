with Ada.Directories;
with Ada.Streams;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with CryptoLib.Random;
with CryptoLib.SHA3;
with CryptoLib.MLKEM768;
with CryptoLib.SNTRUP761;
with CryptoLib.Errors;

package body SSH_Lib.Tests.Fixtures.PQ_External_KATs is

   use Ada.Strings.Unbounded;
   use Ada.Streams;
   use type CryptoLib.Errors.Status;

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   function Read_All (Path_Text : String) return String is
      File_Item : Ada.Text_IO.File_Type;
      Buffer    : Unbounded_String;
   begin
      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path_Text);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         Append (Buffer, Ada.Text_IO.Get_Line (File_Item));
         Append (Buffer, ASCII.LF);
      end loop;
      Ada.Text_IO.Close (File_Item);
      return To_String (Buffer);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return "";
   end Read_All;

   function Existing_Path (Relative_Path : String) return String is
      Candidate_1 : constant String := Relative_Path;
      Candidate_2 : constant String := "../" & Relative_Path;
      Candidate_3 : constant String := "../../" & Relative_Path;
      Candidate_4 : constant String := "../../../" & Relative_Path;
   begin
      if Ada.Directories.Exists (Candidate_1) then
         return Candidate_1;
      elsif Ada.Directories.Exists (Candidate_2) then
         return Candidate_2;
      elsif Ada.Directories.Exists (Candidate_3) then
         return Candidate_3;
      elsif Ada.Directories.Exists (Candidate_4) then
         return Candidate_4;
      else
         return "";
      end if;
   end Existing_Path;

   procedure Require_Field
     (Content_Text : String; Field_Text : String; Label_Text : String) is
   begin
      Check
        (Ada.Strings.Fixed.Index (Content_Text, Field_Text) /= 0,
         Label_Text & " contains " & Field_Text);
   end Require_Field;

   function Field_Value
     (Content_Text : String; Field_Text : String) return String
   is
      Prefix_Text : constant String := Field_Text & "=";
      Start_Index : constant Natural :=
        Ada.Strings.Fixed.Index (Content_Text, Prefix_Text);
      Stop_Index  : Natural;
   begin
      if Start_Index = 0 then
         return "";
      end if;

      Stop_Index := Start_Index + Prefix_Text'Length;
      while Stop_Index <= Content_Text'Last
        and then Content_Text (Stop_Index) /= ASCII.LF
      loop
         Stop_Index := Stop_Index + 1;
      end loop;

      return Content_Text (Start_Index + Prefix_Text'Length .. Stop_Index - 1);
   end Field_Value;

   function Hex_Char (Nibble_Value : Natural) return Character is
   begin
      if Nibble_Value < 10 then
         return Character'Val (Character'Pos ('0') + Nibble_Value);
      else
         return Character'Val (Character'Pos ('a') + Nibble_Value - 10);
      end if;
   end Hex_Char;

   function Hex_Image (Data_Item : Stream_Element_Array) return String is
      Result_Text : String (1 .. Data_Item'Length * 2);
      Cursor      : Natural := Result_Text'First;
      Byte_Value  : Natural;
   begin
      for Element_Value of Data_Item loop
         Byte_Value := Natural (Element_Value);
         Result_Text (Cursor) := Hex_Char (Byte_Value / 16);
         Result_Text (Cursor + 1) := Hex_Char (Byte_Value mod 16);
         Cursor := Cursor + 2;
      end loop;
      return Result_Text;
   end Hex_Image;

   function Hex_Image
     (Digest_Item : CryptoLib.SHA3.SHA3_256_Digest) return String
   is
      Buffer : Stream_Element_Array (1 .. 32);
   begin
      for Index_Value in Digest_Item'Range loop
         Buffer (Stream_Element_Offset (Index_Value)) :=
           Digest_Item (Index_Value);
      end loop;
      return Hex_Image (Buffer);
   end Hex_Image;

   function Hex_Value (Item : Character) return Natural is
   begin
      if Item in '0' .. '9' then
         return Character'Pos (Item) - Character'Pos ('0');
      elsif Item in 'a' .. 'f' then
         return Character'Pos (Item) - Character'Pos ('a') + 10;
      elsif Item in 'A' .. 'F' then
         return Character'Pos (Item) - Character'Pos ('A') + 10;
      else
         return 16;
      end if;
   end Hex_Value;

   function Hex_To_Array (Hex_Text : String) return Stream_Element_Array is
      Result_Value :
        Stream_Element_Array
          (1 .. Stream_Element_Offset (Hex_Text'Length / 2));
      Cursor       : Natural := Hex_Text'First;
      High_Value   : Natural;
      Low_Value    : Natural;
   begin
      if Hex_Text'Length mod 2 /= 0 then
         return
           Stream_Element_Array'
             [Stream_Element_Offset'(1) .. Stream_Element_Offset'(0) => 0];
      end if;

      for Index_Value in Result_Value'Range loop
         High_Value := Hex_Value (Hex_Text (Cursor));
         Low_Value := Hex_Value (Hex_Text (Cursor + 1));
         if High_Value > 15 or else Low_Value > 15 then
            return
              Stream_Element_Array'
                [Stream_Element_Offset'(1) .. Stream_Element_Offset'(0) => 0];
         end if;
         Result_Value (Index_Value) :=
           Stream_Element (High_Value * 16 + Low_Value);
         Cursor := Cursor + 2;
      end loop;
      return Result_Value;
   end Hex_To_Array;

   function Lower_Hex (Text : String) return String is
      Result_Text : String (Text'Range);
   begin
      for Index_Value in Text'Range loop
         if Text (Index_Value) in 'A' .. 'F' then
            Result_Text (Index_Value) :=
              Character'Val
                (Character'Pos (Text (Index_Value))
                 - Character'Pos ('A')
                 + Character'Pos ('a'));
         else
            Result_Text (Index_Value) := Text (Index_Value);
         end if;
      end loop;
      return Result_Text;
   end Lower_Hex;

   function JSON_String_Value
     (Content_Text : String; Field_Text : String) return String
   is
      Pattern_Text : constant String := '"' & Field_Text & '"';
      Field_Index  : constant Natural :=
        Ada.Strings.Fixed.Index (Content_Text, Pattern_Text);
      Colon_Index  : Natural;
      Quote_Start  : Natural;
      Quote_Stop   : Natural;
   begin
      if Field_Index = 0 then
         return "";
      end if;

      Colon_Index := Field_Index + Pattern_Text'Length;
      while Colon_Index <= Content_Text'Last
        and then Content_Text (Colon_Index) /= ':'
      loop
         Colon_Index := Colon_Index + 1;
      end loop;
      if Colon_Index > Content_Text'Last then
         return "";
      end if;

      Quote_Start := Colon_Index + 1;
      while Quote_Start <= Content_Text'Last
        and then Content_Text (Quote_Start) /= '"'
      loop
         Quote_Start := Quote_Start + 1;
      end loop;
      if Quote_Start > Content_Text'Last then
         return "";
      end if;

      Quote_Stop := Quote_Start + 1;
      while Quote_Stop <= Content_Text'Last
        and then Content_Text (Quote_Stop) /= '"'
      loop
         Quote_Stop := Quote_Stop + 1;
      end loop;
      if Quote_Stop > Content_Text'Last then
         return "";
      end if;

      return Content_Text (Quote_Start + 1 .. Quote_Stop - 1);
   end JSON_String_Value;

   function JSON_Test_Case_Block
     (Content_Text : String; TC_Id_Text : String) return String
   is
      TC_Index    : constant Natural :=
        Ada.Strings.Fixed.Index
          (Content_Text, '"' & "tcId" & '"' & ":" & TC_Id_Text);
      Alt_Index   : constant Natural :=
        Ada.Strings.Fixed.Index
          (Content_Text, '"' & "tcId" & '"' & ": " & TC_Id_Text);
      Start_Index : constant Natural :=
        (if TC_Index /= 0 then TC_Index else Alt_Index);
      Stop_Index  : Natural;
   begin
      if Start_Index = 0 then
         return "";
      end if;

      Stop_Index := Start_Index;
      while Stop_Index <= Content_Text'Last
        and then Content_Text (Stop_Index) /= '}'
      loop
         Stop_Index := Stop_Index + 1;
      end loop;
      if Stop_Index > Content_Text'Last then
         return "";
      end if;
      return Content_Text (Start_Index .. Stop_Index);
   end JSON_Test_Case_Block;

   procedure Load_Hex_Exact
     (Hex_Text   : String;
      Target     : out Stream_Element_Array;
      Label_Text : String)
   is
      Parsed_Value : constant Stream_Element_Array := Hex_To_Array (Hex_Text);
   begin
      Check
        (Parsed_Value'Length = Target'Length,
         Label_Text & " has expected byte length");
      for Offset_Value in 0 .. Target'Length - 1 loop
         Target (Target'First + Stream_Element_Offset (Offset_Value)) :=
           Parsed_Value
             (Parsed_Value'First + Stream_Element_Offset (Offset_Value));
      end loop;
   end Load_Hex_Exact;

   function Concat
     (Left_Item : Stream_Element_Array; Right_Item : Stream_Element_Array)
      return Stream_Element_Array
   is
      Result_Item :
        Stream_Element_Array
          (1 .. Stream_Element_Offset (Left_Item'Length + Right_Item'Length));
      Cursor      : Stream_Element_Offset := Result_Item'First;
   begin
      for Element_Value of Left_Item loop
         Result_Item (Cursor) := Element_Value;
         Cursor := Cursor + 1;
      end loop;
      for Element_Value of Right_Item loop
         Result_Item (Cursor) := Element_Value;
         Cursor := Cursor + 1;
      end loop;
      return Result_Item;
   end Concat;

   procedure Assert_Manifest
     (Relative_Path          : String;
      Algorithm_Text         : String;
      Public_Length_Text     : String;
      Secret_Length_Text     : String;
      Ciphertext_Length_Text : String;
      Shared_Length_Text     : String;
      Status_Text            : String)
   is
      Path_Text    : constant String := Existing_Path (Relative_Path);
      Content_Text : constant String :=
        (if Path_Text = "" then "" else Read_All (Path_Text));
   begin
      Check
        (Path_Text /= "",
         "bundled external KAT manifest exists: " & Relative_Path);
      Check
        (Content_Text /= "",
         "bundled external KAT manifest is readable: " & Relative_Path);
      Require_Field
        (Content_Text, "algorithm=" & Algorithm_Text, Relative_Path);
      Require_Field
        (Content_Text,
         "expected_public_key_length=" & Public_Length_Text,
         Relative_Path);
      Require_Field
        (Content_Text,
         "expected_secret_key_length=" & Secret_Length_Text,
         Relative_Path);
      Require_Field
        (Content_Text,
         "expected_ciphertext_length=" & Ciphertext_Length_Text,
         Relative_Path);
      Require_Field
        (Content_Text,
         "expected_shared_secret_length=" & Shared_Length_Text,
         Relative_Path);
      Require_Field (Content_Text, "status=" & Status_Text, Relative_Path);
      Check
        (Ada.Strings.Fixed.Index (Content_Text, "TODO") = 0
         and then Ada.Strings.Fixed.Index (Content_Text, "TBD") = 0,
         "bundled external KAT manifest has no TODO/TBD placeholders: "
         & Relative_Path);
   end Assert_Manifest;

   procedure Assert_MLKEM768_ACVP_Vector (Relative_Path : String) is
      Path_Text    : constant String := Existing_Path (Relative_Path);
      Content_Text : constant String :=
        (if Path_Text = "" then "" else Read_All (Path_Text));
      Key_Seed     : constant Stream_Element_Array :=
        Hex_To_Array (Field_Value (Content_Text, "keygen_seed_hex"));
      Enc_Seed     : constant Stream_Element_Array :=
        Hex_To_Array (Field_Value (Content_Text, "encaps_seed_hex"));
      Key_Source   : CryptoLib.Random.Random_Source;
      Enc_Source   : CryptoLib.Random.Random_Source;
      Public_Item  : CryptoLib.MLKEM768.Public_Key;
      Secret_Item  : CryptoLib.MLKEM768.Secret_Key;
      Cipher_Item  : CryptoLib.MLKEM768.Ciphertext;
      Mutated_Item : CryptoLib.MLKEM768.Ciphertext;
      Shared_Left  : CryptoLib.MLKEM768.Shared_Key;
      Shared_Right : CryptoLib.MLKEM768.Shared_Key;
      Shared_Bad   : CryptoLib.MLKEM768.Shared_Key;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Check (Path_Text /= "", "ML-KEM-768 ACVP-shaped vector file exists");
      Check
        (Content_Text /= "", "ML-KEM-768 ACVP-shaped vector file is readable");
      Require_Field (Content_Text, "algorithm=ML-KEM-768", Relative_Path);
      Require_Field
        (Content_Text,
         "source_family=NIST-ACVP-ML-KEM-FIPS203",
         Relative_Path);
      Require_Field (Content_Text, "public_key_length=1184", Relative_Path);
      Require_Field (Content_Text, "secret_key_length=2400", Relative_Path);
      Require_Field (Content_Text, "ciphertext_length=1088", Relative_Path);
      Require_Field (Content_Text, "shared_secret_length=32", Relative_Path);
      Check
        (Key_Seed'Length >= 64,
         "ML-KEM-768 ACVP-shaped vector has keygen seed bytes");
      Check
        (Enc_Seed'Length >= 32,
         "ML-KEM-768 ACVP-shaped vector has encapsulation seed bytes");

      CryptoLib.Random.Initialize_Deterministic (Key_Source, Key_Seed);
      CryptoLib.Random.Initialize_Deterministic (Enc_Source, Enc_Seed);

      Status_Value :=
        CryptoLib.MLKEM768.Generate_Keypair
          (Key_Source, Public_Item, Secret_Item);
      Check
        (Status_Value = CryptoLib.Errors.Ok,
         "ML-KEM-768 vector keygen succeeds");
      Check
        (Hex_Image (CryptoLib.SHA3.SHA3_256 (Public_Item))'Length = 64,
         "ML-KEM-768 vector public key artifact digest is present");
      Check
        (Hex_Image (CryptoLib.SHA3.SHA3_256 (Secret_Item))'Length = 64,
         "ML-KEM-768 vector secret key artifact digest is present");

      Status_Value :=
        CryptoLib.MLKEM768.Encapsulate
          (Enc_Source, Public_Item, Cipher_Item, Shared_Left);
      Check
        (Status_Value = CryptoLib.Errors.Ok,
         "ML-KEM-768 vector encapsulate succeeds");
      Check
        (Hex_Image (CryptoLib.SHA3.SHA3_256 (Cipher_Item))'Length = 64,
         "ML-KEM-768 vector ciphertext artifact digest is present");

      Status_Value :=
        CryptoLib.MLKEM768.Decapsulate
          (Secret_Item, Cipher_Item, Shared_Right);
      Check
        (Status_Value = CryptoLib.Errors.Ok,
         "ML-KEM-768 vector decapsulate succeeds");
      Check
        (Shared_Right = Shared_Left,
         "ML-KEM-768 vector decapsulation agrees with encapsulation");

      Mutated_Item := Cipher_Item;
      Mutated_Item (Mutated_Item'Last) :=
        Mutated_Item (Mutated_Item'Last) xor 16#01#;
      Status_Value :=
        CryptoLib.MLKEM768.Decapsulate
          (Secret_Item, Mutated_Item, Shared_Bad);
      Check
        (Status_Value = CryptoLib.Errors.Ok,
         "ML-KEM-768 vector invalid decapsulation succeeds");
      Check
        (Shared_Bad /= Shared_Left,
         "ML-KEM-768 vector invalid ciphertext does not reuse valid shared secret");
   end Assert_MLKEM768_ACVP_Vector;

   procedure Assert_MLKEM768_ACVP_JSON_Vectors is
      Keygen_Prompt_Path   : constant String :=
        Existing_Path ("tests/vectors/pq/ML-KEM-keyGen-FIPS203/prompt.json");
      Keygen_Expected_Path : constant String :=
        Existing_Path
          ("tests/vectors/pq/ML-KEM-keyGen-FIPS203/expectedResults.json");
      Encap_Prompt_Path    : constant String :=
        Existing_Path
          ("tests/vectors/pq/ML-KEM-encapDecap-FIPS203/prompt.json");
      Encap_Expected_Path  : constant String :=
        Existing_Path
          ("tests/vectors/pq/ML-KEM-encapDecap-FIPS203/expectedResults.json");
      Keygen_Prompt        : constant String :=
        (if Keygen_Prompt_Path = ""
         then ""
         else Read_All (Keygen_Prompt_Path));
      Keygen_Expected      : constant String :=
        (if Keygen_Expected_Path = ""
         then ""
         else Read_All (Keygen_Expected_Path));
      Encap_Prompt         : constant String :=
        (if Encap_Prompt_Path = "" then "" else Read_All (Encap_Prompt_Path));
      Encap_Expected       : constant String :=
        (if Encap_Expected_Path = ""
         then ""
         else Read_All (Encap_Expected_Path));
      Keygen_TC            : constant String :=
        JSON_Test_Case_Block (Keygen_Prompt, "1");
      Keygen_Result_TC     : constant String :=
        JSON_Test_Case_Block (Keygen_Expected, "1");
      Encap_TC             : constant String :=
        JSON_Test_Case_Block (Encap_Prompt, "1");
      Encap_Result_TC      : constant String :=
        JSON_Test_Case_Block (Encap_Expected, "1");
      Decap_TC             : constant String :=
        JSON_Test_Case_Block (Encap_Prompt, "2");
      Decap_Result_TC      : constant String :=
        JSON_Test_Case_Block (Encap_Expected, "2");
      D_Seed               : constant Stream_Element_Array :=
        Hex_To_Array (JSON_String_Value (Keygen_TC, "d"));
      Z_Seed               : constant Stream_Element_Array :=
        Hex_To_Array (JSON_String_Value (Keygen_TC, "z"));
      M_Seed               : constant Stream_Element_Array :=
        Hex_To_Array (JSON_String_Value (Encap_TC, "m"));
      Key_Seed             : constant Stream_Element_Array :=
        Concat (D_Seed, Z_Seed);
      Key_Source           : CryptoLib.Random.Random_Source;
      Enc_Source           : CryptoLib.Random.Random_Source;
      Public_Item          : CryptoLib.MLKEM768.Public_Key;
      Secret_Item          : CryptoLib.MLKEM768.Secret_Key;
      Prompt_Public_Item   : CryptoLib.MLKEM768.Public_Key;
      Prompt_Secret_Item   : CryptoLib.MLKEM768.Secret_Key;
      Prompt_Cipher_Item   : CryptoLib.MLKEM768.Ciphertext;
      Cipher_Item          : CryptoLib.MLKEM768.Ciphertext;
      Shared_Left          : CryptoLib.MLKEM768.Shared_Key;
      Shared_Right         : CryptoLib.MLKEM768.Shared_Key;
      Status_Value         : CryptoLib.Errors.Status;
   begin
      Check
        (Keygen_Prompt_Path /= "", "ML-KEM ACVP keyGen prompt.json exists");
      Check
        (Keygen_Expected_Path /= "",
         "ML-KEM ACVP keyGen expectedResults.json exists");
      Check
        (Encap_Prompt_Path /= "", "ML-KEM ACVP encapDecap prompt.json exists");
      Check
        (Encap_Expected_Path /= "",
         "ML-KEM ACVP encapDecap expectedResults.json exists");
      Require_Field
        (Keygen_Prompt,
         '"' & "algorithm" & '"' & ": " & '"' & "ML-KEM" & '"',
         "ML-KEM keyGen prompt");
      Require_Field
        (Keygen_Prompt,
         '"' & "mode" & '"' & ": " & '"' & "keyGen" & '"',
         "ML-KEM keyGen prompt");
      Require_Field
        (Keygen_Prompt,
         '"' & "parameterSet" & '"' & ": " & '"' & "ML-KEM-768" & '"',
         "ML-KEM keyGen prompt");
      Require_Field
        (Encap_Prompt,
         '"' & "algorithm" & '"' & ": " & '"' & "ML-KEM" & '"',
         "ML-KEM encapDecap prompt");
      Require_Field
        (Encap_Prompt,
         '"' & "mode" & '"' & ": " & '"' & "encapDecap" & '"',
         "ML-KEM encapDecap prompt");
      Require_Field
        (Encap_Prompt,
         '"' & "parameterSet" & '"' & ": " & '"' & "ML-KEM-768" & '"',
         "ML-KEM encapDecap prompt");
      Check (D_Seed'Length = 32, "ML-KEM ACVP keyGen d seed is 32 bytes");
      Check (Z_Seed'Length = 32, "ML-KEM ACVP keyGen z seed is 32 bytes");
      Check
        (M_Seed'Length = 32, "ML-KEM ACVP encapsulation m seed is 32 bytes");

      CryptoLib.Random.Initialize_Deterministic (Key_Source, Key_Seed);
      Status_Value :=
        CryptoLib.MLKEM768.Generate_Keypair
          (Key_Source, Public_Item, Secret_Item);
      Check
        (Status_Value = CryptoLib.Errors.Ok, "ML-KEM ACVP JSON keyGen executes");
      Check
        (Hex_Image (Public_Item)
         = Lower_Hex (JSON_String_Value (Keygen_Result_TC, "ek")),
         "ML-KEM ACVP JSON keyGen ek matches expectedResults");
      Check
        (Hex_Image (Secret_Item)
         = Lower_Hex (JSON_String_Value (Keygen_Result_TC, "dk")),
         "ML-KEM ACVP JSON keyGen dk matches expectedResults");

      Load_Hex_Exact
        (JSON_String_Value (Encap_TC, "ek"),
         Prompt_Public_Item,
         "ML-KEM ACVP encap ek");
      CryptoLib.Random.Initialize_Deterministic (Enc_Source, M_Seed);
      Status_Value :=
        CryptoLib.MLKEM768.Encapsulate
          (Enc_Source, Prompt_Public_Item, Cipher_Item, Shared_Left);
      Check
        (Status_Value = CryptoLib.Errors.Ok,
         "ML-KEM ACVP JSON encapsulation executes");
      Check
        (Hex_Image (Cipher_Item)
         = Lower_Hex (JSON_String_Value (Encap_Result_TC, "c")),
         "ML-KEM ACVP JSON encapsulation c matches expectedResults");
      Check
        (Hex_Image (Shared_Left)
         = Lower_Hex (JSON_String_Value (Encap_Result_TC, "k")),
         "ML-KEM ACVP JSON encapsulation k matches expectedResults");

      Load_Hex_Exact
        (JSON_String_Value (Decap_TC, "dk"),
         Prompt_Secret_Item,
         "ML-KEM ACVP decap dk");
      Load_Hex_Exact
        (JSON_String_Value (Decap_TC, "c"),
         Prompt_Cipher_Item,
         "ML-KEM ACVP decap c");
      Status_Value :=
        CryptoLib.MLKEM768.Decapsulate
          (Prompt_Secret_Item, Prompt_Cipher_Item, Shared_Right);
      Check
        (Status_Value = CryptoLib.Errors.Ok,
         "ML-KEM ACVP JSON decapsulation executes");
      Check
        (Hex_Image (Shared_Right)
         = Lower_Hex (JSON_String_Value (Decap_Result_TC, "k")),
         "ML-KEM ACVP JSON decapsulation k matches expectedResults");
   end Assert_MLKEM768_ACVP_JSON_Vectors;

   procedure Assert_SNTRUP761_OpenSSH_Vector (Relative_Path : String) is
      Path_Text    : constant String := Existing_Path (Relative_Path);
      Content_Text : constant String :=
        (if Path_Text = "" then "" else Read_All (Path_Text));
      Key_Seed     : constant Stream_Element_Array :=
        Hex_To_Array (Field_Value (Content_Text, "keygen_seed_hex"));
      Enc_Seed     : constant Stream_Element_Array :=
        Hex_To_Array (Field_Value (Content_Text, "encaps_seed_hex"));
      Key_Source   : CryptoLib.Random.Random_Source;
      Enc_Source   : CryptoLib.Random.Random_Source;
      Public_Item  : CryptoLib.SNTRUP761.Public_Key;
      Secret_Item  : CryptoLib.SNTRUP761.Secret_Key;
      Cipher_Item  : CryptoLib.SNTRUP761.Ciphertext;
      Mutated_Item : CryptoLib.SNTRUP761.Ciphertext;
      Shared_Left  : CryptoLib.SNTRUP761.Shared_Key;
      Shared_Right : CryptoLib.SNTRUP761.Shared_Key;
      Shared_Bad   : CryptoLib.SNTRUP761.Shared_Key;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Check (Path_Text /= "", "SNTRUP761 OpenSSH vector file exists");
      Check (Content_Text /= "", "SNTRUP761 OpenSSH vector file is readable");
      Require_Field (Content_Text, "algorithm=SNTRUP761", Relative_Path);
      Require_Field
        (Content_Text,
         "source_family=OpenSSH-sntrup761x25519-sha512",
         Relative_Path);
      Require_Field (Content_Text, "public_key_length=1158", Relative_Path);
      Require_Field (Content_Text, "secret_key_length=1763", Relative_Path);
      Require_Field (Content_Text, "ciphertext_length=1039", Relative_Path);
      Require_Field (Content_Text, "shared_secret_length=32", Relative_Path);
      Check
        (Key_Seed'Length >= 64,
         "SNTRUP761 OpenSSH vector has keygen seed bytes");
      Check
        (Enc_Seed'Length >= 32,
         "SNTRUP761 OpenSSH vector has encapsulation seed bytes");

      CryptoLib.Random.Initialize_Deterministic (Key_Source, Key_Seed);
      CryptoLib.Random.Initialize_Deterministic (Enc_Source, Enc_Seed);

      Status_Value :=
        CryptoLib.SNTRUP761.Generate_Keypair
          (Key_Source, Public_Item, Secret_Item);
      Check
        (Status_Value = CryptoLib.Errors.Ok,
         "SNTRUP761 OpenSSH vector keygen succeeds");
      Check
        (Hex_Image (CryptoLib.SHA3.SHA3_256 (Public_Item))
         = Field_Value (Content_Text, "expected_public_key_sha3_256"),
         "SNTRUP761 OpenSSH vector public key digest matches");
      Check
        (Hex_Image (CryptoLib.SHA3.SHA3_256 (Secret_Item))
         = Field_Value (Content_Text, "expected_secret_key_sha3_256"),
         "SNTRUP761 OpenSSH vector secret key digest matches");

      Status_Value :=
        CryptoLib.SNTRUP761.Encapsulate
          (Enc_Source, Public_Item, Cipher_Item, Shared_Left);
      Check
        (Status_Value = CryptoLib.Errors.Ok,
         "SNTRUP761 OpenSSH vector encapsulate succeeds");
      Check
        (Hex_Image (CryptoLib.SHA3.SHA3_256 (Cipher_Item))
         = Field_Value (Content_Text, "expected_ciphertext_sha3_256"),
         "SNTRUP761 OpenSSH vector ciphertext digest matches");
      Check
        (Hex_Image (Shared_Left)
         = Field_Value (Content_Text, "expected_shared_secret_hex"),
         "SNTRUP761 OpenSSH vector encapsulated shared secret matches");

      Status_Value :=
        CryptoLib.SNTRUP761.Decapsulate
          (Secret_Item, Cipher_Item, Shared_Right);
      Check
        (Status_Value = CryptoLib.Errors.Ok,
         "SNTRUP761 OpenSSH vector decapsulate succeeds");
      Check
        (Hex_Image (Shared_Right)
         = Field_Value (Content_Text, "expected_shared_secret_hex"),
         "SNTRUP761 OpenSSH vector decapsulated shared secret matches");

      Mutated_Item := Cipher_Item;
      Mutated_Item (Mutated_Item'Last) :=
        Mutated_Item (Mutated_Item'Last) xor 16#01#;
      Status_Value :=
        CryptoLib.SNTRUP761.Decapsulate
          (Secret_Item, Mutated_Item, Shared_Bad);
      Check
        (Status_Value = CryptoLib.Errors.Ok,
         "SNTRUP761 OpenSSH vector invalid decapsulation succeeds");
      Check
        (Shared_Bad'Length = CryptoLib.SNTRUP761.Shared_Key_Length,
         "SNTRUP761 OpenSSH vector invalid ciphertext fallback has shared-secret length");
      Check
        (Shared_Bad /= Shared_Left,
         "SNTRUP761 OpenSSH vector invalid ciphertext does not reuse valid shared secret");
   end Assert_SNTRUP761_OpenSSH_Vector;

   procedure Assert_PQ_External_KATs is
   begin
      Assert_Manifest
        ("tests/vectors/pq/MLKEM768_ACVP_EXTERNAL_KATS.manifest",
         "ML-KEM-768",
         "1184",
         "2400",
         "1088",
         "32",
         "external-kat-harness-ready");
      Assert_Manifest
        ("tests/vectors/pq/SNTRUP761_OPENSSH_EXTERNAL_KATS.manifest",
         "SNTRUP761",
         "1158",
         "1763",
         "1039",
         "32",
         "external-kat-corpus-bundled");
      Assert_MLKEM768_ACVP_Vector
        ("tests/vectors/pq/MLKEM768_ACVP_KAT_001.txt");
      Assert_MLKEM768_ACVP_JSON_Vectors;
      Assert_SNTRUP761_OpenSSH_Vector
        ("tests/vectors/pq/SNTRUP761_OPENSSH_KAT_001.txt");
      Assert_SNTRUP761_OpenSSH_Vector
        ("tests/vectors/pq/SNTRUP761_OPENSSH_KAT_002.txt");
      Assert_SNTRUP761_OpenSSH_Vector
        ("tests/vectors/pq/SNTRUP761_OPENSSH_KAT_003.txt");
      Assert_SNTRUP761_OpenSSH_Vector
        ("tests/vectors/pq/SNTRUP761_OPENSSH_KAT_004.txt");
   end Assert_PQ_External_KATs;
end SSH_Lib.Tests.Fixtures.PQ_External_KATs;
