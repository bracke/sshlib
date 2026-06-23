with Ada.Streams;    use Ada.Streams;
with Ada.Characters.Handling;
with Ada.Directories;
with Ada.Text_IO;
with CryptoLib.Errors; use CryptoLib.Errors;
with SSH_Lib.Internal;
with CryptoLib.Constant_Time;
with CryptoLib.Hashes;
with CryptoLib.Macs;
with SSH_Lib.Keys.Internal;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Host_Keys;
with SSH_Lib.Protocol.Certificates;

package body SSH_Lib.Known_Hosts is
   use Ada.Strings.Unbounded;

   Alphabet : constant String :=
     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

   Max_Known_Hosts_Line_Length : constant Positive := 16 * 1024;

   procedure Discard_Rest_Of_Line (Input_File : in out Ada.Text_IO.File_Type)
   is
      Buffer : String (1 .. 1024);
      Last   : Natural;
   begin
      while not Ada.Text_IO.End_Of_Line (Input_File)
        and then not Ada.Text_IO.End_Of_File (Input_File)
      loop
         Ada.Text_IO.Get_Line (Input_File, Buffer, Last);
      end loop;
   exception
      when others =>
         null;
   end Discard_Rest_Of_Line;

   procedure Clear (Item : out Host_Key) is
   begin
      Item.Algorithm_Text := Null_Unbounded_String;
      Item.Encoded_Text := Null_Unbounded_String;
   end Clear;

   function Base64_With_Padding
     (Data : Ada.Streams.Stream_Element_Array) return String
   is
      Output_Length   : constant Natural := ((Data'Length + 2) / 3) * 4;
      Result          : String (1 .. Output_Length);
      Output_Index    : Positive := Result'First;
      Cursor          : Stream_Element_Offset := Data'First;
      First_Byte      : Natural;
      Second_Byte     : Natural;
      Third_Byte      : Natural;
      Combined_Value  : Natural;
      Remaining_Count : Natural;
   begin
      while Cursor <= Data'Last loop
         Remaining_Count := Natural (Data'Last - Cursor + 1);
         First_Byte := Natural (Data (Cursor));
         if Remaining_Count >= 2 then
            Second_Byte := Natural (Data (Cursor + 1));
         else
            Second_Byte := 0;
         end if;
         if Remaining_Count >= 3 then
            Third_Byte := Natural (Data (Cursor + 2));
         else
            Third_Byte := 0;
         end if;

         Combined_Value :=
           First_Byte * 16#10000# + Second_Byte * 16#100# + Third_Byte;

         Result (Output_Index) := Alphabet (Combined_Value / 16#40000# + 1);
         Output_Index := Output_Index + 1;
         Result (Output_Index) :=
           Alphabet ((Combined_Value / 16#1000#) mod 64 + 1);
         Output_Index := Output_Index + 1;

         if Remaining_Count >= 2 then
            Result (Output_Index) :=
              Alphabet ((Combined_Value / 16#40#) mod 64 + 1);
         else
            Result (Output_Index) := '=';
         end if;
         Output_Index := Output_Index + 1;

         if Remaining_Count >= 3 then
            Result (Output_Index) := Alphabet (Combined_Value mod 64 + 1);
         else
            Result (Output_Index) := '=';
         end if;
         Output_Index := Output_Index + 1;

         Cursor := Cursor + 3;
      end loop;

      return Result;
   end Base64_With_Padding;

   function Is_Supported_Key_Format (Value : String) return Boolean is
   begin
      return
        Value = "ssh-ed25519"
        or else Value = "ecdsa-sha2-nistp256"
        or else Value = "ssh-rsa"
        or else SSH_Lib.Protocol.Certificates.Is_Certificate_Algorithm (Value);
   end Is_Supported_Key_Format;

   function Is_Base64_Character (Value : Character) return Boolean is
   begin
      return
        (Value >= 'A' and then Value <= 'Z')
        or else (Value >= 'a' and then Value <= 'z')
        or else (Value >= '0' and then Value <= '9')
        or else Value = '+'
        or else Value = '/'
        or else Value = '=';
   end Is_Base64_Character;

   function Base64_Index
     (Value : Character; Decoded_Value : out Natural) return Boolean is
   begin
      if Value >= 'A' and then Value <= 'Z' then
         Decoded_Value := Character'Pos (Value) - Character'Pos ('A');
         return True;
      elsif Value >= 'a' and then Value <= 'z' then
         Decoded_Value := Character'Pos (Value) - Character'Pos ('a') + 26;
         return True;
      elsif Value >= '0' and then Value <= '9' then
         Decoded_Value := Character'Pos (Value) - Character'Pos ('0') + 52;
         return True;
      elsif Value = '+' then
         Decoded_Value := 62;
         return True;
      elsif Value = '/' then
         Decoded_Value := 63;
         return True;
      else
         Decoded_Value := 0;
         return False;
      end if;
   end Base64_Index;

   function Normalize_Base64
     (Value : String; Normalized : out Unbounded_String) return Boolean
   is
      Padding_Count    : Natural := 0;
      First_Padding    : Natural := 0;
      Effective_Length : Natural;
      Remainder        : Natural;
   begin
      Normalized := Null_Unbounded_String;

      if Value'Length = 0 then
         return False;
      end if;

      for Index_Value in Value'Range loop
         if not Is_Base64_Character (Value (Index_Value)) then
            return False;
         end if;

         if Value (Index_Value) = '=' then
            Padding_Count := Padding_Count + 1;
            if First_Padding = 0 then
               First_Padding := Index_Value;
            end if;
            if Padding_Count > 2 then
               return False;
            end if;
         elsif First_Padding /= 0 then
            return False;
         end if;
      end loop;

      if Padding_Count > 0 then
         if Value'Length mod 4 /= 0 then
            return False;
         end if;
         Normalized := To_Unbounded_String (Value);
         return True;
      end if;

      Effective_Length := Value'Length;
      Remainder := Effective_Length mod 4;

      case Remainder is
         when 0      =>
            Normalized := To_Unbounded_String (Value);
            return True;

         when 2      =>
            Normalized := To_Unbounded_String (Value & "==");
            return True;

         when 3      =>
            Normalized := To_Unbounded_String (Value & "=");
            return True;

         when others =>
            return False;
      end case;
   exception
      when others =>
         Normalized := Null_Unbounded_String;
         return False;
   end Normalize_Base64;

   function Decode_Base64_With_Padding
     (Value : String; Data : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      First_Value      : Natural;
      Second_Value     : Natural;
      Third_Value      : Natural;
      Fourth_Value     : Natural;
      Combined         : Natural;
      Status_Value     : CryptoLib.Errors.Status;
      Normalized_Value : Unbounded_String;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Data);

      if not Normalize_Base64 (Value, Normalized_Value) then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      declare
         Canonical_Value : constant String := To_String (Normalized_Value);
         Index_Value     : Positive := Canonical_Value'First;
      begin
         while Index_Value <= Canonical_Value'Last loop
            if not Base64_Index (Canonical_Value (Index_Value), First_Value)
              or else
                not Base64_Index
                      (Canonical_Value (Index_Value + 1), Second_Value)
            then
               SSH_Lib.Protocol.Buffers.Clear (Data);
               return CryptoLib.Errors.Handshake_Failed;
            end if;

            if Canonical_Value (Index_Value + 2) = '=' then
               Third_Value := 0;
            elsif not Base64_Index
                        (Canonical_Value (Index_Value + 2), Third_Value)
            then
               SSH_Lib.Protocol.Buffers.Clear (Data);
               return CryptoLib.Errors.Handshake_Failed;
            end if;

            if Canonical_Value (Index_Value + 3) = '=' then
               Fourth_Value := 0;
            elsif not Base64_Index
                        (Canonical_Value (Index_Value + 3), Fourth_Value)
            then
               SSH_Lib.Protocol.Buffers.Clear (Data);
               return CryptoLib.Errors.Handshake_Failed;
            end if;

            Combined :=
              First_Value * 16#40000# + Second_Value * 16#1000#
              + Third_Value * 16#40#
              + Fourth_Value;

            Status_Value :=
              SSH_Lib.Protocol.Buffers.Append_Byte
                (Data, Stream_Element (Combined / 16#10000#));
            if Status_Value /= CryptoLib.Errors.Ok then
               SSH_Lib.Protocol.Buffers.Clear (Data);
               return Status_Value;
            end if;

            if Canonical_Value (Index_Value + 2) /= '=' then
               Status_Value :=
                 SSH_Lib.Protocol.Buffers.Append_Byte
                   (Data, Stream_Element ((Combined / 16#100#) mod 16#100#));
               if Status_Value /= CryptoLib.Errors.Ok then
                  SSH_Lib.Protocol.Buffers.Clear (Data);
                  return Status_Value;
               end if;
            end if;

            if Canonical_Value (Index_Value + 3) /= '=' then
               Status_Value :=
                 SSH_Lib.Protocol.Buffers.Append_Byte
                   (Data, Stream_Element (Combined mod 16#100#));
               if Status_Value /= CryptoLib.Errors.Ok then
                  SSH_Lib.Protocol.Buffers.Clear (Data);
                  return Status_Value;
               end if;
            end if;

            Index_Value := Index_Value + 4;
         end loop;
      end;

      if SSH_Lib.Protocol.Buffers.Length (Data) = 0 then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Data);
         return CryptoLib.Errors.Internal_Error;
   end Decode_Base64_With_Padding;

   function Is_Canonical_Base64_With_Padding (Value : String) return Boolean is
      Decoded_Data : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := Decode_Base64_With_Padding (Value, Decoded_Data);
      if Status_Value /= CryptoLib.Errors.Ok then
         return False;
      end if;

      declare
         Normalized : Unbounded_String;
      begin
         if not Normalize_Base64 (Value, Normalized) then
            return False;
         end if;

         return
           Base64_With_Padding
             (SSH_Lib.Protocol.Buffers.To_Array (Decoded_Data))
           = To_String (Normalized);
      end;
   exception
      when others =>
         return False;
   end Is_Canonical_Base64_With_Padding;

   function Negotiated_Algorithm_For_Record (Algorithm : String) return String
   is
   begin
      if Algorithm = "ssh-rsa" then
         return "rsa-sha2-256";
      else
         return Algorithm;
      end if;
   end Negotiated_Algorithm_For_Record;

   function Decoded_Key_Record
     (Encoded_Key : String; Data : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status is
   begin
      return Decode_Base64_With_Padding (Encoded_Key, Data);
   end Decoded_Key_Record;

   function Is_Decoded_Key_Record_Valid
     (Algorithm : String; Encoded_Key : String) return Boolean
   is
      Decoded_Key          : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Parsed_Key           : SSH_Lib.Keys.Public_Key;
      Status_Value         : CryptoLib.Errors.Status;
      Negotiated_Algorithm : constant String :=
        Negotiated_Algorithm_For_Record (Algorithm);
   begin
      Status_Value := Decode_Base64_With_Padding (Encoded_Key, Decoded_Key);
      if Status_Value /= CryptoLib.Errors.Ok then
         return False;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Parse
          (SSH_Lib.Protocol.Buffers.To_Array (Decoded_Key),
           Negotiated_Algorithm,
           Parsed_Key);
      if Status_Value /= CryptoLib.Errors.Ok then
         return False;
      end if;

      return SSH_Lib.Keys.Algorithm (Parsed_Key) = Algorithm;
   exception
      when others =>
         return False;
   end Is_Decoded_Key_Record_Valid;

   function Default_File return Unbounded_String is
   begin
      return SSH_Lib.Internal.Default_Known_Hosts_Path;
   end Default_File;

   function Resolve_Known_Hosts_File (Path : String) return String is
      Home_Path : constant String :=
        To_String (SSH_Lib.Internal.Home_Directory);
   begin
      if Path'Length = 0 then
         return To_String (Default_File);
      elsif Path = "~" then
         return Home_Path;
      elsif Path'Length >= 2
        and then Path (Path'First) = '~'
        and then Path (Path'First + 1) = '/'
      then
         if Home_Path'Length = 0 then
            return "";
         else
            return Home_Path & Path (Path'First + 1 .. Path'Last);
         end if;
      else
         return Path;
      end if;
   exception
      when others =>
         return "";
   end Resolve_Known_Hosts_File;

   function Create_Host_Key
     (Algorithm : String; Encoded_Key : String) return Host_Key
   is
      Normalized_Key : Unbounded_String;
   begin
      return Created_Key : Host_Key do
         if Is_Supported_Key_Format (Algorithm)
           and then Normalize_Base64 (Encoded_Key, Normalized_Key)
           and then
             Is_Canonical_Base64_With_Padding (To_String (Normalized_Key))
           and then
             Is_Decoded_Key_Record_Valid
               (Algorithm, To_String (Normalized_Key))
         then
            Created_Key.Algorithm_Text := To_Unbounded_String (Algorithm);
            Created_Key.Encoded_Text := Normalized_Key;
         else
            Clear (Created_Key);
         end if;
      end return;
   end Create_Host_Key;

   function Algorithm (Item : Host_Key) return String is
   begin
      return To_String (Item.Algorithm_Text);
   end Algorithm;

   function Encoded (Item : Host_Key) return String is
   begin
      return To_String (Item.Encoded_Text);
   end Encoded;

   function Is_Valid (Item : Host_Key) return Boolean is
   begin
      return
        Is_Supported_Key_Format (To_String (Item.Algorithm_Text))
        and then
          Is_Canonical_Base64_With_Padding (To_String (Item.Encoded_Text))
        and then
          Is_Decoded_Key_Record_Valid
            (To_String (Item.Algorithm_Text), To_String (Item.Encoded_Text));
   end Is_Valid;

   function Equal (Left_Item : Host_Key; Right_Item : Host_Key) return Boolean
   is
      Left_Algorithm  : constant String :=
        To_String (Left_Item.Algorithm_Text);
      Right_Algorithm : constant String :=
        To_String (Right_Item.Algorithm_Text);
      Left_Decoded    : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Right_Decoded   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Left_Status     : CryptoLib.Errors.Status;
      Right_Status    : CryptoLib.Errors.Status;
   begin
      if not Is_Valid (Left_Item) or else not Is_Valid (Right_Item) then
         return False;
      end if;

      if Left_Algorithm /= Right_Algorithm then
         return False;
      end if;

      Left_Status :=
        Decode_Base64_With_Padding
          (To_String (Left_Item.Encoded_Text), Left_Decoded);
      Right_Status :=
        Decode_Base64_With_Padding
          (To_String (Right_Item.Encoded_Text), Right_Decoded);

      if Left_Status /= CryptoLib.Errors.Ok
        or else Right_Status /= CryptoLib.Errors.Ok
      then
         return False;
      end if;

      return
        CryptoLib.Constant_Time.Equal
          (SSH_Lib.Protocol.Buffers.To_Array (Left_Decoded),
           SSH_Lib.Protocol.Buffers.To_Array (Right_Decoded));
   exception
      when others =>
         return False;
   end Equal;

   function From_Public_Key
     (Presented_Key : SSH_Lib.Keys.Public_Key; Item : out Host_Key)
      return CryptoLib.Errors.Status is
   begin
      Clear (Item);
      if not SSH_Lib.Keys.Is_Valid (Presented_Key) then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      declare
         Raw_Key_Blob : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Keys.Internal.Raw_Blob (Presented_Key);
      begin
         if Raw_Key_Blob'Length = 0 then
            Clear (Item);
            return CryptoLib.Errors.Handshake_Failed;
         end if;

         declare
            Candidate : constant Host_Key :=
              Create_Host_Key
                (SSH_Lib.Keys.Algorithm (Presented_Key),
                 Base64_With_Padding (Raw_Key_Blob));
         begin
            if not Is_Valid (Candidate) then
               Clear (Item);
               return CryptoLib.Errors.Unsupported_Feature;
            end if;

            Item := Candidate;
         end;
      end;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Clear (Item);
         return CryptoLib.Errors.Internal_Error;
   end From_Public_Key;

   function SHA256_Fingerprint
     (Item : Host_Key; Value : out SSH_Lib.Keys.Fingerprint)
      return CryptoLib.Errors.Status
   is
      Decoded_Key          : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Parsed_Key           : SSH_Lib.Keys.Public_Key;
      Status_Value         : CryptoLib.Errors.Status;
      Empty_Key            : SSH_Lib.Keys.Public_Key;
      Algorithm_Text       : constant String := Algorithm (Item);
      Encoded_Text         : constant String := Encoded (Item);
      Negotiated_Algorithm : constant String :=
        Negotiated_Algorithm_For_Record (Algorithm_Text);
   begin
      Status_Value := SSH_Lib.Keys.SHA256_Fingerprint (Empty_Key, Value);
      if Status_Value /= CryptoLib.Errors.Handshake_Failed then
         return CryptoLib.Errors.Internal_Error;
      end if;

      if not Is_Valid (Item) then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      Status_Value := Decode_Base64_With_Padding (Encoded_Text, Decoded_Key);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Parse
          (SSH_Lib.Protocol.Buffers.To_Array (Decoded_Key),
           Negotiated_Algorithm,
           Parsed_Key);
      if Status_Value /= CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Keys.SHA256_Fingerprint (Empty_Key, Value);
         if Status_Value = CryptoLib.Errors.Handshake_Failed then
            return CryptoLib.Errors.Handshake_Failed;
         else
            return CryptoLib.Errors.Internal_Error;
         end if;
      end if;

      return SSH_Lib.Keys.SHA256_Fingerprint (Parsed_Key, Value);
   exception
      when others =>
         declare
            Empty_Key : SSH_Lib.Keys.Public_Key;
            Ignored   : CryptoLib.Errors.Status;
         begin
            Ignored := SSH_Lib.Keys.SHA256_Fingerprint (Empty_Key, Value);
            pragma Unreferenced (Ignored);
         end;
         return CryptoLib.Errors.Internal_Error;
   end SHA256_Fingerprint;

   function Trim_Field (Value : String) return String is
      First_Index : Integer := Value'First;
      Last_Index  : Integer := Value'Last;
   begin
      while First_Index <= Last_Index
        and then
          (Value (First_Index) = ' '
           or else Value (First_Index) = Character'Val (9))
      loop
         First_Index := First_Index + 1;
      end loop;

      while Last_Index >= First_Index
        and then
          (Value (Last_Index) = ' '
           or else Value (Last_Index) = Character'Val (9))
      loop
         Last_Index := Last_Index - 1;
      end loop;

      if First_Index > Last_Index then
         return "";
      else
         return Value (First_Index .. Last_Index);
      end if;
   end Trim_Field;

   function Lower_ASCII (Value : String) return String is
      Result : String (Value'Range);
   begin
      for Index_Value in Value'Range loop
         Result (Index_Value) :=
           Ada.Characters.Handling.To_Lower (Value (Index_Value));
      end loop;
      return Result;
   end Lower_ASCII;

   function Pattern_Matches
     (Pattern_Value : String; Host_Value : String) return Boolean
   is
      Pattern_Text : constant String := Lower_ASCII (Pattern_Value);
      Host_Text    : constant String := Lower_ASCII (Host_Value);

      function Match_From
        (Pattern_Index : Integer; Host_Index : Integer) return Boolean
      is
         Next_Pattern : Integer;
      begin
         if Pattern_Index > Pattern_Text'Last then
            return Host_Index > Host_Text'Last;
         end if;

         if Pattern_Text (Pattern_Index) = '*' then
            Next_Pattern := Pattern_Index;
            while Next_Pattern <= Pattern_Text'Last
              and then Pattern_Text (Next_Pattern) = '*'
            loop
               Next_Pattern := Next_Pattern + 1;
            end loop;

            if Next_Pattern > Pattern_Text'Last then
               return True;
            end if;

            for Candidate_Index in Host_Index .. Host_Text'Last + 1 loop
               if Match_From (Next_Pattern, Candidate_Index) then
                  return True;
               end if;
            end loop;

            return False;
         elsif Host_Index > Host_Text'Last then
            return False;
         elsif Pattern_Text (Pattern_Index) = '?'
           or else Pattern_Text (Pattern_Index) = Host_Text (Host_Index)
         then
            return Match_From (Pattern_Index + 1, Host_Index + 1);
         else
            return False;
         end if;
      end Match_From;
   begin
      if Pattern_Value'Length = 0 or else Host_Value'Length = 0 then
         return False;
      end if;

      return Match_From (Pattern_Text'First, Host_Text'First);
   exception
      when others =>
         return False;
   end Pattern_Matches;

   function Decimal_Image (Value : Natural) return String is
      Text_Value : constant String := Natural'Image (Value);
   begin
      return Text_Value (Text_Value'First + 1 .. Text_Value'Last);
   end Decimal_Image;

   function To_Bytes (Value : String) return Ada.Streams.Stream_Element_Array
   is
      Result       :
        Ada.Streams.Stream_Element_Array
          (1 .. Ada.Streams.Stream_Element_Offset (Value'Length));
      Output_Index : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      for Character_Value of Value loop
         Result (Output_Index) :=
           Ada.Streams.Stream_Element (Character'Pos (Character_Value));
         Output_Index := Output_Index + 1;
      end loop;
      return Result;
   end To_Bytes;

   function Digest_To_Array
     (Digest : CryptoLib.Hashes.SHA1_Digest)
      return Ada.Streams.Stream_Element_Array
   is
      Result       :
        Ada.Streams.Stream_Element_Array
          (1 .. Ada.Streams.Stream_Element_Offset (Digest'Length));
      Output_Index : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      for Digest_Index in Digest'Range loop
         Result (Output_Index) := Digest (Digest_Index);
         Output_Index := Output_Index + 1;
      end loop;
      return Result;
   end Digest_To_Array;

   function Host_Match_Text (Host : String; Port : Natural) return String is
   begin
      if Port = 22 then
         return Host;
      else
         return "[" & Host & "]:" & Decimal_Image (Port);
      end if;
   end Host_Match_Text;

   function Hashed_Selector_Is_Malformed
     (Selector_Value : String) return Boolean
   is
      First_Separator  : Natural := 0;
      Second_Separator : Natural := 0;
      Salt_Data        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Hash_Data        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value     : CryptoLib.Errors.Status;
   begin
      if Selector_Value'Length < 5
        or else
          Selector_Value (Selector_Value'First .. Selector_Value'First + 2)
          /= "|1|"
      then
         return True;
      end if;

      First_Separator := Selector_Value'First + 2;
      for Index_Value in First_Separator + 1 .. Selector_Value'Last loop
         if Selector_Value (Index_Value) = '|' then
            Second_Separator := Index_Value;
            exit;
         end if;
      end loop;

      if Second_Separator = 0
        or else Second_Separator = First_Separator + 1
        or else Second_Separator = Selector_Value'Last
      then
         return True;
      end if;

      Status_Value :=
        Decode_Base64_With_Padding
          (Selector_Value (First_Separator + 1 .. Second_Separator - 1),
           Salt_Data);
      if Status_Value /= CryptoLib.Errors.Ok
        or else SSH_Lib.Protocol.Buffers.Length (Salt_Data) = 0
      then
         return True;
      end if;

      Status_Value :=
        Decode_Base64_With_Padding
          (Selector_Value (Second_Separator + 1 .. Selector_Value'Last),
           Hash_Data);
      return
        Status_Value /= CryptoLib.Errors.Ok
        or else SSH_Lib.Protocol.Buffers.Length (Hash_Data) /= 20;
   exception
      when others =>
         return True;
   end Hashed_Selector_Is_Malformed;

   function Hashed_Selector_Matches
     (Selector_Value : String; Host : String; Port : Natural) return Boolean
   is
      First_Separator      : Natural := 0;
      Second_Separator     : Natural := 0;
      Salt_Field           : Unbounded_String;
      Hash_Field           : Unbounded_String;
      Salt_Data            : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Expected_Data        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value         : CryptoLib.Errors.Status;
      Candidate_Text       : constant String := Host_Match_Text (Host, Port);
      Lower_Candidate_Text : constant String :=
        Host_Match_Text (Lower_ASCII (Host), Port);
      Actual_Hash          : CryptoLib.Hashes.SHA1_Digest;
      Lower_Hash           : CryptoLib.Hashes.SHA1_Digest;
   begin
      if Selector_Value'Length < 5
        or else
          Selector_Value (Selector_Value'First .. Selector_Value'First + 2)
          /= "|1|"
      then
         return False;
      end if;

      First_Separator := Selector_Value'First + 2;
      for Index_Value in First_Separator + 1 .. Selector_Value'Last loop
         if Selector_Value (Index_Value) = '|' then
            Second_Separator := Index_Value;
            exit;
         end if;
      end loop;

      if Second_Separator = 0 or else Second_Separator = Selector_Value'Last
      then
         return False;
      end if;

      Salt_Field :=
        To_Unbounded_String
          (Selector_Value (First_Separator + 1 .. Second_Separator - 1));
      Hash_Field :=
        To_Unbounded_String
          (Selector_Value (Second_Separator + 1 .. Selector_Value'Last));

      Status_Value :=
        Decode_Base64_With_Padding (To_String (Salt_Field), Salt_Data);
      if Status_Value /= CryptoLib.Errors.Ok then
         return False;
      end if;

      Status_Value :=
        Decode_Base64_With_Padding (To_String (Hash_Field), Expected_Data);
      if Status_Value /= CryptoLib.Errors.Ok
        or else SSH_Lib.Protocol.Buffers.Length (Expected_Data) /= 20
      then
         return False;
      end if;

      Actual_Hash :=
        CryptoLib.Macs.HMAC_SHA1
          (SSH_Lib.Protocol.Buffers.To_Array (Salt_Data),
           To_Bytes (Candidate_Text));

      if CryptoLib.Constant_Time.Equal
           (Digest_To_Array (Actual_Hash),
            SSH_Lib.Protocol.Buffers.To_Array (Expected_Data))
      then
         return True;
      end if;

      --  Host names are case-insensitive.  OpenSSH hashed host entries
      --  store only the HMAC and salt, so match the canonical lower-case
      --  host spelling as a fallback instead of making mixed-case caller
      --  input look like an unknown host.
      if Lower_Candidate_Text /= Candidate_Text then
         Lower_Hash :=
           CryptoLib.Macs.HMAC_SHA1
             (SSH_Lib.Protocol.Buffers.To_Array (Salt_Data),
              To_Bytes (Lower_Candidate_Text));

         return
           CryptoLib.Constant_Time.Equal
             (Digest_To_Array (Lower_Hash),
              SSH_Lib.Protocol.Buffers.To_Array (Expected_Data));
      end if;

      return False;
   exception
      when others =>
         return False;
   end Hashed_Selector_Matches;

   function Decimal_Value
     (Value : String; Parsed_Value : out Natural) return Boolean
   is
      Accumulator : Natural := 0;
   begin
      if Value'Length = 0 then
         Parsed_Value := 0;
         return False;
      end if;

      for Character_Value of Value loop
         if Character_Value < '0' or else Character_Value > '9' then
            Parsed_Value := 0;
            return False;
         end if;
         if Accumulator > 65535 then
            Parsed_Value := 0;
            return False;
         end if;
         Accumulator :=
           Accumulator
           * 10
           + Character'Pos (Character_Value)
           - Character'Pos ('0');
      end loop;

      Parsed_Value := Accumulator;
      return True;
   exception
      when others =>
         Parsed_Value := 0;
         return False;
   end Decimal_Value;

   function Bracketed_Selector_Is_Malformed
     (Selector_Value : String) return Boolean
   is
      Clean_Selector : constant String := Trim_Field (Selector_Value);
      Bracket_End    : Natural := 0;
      Parsed_Port    : Natural;
   begin
      if Clean_Selector'Length = 0
        or else Clean_Selector (Clean_Selector'First) /= '['
      then
         return False;
      end if;

      for Index_Value in Clean_Selector'First + 1 .. Clean_Selector'Last loop
         if Clean_Selector (Index_Value) = ']' then
            Bracket_End := Index_Value;
            exit;
         end if;
      end loop;

      if Bracket_End = 0
        or else Bracket_End = Clean_Selector'First + 1
        or else Bracket_End + 2 > Clean_Selector'Last
        or else Clean_Selector (Bracket_End + 1) /= ':'
      then
         return True;
      end if;

      if not Decimal_Value
               (Clean_Selector (Bracket_End + 2 .. Clean_Selector'Last),
                Parsed_Port)
      then
         return True;
      end if;

      return Parsed_Port = 0 or else Parsed_Port > 65_535;
   exception
      when others =>
         return True;
   end Bracketed_Selector_Is_Malformed;

   function Selector_Matches
     (Selector_Value : String; Host : String; Port : Natural) return Boolean
   is
      Clean_Selector : constant String := Trim_Field (Selector_Value);
      Parsed_Port    : Natural;
      Bracket_End    : Natural := 0;
   begin
      if Clean_Selector'Length = 0 then
         return False;
      end if;

      if Clean_Selector (Clean_Selector'First) = '!' then
         return
           Selector_Matches
             (Clean_Selector (Clean_Selector'First + 1 .. Clean_Selector'Last),
              Host,
              Port);
      end if;

      if Clean_Selector'Length >= 3
        and then Clean_Selector (Clean_Selector'First) = '['
      then
         for Index_Value in Clean_Selector'First + 1 .. Clean_Selector'Last
         loop
            if Clean_Selector (Index_Value) = ']' then
               Bracket_End := Index_Value;
               exit;
            end if;
         end loop;

         if Bracket_End = 0
           or else Bracket_End + 2 > Clean_Selector'Last
           or else Clean_Selector (Bracket_End + 1) /= ':'
         then
            return False;
         end if;

         if not Decimal_Value
                  (Clean_Selector (Bracket_End + 2 .. Clean_Selector'Last),
                   Parsed_Port)
         then
            return False;
         end if;

         return
           Parsed_Port = Port
           and then
             Pattern_Matches
               (Clean_Selector (Clean_Selector'First + 1 .. Bracket_End - 1),
                Host);
      end if;

      if Port /= 22 then
         return False;
      end if;

      return Pattern_Matches (Clean_Selector, Host);
   exception
      when others =>
         return False;
   end Selector_Matches;

   type Host_List_Match is record
      Positive            : Boolean := False;
      Negative            : Boolean := False;
      Unsupported_Pattern : Boolean := False;
      Hashed_Matched      : Boolean := False;
      Unsupported_Hash    : Boolean := False;
   end record;

   function Match_Host_List
     (Pattern_List : String; Host : String; Port : Natural)
      return Host_List_Match
   is
      Result        : Host_List_Match;
      Segment_First : Positive := Pattern_List'First;
      Segment_Last  : Natural;

      function Has_Empty_Host_List_Member return Boolean is
      begin
         if Pattern_List'Length = 0 then
            return False;
         end if;

         if Pattern_List (Pattern_List'First) = ','
           or else Pattern_List (Pattern_List'Last) = ','
         then
            return True;
         end if;

         for Index_Value in Pattern_List'First .. Pattern_List'Last - 1 loop
            if Pattern_List (Index_Value) = ','
              and then Pattern_List (Index_Value + 1) = ','
            then
               return True;
            end if;
         end loop;

         return False;
      exception
         when others =>
            return True;
      end Has_Empty_Host_List_Member;

      procedure Note_Selector (Raw_Selector : String) is
         Selector_Text : constant String := Trim_Field (Raw_Selector);
      begin
         if Selector_Text'Length = 0 then
            Result.Unsupported_Pattern := True;
            return;
         end if;

         if Bracketed_Selector_Is_Malformed (Selector_Text) then
            --  A bracketed known_hosts selector with broken [host]:port
            --  framing is ambiguous policy syntax.  Treat it as unsupported
            --  so a later ordinary trust line cannot hide it.
            Result.Unsupported_Pattern := True;
            return;
         end if;

         if Selector_Text (Selector_Text'First) = '|' then
            if Selector_Text'Length >= 3
              and then
                Selector_Text (Selector_Text'First .. Selector_Text'First + 2)
                = "|1|"
            then
               if Hashed_Selector_Is_Malformed (Selector_Text) then
                  --  A syntactically invalid |1| hashed selector may hide an
                  --  applicable host behind undecodable salt/hash material.
                  --  Fail closed instead of treating it as an unrelated
                  --  nonmatch and allowing a later trust line to mask it.
                  Result.Unsupported_Pattern := False;
               elsif Hashed_Selector_Matches (Selector_Text, Host, Port) then
                  Result.Positive := True;
                  Result.Hashed_Matched := True;
               end if;
            else
               --  OpenSSH currently defines known_hosts hashed selectors with
               --  the |1| marker.  A future or malformed |N| selector cannot
               --  be safely matched or ignored, because it may be the only
               --  applicable selector on a policy line.  Treat it as an
               --  unsupported host-pattern member so verification fails closed
               --  instead of trusting a later line.
               Result.Unsupported_Hash := True;
            end if;
            return;
         end if;

         if Selector_Text (Selector_Text'First) = '!' then
            declare
               Positive_Text : constant String :=
                 Selector_Text (Selector_Text'First + 1 .. Selector_Text'Last);
            begin
               if Positive_Text'Length = 0 then
                  Result.Unsupported_Pattern := True;
                  return;
               end if;

               if Bracketed_Selector_Is_Malformed (Positive_Text) then
                  --  Negating malformed [host]:port syntax is still
                  --  malformed; it cannot safely be treated as a harmless
                  --  nonmatch or line-local veto.
                  Result.Unsupported_Pattern := True;
                  return;
               end if;

               if Positive_Text (Positive_Text'First) = '|' then
                  if Positive_Text'Length >= 3
                    and then
                      Positive_Text
                        (Positive_Text'First .. Positive_Text'First + 2)
                      = "|1|"
                  then
                     if Hashed_Selector_Is_Malformed (Positive_Text) then
                        --  Negated malformed hashed selectors are still
                        --  ambiguous policy syntax.  Do not downgrade them to
                        --  harmless nonmatches or vetoes.
                        Result.Unsupported_Pattern := True;
                     elsif Hashed_Selector_Matches (Positive_Text, Host, Port)
                     then
                        --  OpenSSH allows any host pattern-list member to be
                        --  negated.  Hashed host selectors are still selectors,
                        --  so !|1|salt|hash must veto only this line when the
                        --  hash matches the target host.
                        Result.Negative := True;
                        Result.Hashed_Matched := True;
                     end if;
                  else
                     --  Do not treat an unknown negated hash-version selector
                     --  as a harmless nonmatch.  Its match semantics are
                     --  unavailable, so line applicability is ambiguous.
                     Result.Unsupported_Pattern := True;
                  end if;
                  return;
               end if;

               if Selector_Matches (Positive_Text, Host, Port) then
                  --  OpenSSH pattern-lists use negation as a line-local match
                  --  veto.  A negated selector never means that the presented
                  --  key is changed; it only prevents this specific known_hosts
                  --  line from contributing trust/revocation/CA authority.
                  Result.Negative := True;
               end if;
            end;
         elsif Selector_Matches (Selector_Text, Host, Port) then
            Result.Positive := True;
         end if;
      end Note_Selector;
   begin
      if Pattern_List'Length = 0 then
         return Result;
      end if;

      if Has_Empty_Host_List_Member then
         --  Empty host-pattern members (leading comma, trailing comma, or
         --  consecutive commas) are malformed OpenSSH policy syntax.  Do not
         --  ignore the empty member and let the rest of the line or a later
         --  trust line establish host-key trust.
         Result.Unsupported_Pattern := True;
         return Result;
      end if;

      while Segment_First <= Pattern_List'Last loop
         Segment_Last := Segment_First;
         while Segment_Last <= Pattern_List'Last
           and then Pattern_List (Segment_Last) /= ','
         loop
            Segment_Last := Segment_Last + 1;
         end loop;

         Note_Selector (Pattern_List (Segment_First .. Segment_Last - 1));
         Segment_First := Segment_Last + 1;
      end loop;

      return Result;
   exception
      when others =>
         Result.Unsupported_Pattern := True;
         return Result;
   end Match_Host_List;

   type Parsed_Record_Status is
     (Parsed_Record_Ok,
      Parsed_Record_Cert_Authority,
      Parsed_Record_Revoked,
      Parsed_Record_Ignore,
      Parsed_Record_Unsupported,
      Parsed_Record_Malformed);

   procedure Parse_Known_Hosts_Line
     (Line_Text      : String;
      Host_Field     : out Unbounded_String;
      Algorithm_Text : out Unbounded_String;
      Key_Text       : out Unbounded_String;
      Record_Status  : out Parsed_Record_Status)
   is
      Clean_Line  : constant String := Trim_Field (Line_Text);
      Token_Start : Natural;
      Token_End   : Natural;
      Cursor      : Natural;
      Marker_Text : Unbounded_String;

      function Next_Token (Item : out Unbounded_String) return Boolean is
      begin
         while Cursor <= Clean_Line'Last
           and then
             (Clean_Line (Cursor) = ' '
              or else Clean_Line (Cursor) = Character'Val (9))
         loop
            Cursor := Cursor + 1;
         end loop;

         if Cursor > Clean_Line'Last then
            Item := Null_Unbounded_String;
            return False;
         end if;

         Token_Start := Cursor;
         while Cursor <= Clean_Line'Last
           and then Clean_Line (Cursor) /= ' '
           and then Clean_Line (Cursor) /= Character'Val (9)
         loop
            Cursor := Cursor + 1;
         end loop;
         Token_End := Cursor - 1;
         Item := To_Unbounded_String (Clean_Line (Token_Start .. Token_End));
         return True;
      end Next_Token;
   begin
      Host_Field := Null_Unbounded_String;
      Algorithm_Text := Null_Unbounded_String;
      Key_Text := Null_Unbounded_String;
      Marker_Text := Null_Unbounded_String;
      Record_Status := Parsed_Record_Ignore;

      if Clean_Line'Length = 0 or else Clean_Line (Clean_Line'First) = '#' then
         return;
      end if;

      Cursor := Clean_Line'First;
      if Clean_Line (Clean_Line'First) = '@' then
         if not Next_Token (Marker_Text) then
            Record_Status := Parsed_Record_Malformed;
            return;
         end if;

         if To_String (Marker_Text) = "@cert-authority" then
            Record_Status := Parsed_Record_Cert_Authority;
         elsif To_String (Marker_Text) = "@revoked" then
            null;
         else
            Record_Status := Parsed_Record_Unsupported;
            return;
         end if;
      end if;

      if not Next_Token (Host_Field)
        or else not Next_Token (Algorithm_Text)
        or else not Next_Token (Key_Text)
      then
         Record_Status := Parsed_Record_Malformed;
         return;
      end if;

      if not Is_Supported_Key_Format (To_String (Algorithm_Text)) then
         Record_Status := Parsed_Record_Unsupported;
         return;
      end if;

      if not Is_Valid
               (Create_Host_Key
                  (To_String (Algorithm_Text), To_String (Key_Text)))
      then
         Record_Status := Parsed_Record_Malformed;
         return;
      end if;

      if Length (Marker_Text) > 0 and then To_String (Marker_Text) = "@revoked"
      then
         Record_Status := Parsed_Record_Revoked;
      elsif Length (Marker_Text) > 0
        and then To_String (Marker_Text) = "@cert-authority"
      then
         Record_Status := Parsed_Record_Cert_Authority;
      else
         Record_Status := Parsed_Record_Ok;
      end if;
   exception
      when others =>
         Host_Field := Null_Unbounded_String;
         Algorithm_Text := Null_Unbounded_String;
         Key_Text := Null_Unbounded_String;
         Record_Status := Parsed_Record_Malformed;
   end Parse_Known_Hosts_Line;

   function Possible_Host_List_Field (Line_Text : String) return String is
      Clean_Line   : constant String := Trim_Field (Line_Text);
      First_Start  : Natural;
      First_End    : Natural;
      Second_Start : Natural;
      Second_End   : Natural;

      procedure Skip_Space (Cursor : in out Natural) is
      begin
         while Cursor <= Clean_Line'Last
           and then
             (Clean_Line (Cursor) = ' '
              or else Clean_Line (Cursor) = Character'Val (9))
         loop
            Cursor := Cursor + 1;
         end loop;
      end Skip_Space;

      procedure Scan_Token
        (Cursor      : in out Natural;
         Token_First : out Natural;
         Token_Last  : out Natural) is
      begin
         Skip_Space (Cursor);
         Token_First := Cursor;
         while Cursor <= Clean_Line'Last
           and then Clean_Line (Cursor) /= ' '
           and then Clean_Line (Cursor) /= Character'Val (9)
         loop
            Cursor := Cursor + 1;
         end loop;
         Token_Last := Cursor - 1;
      end Scan_Token;

      Cursor : Natural := Clean_Line'First;
   begin
      if Clean_Line'Length = 0 or else Clean_Line (Clean_Line'First) = '#' then
         return "";
      end if;

      Scan_Token (Cursor, First_Start, First_End);
      if First_Start > First_End then
         return "";
      end if;

      --  Unknown @markers are still marker tokens in OpenSSH known_hosts.
      --  When a line is unsupported or malformed, use the following token as
      --  the host-list for fail-closed applicability checks instead of
      --  accidentally testing the marker text itself as a hostname.
      if Clean_Line (First_Start) = '@' then
         Scan_Token (Cursor, Second_Start, Second_End);
         if Second_Start <= Second_End then
            return Clean_Line (Second_Start .. Second_End);
         else
            return "";
         end if;
      else
         return Clean_Line (First_Start .. First_End);
      end if;
   exception
      when others =>
         return "";
   end Possible_Host_List_Field;

   function Load
     (Path : String; Item : out Database) return CryptoLib.Errors.Status
   is
      Probe_File    : Ada.Text_IO.File_Type;
      Resolved_Path : constant String := Resolve_Known_Hosts_File (Path);
   begin
      Item.Path_Text := Null_Unbounded_String;
      Item.Loaded := False;

      if Resolved_Path'Length = 0 then
         return CryptoLib.Errors.Host_Key_Unknown;
      end if;

      if not Ada.Directories.Exists (Resolved_Path) then
         return CryptoLib.Errors.Host_Key_Unknown;
      end if;

      Ada.Text_IO.Open (Probe_File, Ada.Text_IO.In_File, Resolved_Path);
      Ada.Text_IO.Close (Probe_File);
      Item.Path_Text := To_Unbounded_String (Resolved_Path);
      Item.Loaded := True;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Probe_File) then
            Ada.Text_IO.Close (Probe_File);
         end if;
         Item.Path_Text := Null_Unbounded_String;
         Item.Loaded := False;
         return CryptoLib.Errors.Host_Key_Unknown;
   end Load;

   function Check
     (Item : Database;
      Host : String;
      Port : Natural;
      Key  : SSH_Lib.Keys.Public_Key) return CryptoLib.Errors.Status
   is
      Material     : Host_Key;
      Status_Value : CryptoLib.Errors.Status;
   begin
      if not Item.Loaded then
         return CryptoLib.Errors.Host_Key_Unknown;
      end if;

      Status_Value := From_Public_Key (Key, Material);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      return
        To_Status (Verify (To_String (Item.Path_Text), Host, Port, Material));
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Check;

   function Verify
     (Known_Hosts_File : String;
      Host             : String;
      Port             : Natural;
      Presented_Key    : Host_Key) return Verification_Result
   is
      Input_File                     : Ada.Text_IO.File_Type;
      Host_Field                     : Unbounded_String;
      Algorithm_Text                 : Unbounded_String;
      Key_Text                       : Unbounded_String;
      Record_Status                  : Parsed_Record_Status;
      Match_Status                   : Host_List_Match;
      Candidate_Key                  : Host_Key;
      Matching_Host_Seen             : Boolean := False;
      Supported_Matching_Host_Seen   : Boolean := False;
      Unsupported_Matching_Host_Seen : Boolean := False;
      Resolved_Path                  : constant String :=
        Resolve_Known_Hosts_File (Known_Hosts_File);
   begin
      if not Is_Valid (Presented_Key) then
         return Invalid_Record;
      end if;

      if Resolved_Path'Length = 0
        or else not Ada.Directories.Exists (Resolved_Path)
      then
         return Unknown;
      end if;

      Ada.Text_IO.Open (Input_File, Ada.Text_IO.In_File, Resolved_Path);
      while not Ada.Text_IO.End_Of_File (Input_File) loop
         declare
            Line_Buffer   : String (1 .. Max_Known_Hosts_Line_Length);
            Last          : Natural;
            Line_Too_Long : Boolean := False;
         begin
            Ada.Text_IO.Get_Line (Input_File, Line_Buffer, Last);
            if Last = Line_Buffer'Last
              and then not Ada.Text_IO.End_Of_Line (Input_File)
              and then not Ada.Text_IO.End_Of_File (Input_File)
            then
               Discard_Rest_Of_Line (Input_File);
               Line_Too_Long := True;
            end if;

            if Line_Too_Long then
               --  A record that exceeds the bounded parser line length may
               --  hide an applicable host selector, marker, or key material
               --  past the buffer boundary.  Do not silently skip it and then
               --  allow a later trust line to mask the ambiguity; fail closed
               --  for this known_hosts file.
               Ada.Text_IO.Close (Input_File);
               return Unsupported_Entry;
            else
               declare
                  Line_Text : constant String := Line_Buffer (1 .. Last);
               begin
                  Parse_Known_Hosts_Line
                    (Line_Text,
                     Host_Field,
                     Algorithm_Text,
                     Key_Text,
                     Record_Status);

                  if Record_Status = Parsed_Record_Unsupported then
                     declare
                        Possible_Hosts : constant String :=
                          Possible_Host_List_Field (Line_Text);
                     begin
                        if Possible_Hosts'Length > 0 then
                           Match_Status :=
                             Match_Host_List (Possible_Hosts, Host, Port);
                           if Match_Status.Unsupported_Hash then
                              Matching_Host_Seen := True;
                              Unsupported_Matching_Host_Seen := True;
                              Ada.Text_IO.Close (Input_File);
                              return Unsupported_Entry;
                           elsif Match_Status.Unsupported_Pattern then
                              Matching_Host_Seen := True;
                              Unsupported_Matching_Host_Seen := True;
                              Ada.Text_IO.Close (Input_File);
                              return Unsupported_Entry;
                           elsif Match_Status.Negative then
                              null;
                           elsif Match_Status.Hashed_Matched then
                              Matching_Host_Seen := True;
                              Unsupported_Matching_Host_Seen := True;
                              Ada.Text_IO.Close (Input_File);
                              return Unsupported_Entry;
                           elsif Match_Status.Positive then
                              Matching_Host_Seen := True;
                              Unsupported_Matching_Host_Seen := True;
                              Ada.Text_IO.Close (Input_File);
                              return Unsupported_Entry;
                           end if;
                        end if;
                     end;
                  elsif Record_Status = Parsed_Record_Malformed then
                     declare
                        Possible_Hosts : constant String :=
                          Possible_Host_List_Field (Line_Text);
                     begin
                        if Possible_Hosts'Length > 0 then
                           Match_Status :=
                             Match_Host_List (Possible_Hosts, Host, Port);
                           if Match_Status.Unsupported_Hash then
                              Matching_Host_Seen := True;
                              Unsupported_Matching_Host_Seen := True;
                              Ada.Text_IO.Close (Input_File);
                              return Unsupported_Entry;
                           elsif Match_Status.Unsupported_Pattern then
                              Matching_Host_Seen := True;
                              Unsupported_Matching_Host_Seen := True;
                              Ada.Text_IO.Close (Input_File);
                              return Unsupported_Entry;
                           elsif Match_Status.Negative then
                              null;
                           elsif Match_Status.Hashed_Matched then
                              Matching_Host_Seen := True;
                              Unsupported_Matching_Host_Seen := True;
                              Ada.Text_IO.Close (Input_File);
                              return Unsupported_Entry;
                           elsif Match_Status.Positive then
                              Matching_Host_Seen := True;
                              if Length (Key_Text) > 0 then
                                 Unsupported_Matching_Host_Seen := True;
                                 Ada.Text_IO.Close (Input_File);
                                 return Unsupported_Entry;
                              end if;
                           end if;
                        end if;
                     end;
                  elsif Record_Status = Parsed_Record_Cert_Authority then
                     Match_Status :=
                       Match_Host_List (To_String (Host_Field), Host, Port);

                     if Match_Status.Unsupported_Hash then
                        Matching_Host_Seen := True;
                        Unsupported_Matching_Host_Seen := True;
                        Ada.Text_IO.Close (Input_File);
                        return Unsupported_Entry;
                     elsif Match_Status.Unsupported_Pattern then
                        Matching_Host_Seen := True;
                        Unsupported_Matching_Host_Seen := True;
                     elsif Match_Status.Negative then
                        null;
                     elsif Match_Status.Positive then
                        Matching_Host_Seen := True;

                        if Match_Status.Unsupported_Hash then
                           Ada.Text_IO.Close (Input_File);
                           return Unsupported_Entry;
                        elsif Match_Status.Unsupported_Pattern then
                           Unsupported_Matching_Host_Seen := True;
                        elsif SSH_Lib
                                .Protocol
                                .Certificates
                                .Is_Certificate_Algorithm
                                   (Algorithm (Presented_Key))
                        then
                           declare
                              Certificate_Data   :
                                SSH_Lib.Protocol.Buffers.Packet_Buffer;
                              Authority_Data     :
                                SSH_Lib.Protocol.Buffers.Packet_Buffer;
                              Certificate_Status : CryptoLib.Errors.Status;
                              Authority_Status   : CryptoLib.Errors.Status;
                           begin
                              Certificate_Status :=
                                Decoded_Key_Record
                                  (Encoded (Presented_Key), Certificate_Data);
                              Authority_Status :=
                                Decoded_Key_Record
                                  (To_String (Key_Text), Authority_Data);

                              if Certificate_Status = CryptoLib.Errors.Ok
                                and then Authority_Status = CryptoLib.Errors.Ok
                              then
                                 Certificate_Status :=
                                   SSH_Lib
                                     .Protocol
                                     .Certificates
                                     .Validate_Host_Certificate
                                        (SSH_Lib.Protocol.Buffers.To_Array
                                           (Certificate_Data),
                                         Algorithm (Presented_Key),
                                         Host,
                                         Port,
                                         SSH_Lib.Protocol.Buffers.To_Array
                                           (Authority_Data));
                                 if Certificate_Status = CryptoLib.Errors.Ok then
                                    Ada.Text_IO.Close (Input_File);
                                    return Trusted;
                                 elsif Certificate_Status
                                   = CryptoLib.Errors.Host_Key_Mismatch
                                 then
                                    Supported_Matching_Host_Seen := True;
                                 elsif Certificate_Status
                                   = CryptoLib.Errors.Unsupported_Feature
                                 then
                                    Unsupported_Matching_Host_Seen := True;
                                 else
                                    Supported_Matching_Host_Seen := True;
                                 end if;
                              else
                                 Unsupported_Matching_Host_Seen := True;
                              end if;
                           end;
                        else
                           --  A CA record matches the hostname but the server did not
                           --  present an OpenSSH host certificate.  Do not treat the
                           --  CA key as raw host-key trust and do not turn this into
                           --  a mismatch for ordinary raw-host-key verification.
                           null;
                        end if;
                     end if;
                  elsif Record_Status = Parsed_Record_Revoked then
                     Match_Status :=
                       Match_Host_List (To_String (Host_Field), Host, Port);

                     if Match_Status.Unsupported_Hash then
                        Matching_Host_Seen := True;
                        Unsupported_Matching_Host_Seen := True;
                        Ada.Text_IO.Close (Input_File);
                        return Unsupported_Entry;
                     elsif Match_Status.Unsupported_Pattern then
                        Matching_Host_Seen := True;
                        Unsupported_Matching_Host_Seen := True;
                     elsif Match_Status.Negative then
                        null;
                     elsif Match_Status.Positive then
                        Candidate_Key :=
                          Create_Host_Key
                            (To_String (Algorithm_Text), To_String (Key_Text));
                        if Equal (Candidate_Key, Presented_Key) then
                           --  OpenSSH @revoked records explicitly deny this host key.
                           --  Treat the presented key as a deterministic mismatch so
                           --  a later normal line can never re-enable it.
                           Ada.Text_IO.Close (Input_File);
                           return Mismatch;
                        elsif SSH_Lib
                                .Protocol
                                .Certificates
                                .Is_Certificate_Algorithm
                                   (Algorithm (Presented_Key))
                        then
                           --  A revoked raw CA key must also revoke any presented
                           --  OpenSSH host certificate signed by that CA.  Without
                           --  this check, a file could revoke a compromised CA key
                           --  while still allowing host certificates issued by it to
                           --  pass a later @cert-authority record.
                           declare
                              Certificate_Data   :
                                SSH_Lib.Protocol.Buffers.Packet_Buffer;
                              Authority_Data     :
                                SSH_Lib.Protocol.Buffers.Packet_Buffer;
                              Certificate_Status : CryptoLib.Errors.Status;
                              Authority_Status   : CryptoLib.Errors.Status;
                           begin
                              Certificate_Status :=
                                Decoded_Key_Record
                                  (Encoded (Presented_Key), Certificate_Data);
                              Authority_Status :=
                                Decoded_Key_Record
                                  (To_String (Key_Text), Authority_Data);

                              if Certificate_Status = CryptoLib.Errors.Ok
                                and then Authority_Status = CryptoLib.Errors.Ok
                              then
                                 Certificate_Status :=
                                   SSH_Lib
                                     .Protocol
                                     .Certificates
                                     .Host_Certificate_Signed_By_Public_Key
                                        (SSH_Lib.Protocol.Buffers.To_Array
                                           (Certificate_Data),
                                         Algorithm (Presented_Key),
                                         SSH_Lib.Protocol.Buffers.To_Array
                                           (Authority_Data));
                                 if Certificate_Status = CryptoLib.Errors.Ok then
                                    Ada.Text_IO.Close (Input_File);
                                    return Mismatch;
                                 elsif Certificate_Status
                                   = CryptoLib.Errors.Unsupported_Feature
                                 then
                                    Unsupported_Matching_Host_Seen := True;
                                 end if;
                              else
                                 Unsupported_Matching_Host_Seen := True;
                              end if;
                           end;
                        elsif Match_Status.Unsupported_Hash then
                           Ada.Text_IO.Close (Input_File);
                           return Unsupported_Entry;
                        elsif Match_Status.Unsupported_Pattern then
                           Unsupported_Matching_Host_Seen := True;
                        end if;
                     end if;
                  elsif Record_Status = Parsed_Record_Ok then
                     Match_Status :=
                       Match_Host_List (To_String (Host_Field), Host, Port);

                     if Match_Status.Unsupported_Hash then
                        Matching_Host_Seen := True;
                        Unsupported_Matching_Host_Seen := True;
                        Ada.Text_IO.Close (Input_File);
                        return Unsupported_Entry;
                     elsif Match_Status.Unsupported_Pattern then
                        Matching_Host_Seen := True;
                        Unsupported_Matching_Host_Seen := True;
                     elsif Match_Status.Negative then
                        null;
                     elsif Match_Status.Positive then
                        Matching_Host_Seen := True;

                        if Match_Status.Unsupported_Hash then
                           Ada.Text_IO.Close (Input_File);
                           return Unsupported_Entry;
                        elsif Match_Status.Unsupported_Pattern then
                           Unsupported_Matching_Host_Seen := True;
                        else
                           Supported_Matching_Host_Seen := True;
                           Candidate_Key :=
                             Create_Host_Key
                               (To_String (Algorithm_Text),
                                To_String (Key_Text));
                           if Equal (Candidate_Key, Presented_Key) then
                              Ada.Text_IO.Close (Input_File);
                              return Trusted;
                           end if;
                        end if;
                     end if;
                  end if;
               end;
            end if;
         end;
      end loop;

      Ada.Text_IO.Close (Input_File);

      if Supported_Matching_Host_Seen then
         return Mismatch;
      elsif Matching_Host_Seen and then Unsupported_Matching_Host_Seen then
         return Unsupported_Entry;
      else
         return Unknown;
      end if;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Input_File) then
            Ada.Text_IO.Close (Input_File);
         end if;
         return Unavailable;
   end Verify;

   function Valid_Host_Field_Text (Value : String) return Boolean is
   begin
      if Value'Length = 0 then
         return False;
      end if;

      for Char_Value of Value loop
         if Char_Value = Character'Val (0)
           or else Char_Value = Character'Val (10)
           or else Char_Value = Character'Val (13)
           or else Char_Value = ' '
           or else Char_Value = Character'Val (9)
           or else Char_Value = ','
         then
            return False;
         end if;
      end loop;
      return True;
   exception
      when others =>
         return False;
   end Valid_Host_Field_Text;

   function Host_Field (Host : String; Port : Natural) return String is
   begin
      if Port = 22 then
         return Host;
      end if;
      return "[" & Host & "]:" & Decimal_Image (Port);
   end Host_Field;

   function Append_Trusted_Host
     (Known_Hosts_File : String;
      Host             : String;
      Port             : Natural;
      Presented_Key    : Host_Key) return CryptoLib.Errors.Status
   is
      Existing_Status : Verification_Result;
      Output_File     : Ada.Text_IO.File_Type;
      Line_Text       : constant String :=
        Host_Field (Host, Port)
        & " "
        & Algorithm (Presented_Key)
        & " "
        & Encoded (Presented_Key);
   begin
      --  This helper is deliberately explicit.  It never performs silent TOFU
      --  from Sessions.Open; callers must present a key they have decided to
      --  trust and choose the file to update.
      if Known_Hosts_File'Length = 0
        or else not Valid_Host_Field_Text (Host)
        or else Port = 0
        or else not Is_Valid (Presented_Key)
        or else Line_Text'Length > Max_Known_Hosts_Line_Length
      then
         return CryptoLib.Errors.Authentication_Failed;
      end if;

      if Ada.Directories.Exists (Known_Hosts_File) then
         Existing_Status :=
           Verify (Known_Hosts_File, Host, Port, Presented_Key);
         case Existing_Status is
            when Trusted                            =>
               return CryptoLib.Errors.Ok;

            when Mismatch                           =>
               return CryptoLib.Errors.Host_Key_Mismatch;

            when Invalid_Record | Unsupported_Entry =>
               return CryptoLib.Errors.Unsupported_Feature;

            when Unknown | Unavailable              =>
               null;
         end case;
         Ada.Text_IO.Open
           (Output_File, Ada.Text_IO.Append_File, Known_Hosts_File);
      else
         Ada.Text_IO.Create
           (Output_File, Ada.Text_IO.Out_File, Known_Hosts_File);
      end if;

      Ada.Text_IO.Put_Line (Output_File, Line_Text);
      Ada.Text_IO.Close (Output_File);
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Output_File) then
            Ada.Text_IO.Close (Output_File);
         end if;
         return CryptoLib.Errors.Internal_Error;
   end Append_Trusted_Host;

   function To_Status
     (Value : Verification_Result) return CryptoLib.Errors.Status is
   begin
      case Value is
         when Trusted                            =>
            return CryptoLib.Errors.Ok;

         when Unknown                            =>
            return CryptoLib.Errors.Host_Key_Unknown;

         when Mismatch                           =>
            return CryptoLib.Errors.Host_Key_Mismatch;

         when Invalid_Record | Unsupported_Entry =>
            return CryptoLib.Errors.Unsupported_Feature;

         when Unavailable                        =>
            return CryptoLib.Errors.Internal_Error;
      end case;
   end To_Status;
end SSH_Lib.Known_Hosts;
