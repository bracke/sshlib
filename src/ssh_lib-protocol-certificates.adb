with Ada.Calendar;
with Ada.Characters.Handling;
with Ada.Strings.Unbounded;
with Interfaces;
with CryptoLib.Constant_Time;
with SSH_Lib.Signatures;
with SSH_Lib.Keys.Internal;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Host_Keys;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Validation;

package body SSH_Lib.Protocol.Certificates is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;
   use type Ada.Calendar.Time;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;

   Max_Certificate_Blob_Length : constant Natural := 256 * 1024;
   User_Certificate_Type       : constant Interfaces.Unsigned_32 := 1;
   Host_Certificate_Type       : constant Interfaces.Unsigned_32 := 2;
   Forever_Valid_Before        : constant Interfaces.Unsigned_64 :=
     Interfaces.Unsigned_64'Last;

   function Is_Certificate_Algorithm (Algorithm_Name : String) return Boolean
   is
   begin
      return
        Algorithm_Name = "ssh-ed25519-cert-v01@openssh.com"
        or else Algorithm_Name = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
        or else Algorithm_Name = "sk-ssh-ed25519-cert-v01@openssh.com"
        or else Algorithm_Name = "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"
        or else Algorithm_Name = "rsa-sha2-512-cert-v01@openssh.com"
        or else Algorithm_Name = "rsa-sha2-256-cert-v01@openssh.com"
        or else Algorithm_Name = "ssh-rsa-cert-v01@openssh.com";
   end Is_Certificate_Algorithm;

   function Raw_Algorithm_For_Certificate
     (Algorithm_Name : String) return String is
   begin
      if Algorithm_Name = "ssh-ed25519-cert-v01@openssh.com" then
         return "ssh-ed25519";
      elsif Algorithm_Name = "ecdsa-sha2-nistp256-cert-v01@openssh.com" then
         return "ecdsa-sha2-nistp256";
      elsif Algorithm_Name = "sk-ssh-ed25519-cert-v01@openssh.com" then
         return "sk-ssh-ed25519@openssh.com";
      elsif Algorithm_Name = "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" then
         return "sk-ecdsa-sha2-nistp256@openssh.com";
      elsif Algorithm_Name = "rsa-sha2-512-cert-v01@openssh.com" then
         return "rsa-sha2-512";
      elsif Algorithm_Name = "rsa-sha2-256-cert-v01@openssh.com" then
         return "rsa-sha2-256";
      elsif Algorithm_Name = "ssh-rsa-cert-v01@openssh.com" then
         return "ssh-rsa";
      else
         return "";
      end if;
   end Raw_Algorithm_For_Certificate;

   function Decode_Uint64
     (Data        : Stream_Element_Array;
      First_Index : Stream_Element_Offset;
      Value       : out Interfaces.Unsigned_64;
      Next_Index  : out Stream_Element_Offset) return Status is
   begin
      Value := 0;
      Next_Index := First_Index;
      if First_Index < Data'First or else First_Index + 7 > Data'Last then
         return Handshake_Failed;
      end if;
      for Index_Value in First_Index .. First_Index + 7 loop
         Value :=
           Interfaces.Shift_Left (Value, 8)
           or Interfaces.Unsigned_64 (Data (Index_Value));
      end loop;
      Next_Index := First_Index + 8;
      return Ok;
   exception
      when others =>
         Value := 0;
         Next_Index := First_Index;
         return Internal_Error;
   end Decode_Uint64;

   function Decode_Uint32_Local
     (Data        : Stream_Element_Array;
      First_Index : Stream_Element_Offset;
      Value       : out Interfaces.Unsigned_32;
      Next_Index  : out Stream_Element_Offset) return Status is
   begin
      return
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Data, First_Index, Value, Next_Index);
   end Decode_Uint32_Local;

   function SSH_String_To_Text
     (Data : Stream_Element_Array; Text : out Unbounded_String) return Status
   is
   begin
      Text := Null_Unbounded_String;
      for Byte_Value of Data loop
         if Byte_Value = 0 or else Byte_Value > 127 then
            Text := Null_Unbounded_String;
            return Handshake_Failed;
         end if;
         Append (Text, Character'Val (Natural (Byte_Value)));
      end loop;
      return Ok;
   exception
      when others =>
         Text := Null_Unbounded_String;
         return Internal_Error;
   end SSH_String_To_Text;

   function Decimal_Image (Value : Natural) return String is
      Raw : constant String := Natural'Image (Value);
   begin
      if Raw'Length > 0 and then Raw (Raw'First) = ' ' then
         return Raw (Raw'First + 1 .. Raw'Last);
      else
         return Raw;
      end if;
   end Decimal_Image;

   function Principal_Pattern_Matches
     (Pattern_Text : String; Host_Text : String) return Boolean
   is
      function Match_From
        (Pattern_Index : Natural; Host_Index : Natural) return Boolean is
      begin
         if Pattern_Index > Pattern_Text'Last then
            return Host_Index > Host_Text'Last;
         end if;

         if Pattern_Text (Pattern_Index) = '*' then
            if Pattern_Index = Pattern_Text'Last then
               return True;
            end if;
            declare
               Candidate_Index : Natural := Host_Index;
            begin
               while Candidate_Index <= Host_Text'Last + 1 loop
                  if Match_From (Pattern_Index + 1, Candidate_Index) then
                     return True;
                  end if;
                  Candidate_Index := Candidate_Index + 1;
               end loop;
               return False;
            end;
         elsif Pattern_Text (Pattern_Index) = '?' then
            return
              Host_Index <= Host_Text'Last
              and then Match_From (Pattern_Index + 1, Host_Index + 1);
         elsif Host_Index <= Host_Text'Last
           and then Pattern_Text (Pattern_Index) = Host_Text (Host_Index)
         then
            return Match_From (Pattern_Index + 1, Host_Index + 1);
         else
            return False;
         end if;
      end Match_From;

   begin
      if Pattern_Text'Length = 0 then
         return False;
      end if;
      return Match_From (Pattern_Text'First, Host_Text'First);
   exception
      when others =>
         return False;
   end Principal_Pattern_Matches;

   function Principal_Candidate_Matches
     (Candidate      : String;
      Host_Lower     : String;
      Port           : Natural;
      Bracketed_Host : String) return Boolean
   is
      Portless_Bracketed : constant String := "[" & Host_Lower & "]";
      Has_Wildcard       : Boolean := False;
   begin
      if Candidate = Host_Lower
        or else Candidate = Portless_Bracketed
        or else (Port /= 22 and then Candidate = Bracketed_Host)
      then
         return True;
      end if;

      for Character_Value of Candidate loop
         if Character_Value = '*' or else Character_Value = '?' then
            Has_Wildcard := True;
         end if;
      end loop;

      if not Has_Wildcard then
         return False;
      end if;

      return
        Principal_Pattern_Matches (Candidate, Host_Lower)
        or else Principal_Pattern_Matches (Candidate, Portless_Bracketed)
        or else
          (Port /= 22
           and then Principal_Pattern_Matches (Candidate, Bracketed_Host));
   exception
      when others =>
         return False;
   end Principal_Candidate_Matches;

   function Principal_Matches
     (Principals : Stream_Element_Array; Host : String; Port : Natural)
      return Boolean
   is
      Cursor           : Stream_Element_Offset := Principals'First;
      Principal_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Next_Cursor      : Stream_Element_Offset;
      Status_Value     : Status;
      Principal_Text   : Unbounded_String;
      Host_Lower       : constant String :=
        Ada.Characters.Handling.To_Lower (Host);
      Bracketed_Host   : constant String :=
        "[" & Host_Lower & "]:" & Decimal_Image (Port);
   begin
      if Principals'Length = 0 then
         --  Host certificates must name the host explicitly.  Empty
         --  principal lists are not treated as wildcard trust here.
         return False;
      end if;

      while Cursor <= Principals'Last loop
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Principals, Cursor, Principal_Buffer, Next_Cursor);
         if Status_Value /= Ok or else Next_Cursor <= Cursor then
            return False;
         end if;
         Status_Value :=
           SSH_String_To_Text
             (SSH_Lib.Protocol.Buffers.To_Array (Principal_Buffer),
              Principal_Text);
         if Status_Value /= Ok then
            return False;
         end if;
         declare
            Candidate : constant String :=
              Ada.Characters.Handling.To_Lower (To_String (Principal_Text));
         begin
            if Principal_Candidate_Matches
                 (Candidate, Host_Lower, Port, Bracketed_Host)
            then
               return True;
            end if;
         end;
         Cursor := Next_Cursor;
      end loop;
      return Cursor = Principals'Last + 1 and then False;
   exception
      when others =>
         return False;
   end Principal_Matches;

   function Text_Less
     (Left_Value : String; Right_Value : String) return Boolean is
   begin
      return Left_Value < Right_Value;
   exception
      when others =>
         return False;
   end Text_Less;

   function SSH_String_List_Well_Formed
     (Data : Stream_Element_Array) return Boolean
   is
      Cursor       : Stream_Element_Offset := Data'First;
      Next_Cursor  : Stream_Element_Offset;
      Entry_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : Status;
   begin
      if Data'Length = 0 then
         return True;
      end if;
      while Cursor <= Data'Last loop
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Data, Cursor, Entry_Buffer, Next_Cursor);
         if Status_Value /= Ok or else Next_Cursor <= Cursor then
            return False;
         end if;
         Cursor := Next_Cursor;
      end loop;
      return Cursor = Data'Last + 1;
   exception
      when others =>
         return False;
   end SSH_String_List_Well_Formed;

   function Valid_Source_Address_Text (Value : String) return Boolean is
      function Decimal_Value_Within
        (Text : String; Max_Value : Natural) return Boolean
      is
         Numeric_Value : Natural := 0;
      begin
         if Text'Length = 0 then
            return False;
         end if;
         for Char_Value of Text loop
            if Char_Value < '0' or else Char_Value > '9' then
               return False;
            end if;
            Numeric_Value :=
              Numeric_Value
              * 10
              + (Character'Pos (Char_Value) - Character'Pos ('0'));
            if Numeric_Value > Max_Value then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Decimal_Value_Within;

      function Valid_IPv4_Address (Text : String) return Boolean is
         Segment_First : Natural := Text'First;
         Segment_Last  : Natural;
         Segment_Count : Natural := 0;
      begin
         if Text'Length = 0 then
            return False;
         end if;

         while Segment_First <= Text'Last loop
            Segment_Last := Segment_First;
            while Segment_Last <= Text'Last and then Text (Segment_Last) /= '.'
            loop
               Segment_Last := Segment_Last + 1;
            end loop;

            if Segment_Last = Segment_First then
               return False;
            end if;
            Segment_Count := Segment_Count + 1;
            if Segment_Count > 4
              or else
                not Decimal_Value_Within
                      (Text (Segment_First .. Segment_Last - 1), 255)
            then
               return False;
            end if;

            Segment_First := Segment_Last + 1;
         end loop;

         return Segment_Count = 4;
      exception
         when others =>
            return False;
      end Valid_IPv4_Address;

      function Is_Hex_Digit (Char_Value : Character) return Boolean is
      begin
         return
           (Char_Value >= '0' and then Char_Value <= '9')
           or else (Char_Value >= 'a' and then Char_Value <= 'f')
           or else (Char_Value >= 'A' and then Char_Value <= 'F');
      end Is_Hex_Digit;

      function Valid_IPv6_Address (Text : String) return Boolean is
         Group_Digits       : Natural := 0;
         Group_Count        : Natural := 0;
         Have_Double_Colon  : Boolean := False;
         Have_Colon         : Boolean := False;
         Previous_Was_Colon : Boolean := False;
         Index_Value        : Natural := Text'First;
      begin
         if Text'Length = 0 then
            return False;
         end if;

         while Index_Value <= Text'Last loop
            if Is_Hex_Digit (Text (Index_Value)) then
               Group_Digits := Group_Digits + 1;
               if Group_Digits > 4 then
                  return False;
               end if;
               Previous_Was_Colon := False;
            elsif Text (Index_Value) = ':' then
               Have_Colon := True;
               if Previous_Was_Colon then
                  if Have_Double_Colon then
                     return False;
                  end if;
                  Have_Double_Colon := True;
               else
                  if Group_Digits > 0 then
                     Group_Count := Group_Count + 1;
                     Group_Digits := 0;
                  elsif Index_Value /= Text'First then
                     return False;
                  end if;
               end if;
               Previous_Was_Colon := True;
            else
               return False;
            end if;
            Index_Value := Index_Value + 1;
         end loop;

         if Group_Digits > 0 then
            Group_Count := Group_Count + 1;
         elsif not Previous_Was_Colon then
            return False;
         end if;

         if not Have_Colon then
            return False;
         end if;

         --  A single trailing colon is not a valid IPv6 terminator.  Only a
         --  double-colon compression marker may end an IPv6 literal, such as
         --  ``2001:db8::``.  Without this check, addresses like
         --  ``2001:db8:1:2:3:4:5:`` could be misclassified as complete
         --  eight-group literals because the last non-empty group had already
         --  been counted before the trailing separator.
         if Previous_Was_Colon and then not Have_Double_Colon then
            return False;
         end if;

         if Have_Double_Colon then
            return Group_Count < 8;
         else
            return Group_Count = 8;
         end if;
      exception
         when others =>
            return False;
      end Valid_IPv6_Address;

      function Valid_Source_Address_Item (Text : String) return Boolean is
         Slash_Index : Natural := 0;
         Have_Dot    : Boolean := False;
         Have_Colon  : Boolean := False;
      begin
         if Text'Length = 0 then
            return False;
         end if;

         for Index_Value in Text'Range loop
            if Text (Index_Value) = '/' then
               if Slash_Index /= 0 then
                  return False;
               end if;
               Slash_Index := Index_Value;
            elsif Text (Index_Value) = '.' then
               Have_Dot := True;
            elsif Text (Index_Value) = ':' then
               Have_Colon := True;
            end if;
         end loop;

         declare
            Address_Last : constant Natural :=
              (if Slash_Index = 0 then Text'Last else Slash_Index - 1);
            Mask_First   : constant Natural :=
              (if Slash_Index = 0 then Text'Last + 1 else Slash_Index + 1);
         begin
            if Address_Last < Text'First then
               return False;
            end if;

            if Have_Colon then
               if not Valid_IPv6_Address (Text (Text'First .. Address_Last))
               then
                  return False;
               end if;
               if Slash_Index /= 0 then
                  return
                    Mask_First <= Text'Last
                    and then
                      Decimal_Value_Within
                        (Text (Mask_First .. Text'Last), 128);
               end if;
               return True;
            elsif Have_Dot then
               if not Valid_IPv4_Address (Text (Text'First .. Address_Last))
               then
                  return False;
               end if;
               if Slash_Index /= 0 then
                  return
                    Mask_First <= Text'Last
                    and then
                      Decimal_Value_Within
                        (Text (Mask_First .. Text'Last), 32);
               end if;
               return True;
            else
               return False;
            end if;
         end;
      exception
         when others =>
            return False;
      end Valid_Source_Address_Item;

      Segment_First : Natural := Value'First;
      Segment_Last  : Natural;
   begin
      if Value'Length = 0 then
         return False;
      end if;

      while Segment_First <= Value'Last loop
         Segment_Last := Segment_First;
         while Segment_Last <= Value'Last and then Value (Segment_Last) /= ','
         loop
            Segment_Last := Segment_Last + 1;
         end loop;

         if Segment_Last = Segment_First
           or else
             not Valid_Source_Address_Item
                   (Value (Segment_First .. Segment_Last - 1))
         then
            return False;
         end if;

         Segment_First := Segment_Last + 1;
      end loop;

      return True;
   exception
      when others =>
         return False;
   end Valid_Source_Address_Text;

   function Decode_Critical_Option_String
     (Data  : Stream_Element_Array;
      Value : out SSH_Lib.Protocol.Buffers.Packet_Buffer) return Status
   is
      Next_Cursor  : Stream_Element_Offset;
      Status_Value : Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Value);
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Data, Data'First, Value, Next_Cursor);
      if Status_Value /= Ok then
         return Handshake_Failed;
      end if;
      if Next_Cursor /= Data'Last + 1 then
         SSH_Lib.Protocol.Buffers.Clear (Value);
         return Handshake_Failed;
      end if;
      return Ok;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Value);
         return Internal_Error;
   end Decode_Critical_Option_String;

   function Decode_Critical_Option_Text
     (Data : Stream_Element_Array; Text : out Unbounded_String) return Status
   is
      Text_Buffer  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : Status;
   begin
      Text := Null_Unbounded_String;
      Status_Value := Decode_Critical_Option_String (Data, Text_Buffer);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_String_To_Text
          (SSH_Lib.Protocol.Buffers.To_Array (Text_Buffer), Text);
      SSH_Lib.Protocol.Buffers.Clear (Text_Buffer);
      if Status_Value /= Ok then
         Text := Null_Unbounded_String;
         return Handshake_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Text := Null_Unbounded_String;
         return Internal_Error;
   end Decode_Critical_Option_Text;

   function Critical_Option_Has_No_Data
     (Data : Stream_Element_Array) return Boolean is
   begin
      return Data'Length = 0;
   exception
      when others =>
         return False;
   end Critical_Option_Has_No_Data;

   function Validate_Certificate_Option_Map
     (Options : Stream_Element_Array) return Status
   is
      Cursor        : Stream_Element_Offset := Options'First;
      Next_Cursor   : Stream_Element_Offset;
      Name_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Data_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value  : Status;
      Name_Text     : Unbounded_String;
      Previous_Name : Unbounded_String := Null_Unbounded_String;
      Have_Previous : Boolean := False;
   begin
      if Options'Length = 0 then
         return Ok;
      end if;
      while Cursor <= Options'Last loop
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Options, Cursor, Name_Buffer, Next_Cursor);
         if Status_Value /= Ok or else Next_Cursor <= Cursor then
            return Handshake_Failed;
         end if;
         Cursor := Next_Cursor;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Options, Cursor, Data_Buffer, Next_Cursor);
         if Status_Value /= Ok or else Next_Cursor <= Cursor then
            return Handshake_Failed;
         end if;
         Cursor := Next_Cursor;
         Status_Value :=
           SSH_String_To_Text
             (SSH_Lib.Protocol.Buffers.To_Array (Name_Buffer), Name_Text);
         if Status_Value /= Ok
           or else
             not SSH_Lib.Protocol.Validation.Is_ASCII_Protocol_Name
                   (To_String (Name_Text))
         then
            return Handshake_Failed;
         end if;
         if Have_Previous
           and then
             not Text_Less (To_String (Previous_Name), To_String (Name_Text))
         then
            return Handshake_Failed;
         end if;
         Previous_Name := Name_Text;
         Have_Previous := True;
      end loop;
      if Cursor = Options'Last + 1 then
         return Ok;
      else
         return Handshake_Failed;
      end if;
   exception
      when others =>
         return Internal_Error;
   end Validate_Certificate_Option_Map;

   function Validate_User_Critical_Options
     (Options : Stream_Element_Array) return Status
   is
      Cursor       : Stream_Element_Offset := Options'First;
      Next_Cursor  : Stream_Element_Offset;
      Name_Buffer  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Data_Buffer  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : Status;
      Name_Text    : Unbounded_String;
   begin
      Status_Value := Validate_Certificate_Option_Map (Options);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if Options'Length = 0 then
         return Ok;
      end if;
      while Cursor <= Options'Last loop
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Options, Cursor, Name_Buffer, Next_Cursor);
         if Status_Value /= Ok or else Next_Cursor <= Cursor then
            return Handshake_Failed;
         end if;
         Cursor := Next_Cursor;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Options, Cursor, Data_Buffer, Next_Cursor);
         if Status_Value /= Ok or else Next_Cursor <= Cursor then
            return Handshake_Failed;
         end if;
         Cursor := Next_Cursor;
         Status_Value :=
           SSH_String_To_Text
             (SSH_Lib.Protocol.Buffers.To_Array (Name_Buffer), Name_Text);
         if Status_Value /= Ok then
            return Handshake_Failed;
         end if;
         declare
            Name_Value : constant String := To_String (Name_Text);
            Data_Array : constant Stream_Element_Array :=
              SSH_Lib.Protocol.Buffers.To_Array (Data_Buffer);
            Data_Value : Unbounded_String;
         begin
            if Name_Value = "source-address" then
               Status_Value :=
                 Decode_Critical_Option_Text (Data_Array, Data_Value);
               if Status_Value /= Ok
                 or else not Valid_Source_Address_Text (To_String (Data_Value))
               then
                  return Handshake_Failed;
               end if;
            elsif Name_Value = "force-command" then
               declare
                  Command_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
               begin
                  Status_Value :=
                    Decode_Critical_Option_String (Data_Array, Command_Buffer);
                  SSH_Lib.Protocol.Buffers.Clear (Command_Buffer);
                  if Status_Value /= Ok then
                     return Handshake_Failed;
                  end if;
               end;
            elsif Name_Value = "verify-required"
              or else Name_Value = "no-touch-required"
            then
               if not Critical_Option_Has_No_Data (Data_Array) then
                  return Handshake_Failed;
               end if;
            else
               null;
            end if;
         end;
      end loop;
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Validate_User_Critical_Options;

   function Validate_Host_Critical_Options
     (Options : Stream_Element_Array) return Status
   is
      Cursor        : Stream_Element_Offset := Options'First;
      Next_Cursor   : Stream_Element_Offset;
      Name_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Data_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value  : Status;
      Name_Text     : Unbounded_String;
      Previous_Name : Unbounded_String := Null_Unbounded_String;
      Have_Previous : Boolean := False;
   begin
      if Options'Length = 0 then
         return Ok;
      end if;

      while Cursor <= Options'Last loop
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Options, Cursor, Name_Buffer, Next_Cursor);
         if Status_Value /= Ok or else Next_Cursor <= Cursor then
            return Handshake_Failed;
         end if;
         Cursor := Next_Cursor;

         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Options, Cursor, Data_Buffer, Next_Cursor);
         if Status_Value /= Ok or else Next_Cursor <= Cursor then
            return Handshake_Failed;
         end if;
         Cursor := Next_Cursor;

         Status_Value :=
           SSH_String_To_Text
             (SSH_Lib.Protocol.Buffers.To_Array (Name_Buffer), Name_Text);
         if Status_Value /= Ok
           or else
             not SSH_Lib.Protocol.Validation.Is_ASCII_Protocol_Name
                   (To_String (Name_Text))
         then
            return Handshake_Failed;
         end if;

         if Have_Previous
           and then
             not Text_Less (To_String (Previous_Name), To_String (Name_Text))
         then
            --  OpenSSH certificates encode critical options as a sorted map.
            --  Duplicate or unsorted names indicate a non-canonical or
            --  malformed certificate and are rejected before any policy check.
            return Handshake_Failed;
         end if;
         Previous_Name := Name_Text;
         Have_Previous := True;

         declare
            Name_Value : constant String := To_String (Name_Text);
            Data_Array : constant Stream_Element_Array :=
              SSH_Lib.Protocol.Buffers.To_Array (Data_Buffer);
            Data_Value : Unbounded_String;
         begin
            if Name_Value = "source-address" then
               --  OpenSSH encodes source-address option data as a nested SSH
               --  string containing a comma-separated CIDR/address list.  Parse
               --  that structure before applying host-certificate policy so a
               --  syntactically valid but inapplicable option is reported as a
               --  certificate policy mismatch, while malformed option data
               --  remains a handshake failure.
               Status_Value :=
                 Decode_Critical_Option_Text (Data_Array, Data_Value);
               if Status_Value /= Ok
                 or else not Valid_Source_Address_Text (To_String (Data_Value))
               then
                  return Handshake_Failed;
               end if;
               return Host_Key_Mismatch;
            elsif Name_Value = "force-command" then
               --  force-command is likewise nested SSH-string data and only
               --  meaningful for user certificates.  The command is parsed only
               --  for certificate canonicality; it is never executed or exposed
               --  as policy for server host keys.  Its payload is binary SSH
               --  string data, so local validation checks only the nested string
               --  framing rather than performing text conversion.
               declare
                  Command_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
               begin
                  Status_Value :=
                    Decode_Critical_Option_String (Data_Array, Command_Buffer);
                  SSH_Lib.Protocol.Buffers.Clear (Command_Buffer);
                  if Status_Value /= Ok then
                     return Handshake_Failed;
                  end if;
               end;
               return Host_Key_Mismatch;
            elsif Name_Value = "verify-required"
              or else Name_Value = "no-touch-required"
            then
               --  These security-key/user-certificate policy switches carry no
               --  payload in OpenSSH certificate maps.  Reject them for host
               --  certificates only after checking that they are canonical.
               if not Critical_Option_Has_No_Data (Data_Array) then
                  return Handshake_Failed;
               end if;
               return Host_Key_Mismatch;
            else
               --  Unknown critical options must remain fail-closed because a
               --  critical option is a CA-imposed validation requirement.
               return Unsupported_Feature;
            end if;
         end;
      end loop;

      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Validate_Host_Critical_Options;

   function Validate_Host_Critical_Options_For_Test
     (Options : Stream_Element_Array) return Status is
   begin
      return Validate_Host_Critical_Options (Options);
   exception
      when others =>
         return Internal_Error;
   end Validate_Host_Critical_Options_For_Test;

   function Host_Principals_Match_For_Test
     (Principals : Stream_Element_Array; Host : String; Port : Natural)
      return Boolean is
   begin
      return Principal_Matches (Principals, Host, Port);
   exception
      when others =>
         return False;
   end Host_Principals_Match_For_Test;

   function Validate_User_Critical_Options_For_Test
     (Options : Stream_Element_Array) return Status is
   begin
      return Validate_User_Critical_Options (Options);
   exception
      when others =>
         return Internal_Error;
   end Validate_User_Critical_Options_For_Test;

   function Current_Unix_Time return Interfaces.Unsigned_64 is
      Epoch            : constant Ada.Calendar.Time :=
        Ada.Calendar.Time_Of (1970, 1, 1, 0.0);
      Now              : constant Ada.Calendar.Time := Ada.Calendar.Clock;
      Elapsed_Duration : constant Duration := Now - Epoch;
   begin
      if Elapsed_Duration <= 0.0 then
         return 0;
      else
         return Interfaces.Unsigned_64 (Elapsed_Duration);
      end if;
   exception
      when others =>
         return 0;
   end Current_Unix_Time;

   function Certificate_Validity_Window_Is_Canonical
     (Valid_After  : Interfaces.Unsigned_64;
      Valid_Before : Interfaces.Unsigned_64) return Boolean is
   begin
      return
        Valid_Before = Forever_Valid_Before or else Valid_After < Valid_Before;
   exception
      when others =>
         return False;
   end Certificate_Validity_Window_Is_Canonical;

   function Is_Supported_Certificate_Signature_Algorithm
     (Algorithm_Name : String) return Boolean is
   begin
      return
        Algorithm_Name = "ssh-ed25519"
        or else Algorithm_Name = "ecdsa-sha2-nistp256"
        or else Algorithm_Name = "rsa-sha2-512"
        or else Algorithm_Name = "rsa-sha2-256"
        or else Algorithm_Name = "ssh-rsa";
   exception
      when others =>
         return False;
   end Is_Supported_Certificate_Signature_Algorithm;

   function Certificate_Signature_Algorithm_Compatible
     (Signature_Algorithm_Name : String; Authority_Algorithm_Name : String)
      return Boolean is
   begin
      if Authority_Algorithm_Name = "ssh-ed25519" then
         return Signature_Algorithm_Name = "ssh-ed25519";
      elsif Authority_Algorithm_Name = "ecdsa-sha2-nistp256" then
         return Signature_Algorithm_Name = "ecdsa-sha2-nistp256";
      elsif Authority_Algorithm_Name = "ssh-rsa"
        or else Authority_Algorithm_Name = "rsa-sha2-512"
        or else Authority_Algorithm_Name = "rsa-sha2-256"
      then
         --  OpenSSH RSA CA keys are encoded as ssh-rsa public keys, but the
         --  certificate signature itself may use SHA-2 RSA algorithms.  Permit
         --  the supported RSA signature algorithms for RSA CA keys and reject
         --  cross-family signatures before invoking lower-level verification.
         return
           Signature_Algorithm_Name = "rsa-sha2-512"
           or else Signature_Algorithm_Name = "rsa-sha2-256"
           or else Signature_Algorithm_Name = "ssh-rsa";
      else
         return False;
      end if;
   exception
      when others =>
         return False;
   end Certificate_Signature_Algorithm_Compatible;

   function Signature_Algorithm
     (Signature_Blob  : Stream_Element_Array;
      Algorithm_Text  : out Unbounded_String;
      Signature_Bytes : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return Status
   is
      Algorithm_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      After_Algorithm  : Stream_Element_Offset;
      After_Signature  : Stream_Element_Offset;
      Status_Value     : Status;
   begin
      Algorithm_Text := Null_Unbounded_String;
      SSH_Lib.Protocol.Buffers.Clear (Signature_Bytes);
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Signature_Blob,
           Signature_Blob'First,
           Algorithm_Buffer,
           After_Algorithm);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Signature_Blob, After_Algorithm, Signature_Bytes, After_Signature);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if After_Signature /= Signature_Blob'Last + 1 then
         return Handshake_Failed;
      end if;
      Status_Value :=
        SSH_String_To_Text
          (SSH_Lib.Protocol.Buffers.To_Array (Algorithm_Buffer),
           Algorithm_Text);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if not SSH_Lib.Protocol.Validation.Is_ASCII_Protocol_Name
               (To_String (Algorithm_Text))
      then
         Algorithm_Text := Null_Unbounded_String;
         SSH_Lib.Protocol.Buffers.Clear (Signature_Bytes);
         return Handshake_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Algorithm_Text := Null_Unbounded_String;
         SSH_Lib.Protocol.Buffers.Clear (Signature_Bytes);
         return Internal_Error;
   end Signature_Algorithm;

   type Parsed_Certificate is record
      Raw_Algorithm      : Unbounded_String;
      Host_Key_Blob      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Principals         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Critical_Options   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Extensions         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Signature_Key_Blob : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Signature_Blob     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Signed_Portion     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Valid_After        : Interfaces.Unsigned_64 := 0;
      Valid_Before       : Interfaces.Unsigned_64 := 0;
      Certificate_Type   : Interfaces.Unsigned_32 := 0;
   end record;

   function Parse_Certificate
     (Certificate_Blob      : Stream_Element_Array;
      Certificate_Algorithm : String;
      Item                  : out Parsed_Certificate) return Status
   is
      Algorithm_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Nonce_Buffer     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Exponent_Buffer  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Modulus_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Key_Buffer       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Key_Id_Buffer    : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reserved_Buffer  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Cursor           : Stream_Element_Offset;
      Next_Cursor      : Stream_Element_Offset;
      Serial_Number    : Interfaces.Unsigned_64;
      Cert_Type        : Interfaces.Unsigned_32;
      Status_Value     : Status;
      Raw_Name         : constant String :=
        Raw_Algorithm_For_Certificate (Certificate_Algorithm);
      Before_Signature : Stream_Element_Offset;
   begin
      Item.Raw_Algorithm := Null_Unbounded_String;
      SSH_Lib.Protocol.Buffers.Clear (Item.Host_Key_Blob);
      SSH_Lib.Protocol.Buffers.Clear (Item.Principals);
      SSH_Lib.Protocol.Buffers.Clear (Item.Critical_Options);
      SSH_Lib.Protocol.Buffers.Clear (Item.Extensions);
      SSH_Lib.Protocol.Buffers.Clear (Item.Signature_Key_Blob);
      SSH_Lib.Protocol.Buffers.Clear (Item.Signature_Blob);
      SSH_Lib.Protocol.Buffers.Clear (Item.Signed_Portion);
      Item.Valid_After := 0;
      Item.Valid_Before := 0;
      Item.Certificate_Type := 0;

      if not Is_Certificate_Algorithm (Certificate_Algorithm)
        or else Certificate_Blob'Length = 0
        or else Certificate_Blob'Length > Max_Certificate_Blob_Length
        or else Raw_Name'Length = 0
      then
         return Handshake_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Certificate_Blob, Certificate_Blob'First, Algorithm_Buffer, Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      declare
         Algorithm_Text : Unbounded_String;
      begin
         Status_Value :=
           SSH_String_To_Text
             (SSH_Lib.Protocol.Buffers.To_Array (Algorithm_Buffer),
              Algorithm_Text);
         if Status_Value /= Ok
           or else To_String (Algorithm_Text) /= Certificate_Algorithm
         then
            return Handshake_Failed;
         end if;
      end;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Certificate_Blob, Cursor, Nonce_Buffer, Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Raw_Name = "ssh-ed25519"
        or else Raw_Name = "sk-ssh-ed25519@openssh.com"
      then
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Certificate_Blob, Cursor, Key_Buffer, Cursor);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         if Raw_Name = "sk-ssh-ed25519@openssh.com" then
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Certificate_Blob, Cursor, Modulus_Buffer, Cursor);
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         end if;
      elsif Raw_Name = "ecdsa-sha2-nistp256"
        or else Raw_Name = "sk-ecdsa-sha2-nistp256@openssh.com"
      then
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Certificate_Blob, Cursor, Exponent_Buffer, Cursor);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Certificate_Blob, Cursor, Key_Buffer, Cursor);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         if Raw_Name = "sk-ecdsa-sha2-nistp256@openssh.com" then
            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_SSH_String
                (Certificate_Blob, Cursor, Modulus_Buffer, Cursor);
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         end if;
      else
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Certificate_Blob, Cursor, Exponent_Buffer, Cursor);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         Status_Value :=
           SSH_Lib.Protocol.Numbers.Decode_SSH_String
             (Certificate_Blob, Cursor, Modulus_Buffer, Cursor);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end if;

      Status_Value :=
        Decode_Uint64 (Certificate_Blob, Cursor, Serial_Number, Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Decode_Uint32_Local (Certificate_Blob, Cursor, Cert_Type, Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if Cert_Type /= Host_Certificate_Type
        and then Cert_Type /= User_Certificate_Type
      then
         return Host_Key_Mismatch;
      end if;
      Item.Certificate_Type := Cert_Type;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Certificate_Blob, Cursor, Key_Id_Buffer, Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Certificate_Blob, Cursor, Item.Principals, Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Decode_Uint64 (Certificate_Blob, Cursor, Item.Valid_After, Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Decode_Uint64 (Certificate_Blob, Cursor, Item.Valid_Before, Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Certificate_Blob, Cursor, Item.Critical_Options, Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Certificate_Blob, Cursor, Item.Extensions, Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Certificate_Blob, Cursor, Reserved_Buffer, Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if not SSH_Lib.Protocol.Buffers.Is_Empty (Reserved_Buffer) then
         --  OpenSSH certificate format reserves this SSH string for future
         --  protocol use.  Accepting non-empty reserved data would create an
         --  ambiguity where a CA could attach semantics this implementation
         --  does not understand.  Keep both host and user certificates
         --  fail-closed until such semantics are explicitly implemented.
         return Handshake_Failed;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Certificate_Blob, Cursor, Item.Signature_Key_Blob, Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Before_Signature := Cursor;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Certificate_Blob, Cursor, Item.Signature_Blob, Next_Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if Next_Cursor /= Certificate_Blob'Last + 1 then
         return Handshake_Failed;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Buffers.Set
          (Item.Signed_Portion,
           Certificate_Blob (Certificate_Blob'First .. Before_Signature - 1));
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      declare
         Host_Key_Data : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      begin
         declare
            Key_Blob_Name : constant String :=
              (if Raw_Name = "ssh-ed25519"
               then "ssh-ed25519"
               elsif Raw_Name = "ecdsa-sha2-nistp256"
               then "ecdsa-sha2-nistp256"
               elsif Raw_Name = "sk-ssh-ed25519@openssh.com"
               then "sk-ssh-ed25519@openssh.com"
               elsif Raw_Name = "sk-ecdsa-sha2-nistp256@openssh.com"
               then "sk-ecdsa-sha2-nistp256@openssh.com"
               else "ssh-rsa");
         begin
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Append
                (Host_Key_Data,
                 SSH_Lib.Protocol.Buffers.To_Array
                   (SSH_Lib.Protocol.Numbers.Encode_Name_List
                      (Key_Blob_Name)));
         end;
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         if Raw_Name = "ssh-ed25519"
           or else Raw_Name = "sk-ssh-ed25519@openssh.com"
         then
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Append
                (Host_Key_Data,
                 SSH_Lib.Protocol.Buffers.To_Array
                   (SSH_Lib.Protocol.Numbers.Encode_SSH_String
                      (SSH_Lib.Protocol.Buffers.To_Array (Key_Buffer))));
            if Status_Value = Ok
              and then Raw_Name = "sk-ssh-ed25519@openssh.com"
            then
               Status_Value :=
                 SSH_Lib.Protocol.Buffers.Append
                   (Host_Key_Data,
                    SSH_Lib.Protocol.Buffers.To_Array
                      (SSH_Lib.Protocol.Numbers.Encode_SSH_String
                         (SSH_Lib.Protocol.Buffers.To_Array
                            (Modulus_Buffer))));
            end if;
         elsif Raw_Name = "ecdsa-sha2-nistp256"
           or else Raw_Name = "sk-ecdsa-sha2-nistp256@openssh.com"
         then
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Append
                (Host_Key_Data,
                 SSH_Lib.Protocol.Buffers.To_Array
                   (SSH_Lib.Protocol.Numbers.Encode_SSH_String
                      (SSH_Lib.Protocol.Buffers.To_Array (Exponent_Buffer))));
            if Status_Value = Ok then
               Status_Value :=
                 SSH_Lib.Protocol.Buffers.Append
                   (Host_Key_Data,
                    SSH_Lib.Protocol.Buffers.To_Array
                      (SSH_Lib.Protocol.Numbers.Encode_SSH_String
                         (SSH_Lib.Protocol.Buffers.To_Array (Key_Buffer))));
            end if;
            if Status_Value = Ok
              and then Raw_Name = "sk-ecdsa-sha2-nistp256@openssh.com"
            then
               Status_Value :=
                 SSH_Lib.Protocol.Buffers.Append
                   (Host_Key_Data,
                    SSH_Lib.Protocol.Buffers.To_Array
                      (SSH_Lib.Protocol.Numbers.Encode_SSH_String
                         (SSH_Lib.Protocol.Buffers.To_Array
                            (Modulus_Buffer))));
            end if;
         else
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Append
                (Host_Key_Data,
                 SSH_Lib.Protocol.Buffers.To_Array
                   (SSH_Lib.Protocol.Numbers.Encode_SSH_String
                      (SSH_Lib.Protocol.Buffers.To_Array (Exponent_Buffer))));
            if Status_Value = Ok then
               Status_Value :=
                 SSH_Lib.Protocol.Buffers.Append
                   (Host_Key_Data,
                    SSH_Lib.Protocol.Buffers.To_Array
                      (SSH_Lib.Protocol.Numbers.Encode_SSH_String
                         (SSH_Lib.Protocol.Buffers.To_Array
                            (Modulus_Buffer))));
            end if;
         end if;
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Set
             (Item.Host_Key_Blob,
              SSH_Lib.Protocol.Buffers.To_Array (Host_Key_Data));
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end;

      Item.Raw_Algorithm := To_Unbounded_String (Raw_Name);
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Parse_Certificate;

   function Parse_Host_Certificate
     (Certificate_Blob      : Stream_Element_Array;
      Certificate_Algorithm : String;
      Host_Key              : out SSH_Lib.Keys.Public_Key;
      Signature_Key         : out SSH_Lib.Keys.Public_Key) return Status
   is
      Parsed       : Parsed_Certificate;
      Status_Value : Status;
   begin
      SSH_Lib.Keys.Internal.Clear (Host_Key);
      SSH_Lib.Keys.Internal.Clear (Signature_Key);
      Status_Value :=
        Parse_Certificate (Certificate_Blob, Certificate_Algorithm, Parsed);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if Parsed.Certificate_Type /= Host_Certificate_Type then
         return Host_Key_Mismatch;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Parse
          (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Host_Key_Blob),
           To_String (Parsed.Raw_Algorithm),
           Host_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Parse
          (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Key_Blob),
           "ssh-ed25519",
           Signature_Key);
      if Status_Value = Ok then
         return Ok;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Parse
          (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Key_Blob),
           "ecdsa-sha2-nistp256",
           Signature_Key);
      if Status_Value = Ok then
         return Ok;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Parse
          (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Key_Blob),
           "rsa-sha2-512",
           Signature_Key);
      if Status_Value = Ok then
         return Ok;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Parse
          (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Key_Blob),
           "rsa-sha2-256",
           Signature_Key);
      if Status_Value = Ok then
         return Ok;
      end if;
      return
        SSH_Lib.Protocol.Host_Keys.Parse
          (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Key_Blob),
           "ssh-rsa",
           Signature_Key);
   exception
      when others =>
         SSH_Lib.Keys.Internal.Clear (Host_Key);
         SSH_Lib.Keys.Internal.Clear (Signature_Key);
         return Internal_Error;
   end Parse_Host_Certificate;

   function Host_Certificate_Signed_By_Public_Key
     (Certificate_Blob      : Stream_Element_Array;
      Certificate_Algorithm : String;
      Authority_Key_Blob    : Stream_Element_Array) return Status
   is
      Host_Key      : SSH_Lib.Keys.Public_Key;
      Signature_Key : SSH_Lib.Keys.Public_Key;
      Authority_Key : SSH_Lib.Keys.Public_Key;
      Status_Value  : Status;
   begin
      Status_Value :=
        Parse_Host_Certificate
          (Certificate_Blob, Certificate_Algorithm, Host_Key, Signature_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Parse
          (Authority_Key_Blob, "ssh-ed25519", Authority_Key);
      if Status_Value /= Ok then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (Authority_Key_Blob, "ecdsa-sha2-nistp256", Authority_Key);
      end if;
      if Status_Value /= Ok then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (Authority_Key_Blob, "rsa-sha2-512", Authority_Key);
      end if;
      if Status_Value /= Ok then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (Authority_Key_Blob, "rsa-sha2-256", Authority_Key);
      end if;
      if Status_Value /= Ok then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (Authority_Key_Blob, "ssh-rsa", Authority_Key);
      end if;
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if CryptoLib.Constant_Time.Equal
           (SSH_Lib.Keys.Internal.Raw_Blob (Authority_Key),
            SSH_Lib.Keys.Internal.Raw_Blob (Signature_Key))
      then
         return Ok;
      else
         return Host_Key_Mismatch;
      end if;
   exception
      when others =>
         return Internal_Error;
   end Host_Certificate_Signed_By_Public_Key;

   function Validate_Host_Certificate
     (Certificate_Blob      : Stream_Element_Array;
      Certificate_Algorithm : String;
      Host                  : String;
      Port                  : Natural;
      Authority_Key_Blob    : Stream_Element_Array) return Status
   is
      Parsed          : Parsed_Certificate;
      Host_Key        : SSH_Lib.Keys.Public_Key;
      Signature_Key   : SSH_Lib.Keys.Public_Key;
      Authority_Key   : SSH_Lib.Keys.Public_Key;
      Signature_Name  : Unbounded_String;
      Signature_Bytes : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value    : Status;
      Now_Seconds     : Interfaces.Unsigned_64;
   begin
      Status_Value :=
        Parse_Certificate (Certificate_Blob, Certificate_Algorithm, Parsed);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Parsed.Certificate_Type /= Host_Certificate_Type then
         return Host_Key_Mismatch;
      end if;

      Status_Value :=
        Validate_Host_Critical_Options
          (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Critical_Options));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Validate_Certificate_Option_Map
          (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Extensions));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if not SSH_String_List_Well_Formed
               (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Principals))
      then
         return Handshake_Failed;
      end if;
      if not Principal_Matches
               (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Principals),
                Host,
                Port)
      then
         return Host_Key_Mismatch;
      end if;
      if not Certificate_Validity_Window_Is_Canonical
               (Parsed.Valid_After, Parsed.Valid_Before)
      then
         return Host_Key_Mismatch;
      end if;

      Now_Seconds := Current_Unix_Time;
      if Parsed.Valid_After > Now_Seconds then
         return Host_Key_Mismatch;
      end if;
      if Parsed.Valid_Before /= Forever_Valid_Before
        and then Now_Seconds >= Parsed.Valid_Before
      then
         return Host_Key_Mismatch;
      end if;

      Status_Value :=
        Parse_Host_Certificate
          (Certificate_Blob, Certificate_Algorithm, Host_Key, Signature_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Parse
          (Authority_Key_Blob, "ssh-ed25519", Authority_Key);
      if Status_Value /= Ok then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (Authority_Key_Blob, "ecdsa-sha2-nistp256", Authority_Key);
      end if;
      if Status_Value /= Ok then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (Authority_Key_Blob, "rsa-sha2-512", Authority_Key);
      end if;
      if Status_Value /= Ok then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (Authority_Key_Blob, "rsa-sha2-256", Authority_Key);
      end if;
      if Status_Value /= Ok then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (Authority_Key_Blob, "ssh-rsa", Authority_Key);
      end if;
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if not CryptoLib.Constant_Time.Equal
               (SSH_Lib.Keys.Internal.Raw_Blob (Authority_Key),
                SSH_Lib.Keys.Internal.Raw_Blob (Signature_Key))
      then
         return Host_Key_Mismatch;
      end if;

      Status_Value :=
        Signature_Algorithm
          (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Blob),
           Signature_Name,
           Signature_Bytes);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if not Is_Supported_Certificate_Signature_Algorithm
               (To_String (Signature_Name))
      then
         SSH_Lib.Protocol.Buffers.Clear (Signature_Bytes);
         return Unsupported_Feature;
      end if;
      if not Certificate_Signature_Algorithm_Compatible
               (To_String (Signature_Name),
                SSH_Lib.Keys.Algorithm (Authority_Key))
      then
         SSH_Lib.Protocol.Buffers.Clear (Signature_Bytes);
         return Host_Key_Mismatch;
      end if;

      Status_Value :=
        SSH_Lib.Signatures.Verify
          (To_String (Signature_Name),
           SSH_Lib.Keys.Internal.Raw_Blob (Authority_Key),
           SSH_Lib.Protocol.Buffers.To_Array (Signature_Bytes),
           SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signed_Portion));
      SSH_Lib.Protocol.Buffers.Clear (Signature_Bytes);

      if Status_Value = Ok then
         return Ok;
      elsif Status_Value = Internal_Error then
         return Internal_Error;
      elsif Status_Value = Unsupported_Feature then
         return Unsupported_Feature;
      else
         --  A host certificate whose CA signature does not verify is a host
         --  trust mismatch, not an authentication failure and not a reason to
         --  continue with a weaker host-key interpretation.
         return Host_Key_Mismatch;
      end if;
   exception
      when others =>
         return Internal_Error;
   end Validate_Host_Certificate;

   function Validate_User_Certificate_For_Auth
     (Certificate_Blob : Stream_Element_Array; Certificate_Algorithm : String)
      return Status
   is
      Parsed             : Parsed_Certificate;
      Certificate_CA_Key : SSH_Lib.Keys.Public_Key;
      Certified_Key      : SSH_Lib.Keys.Public_Key;
      Status_Value       : Status;
      Raw_Name           : constant String :=
        Raw_Algorithm_For_Certificate (Certificate_Algorithm);
   begin
      Status_Value :=
        Parse_Certificate (Certificate_Blob, Certificate_Algorithm, Parsed);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Raw_Name'Length = 0 then
         return Unsupported_Feature;
      end if;
      if Parsed.Certificate_Type /= User_Certificate_Type then
         return Authentication_Failed;
      end if;

      if not SSH_String_List_Well_Formed
               (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Principals))
      then
         return Authentication_Failed;
      end if;

      --  Agent-supplied certificates are not paired with a local private-key
      --  object that can run Certificate_Matches_Signing_Key, so verify here
      --  that the certified public key itself has a supported, well-formed raw
      --  key shape before it is offered to the server.  The server still
      --  enforces authorization principals and CA policy; this check only
      --  prevents malformed certificate key material from entering userauth.
      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Parse
          (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Host_Key_Blob),
           Raw_Name,
           Certified_Key);
      if Status_Value /= Ok
        and then Raw_Name /= "ssh-ed25519"
        and then Raw_Name /= "ecdsa-sha2-nistp256"
        and then Raw_Name /= "sk-ssh-ed25519@openssh.com"
        and then Raw_Name /= "sk-ecdsa-sha2-nistp256@openssh.com"
      then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Host_Key_Blob),
              "ssh-rsa",
              Certified_Key);
      end if;
      if Status_Value = Internal_Error then
         return Internal_Error;
      elsif Status_Value /= Ok then
         return Authentication_Failed;
      end if;

      Status_Value :=
        Validate_User_Critical_Options
          (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Critical_Options));
      if Status_Value = Internal_Error then
         return Internal_Error;
      elsif Status_Value /= Ok then
         return Authentication_Failed;
      end if;
      Status_Value :=
        Validate_Certificate_Option_Map
          (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Extensions));
      if Status_Value = Internal_Error then
         return Internal_Error;
      elsif Status_Value /= Ok then
         return Authentication_Failed;
      end if;

      if not Certificate_Validity_Window_Is_Canonical
               (Parsed.Valid_After, Parsed.Valid_Before)
      then
         return Authentication_Failed;
      end if;

      declare
         Now_Seconds : constant Interfaces.Unsigned_64 := Current_Unix_Time;
      begin
         if Parsed.Valid_After > Now_Seconds then
            return Authentication_Failed;
         end if;
         if Parsed.Valid_Before /= Forever_Valid_Before
           and then Now_Seconds >= Parsed.Valid_Before
         then
            return Authentication_Failed;
         end if;
      end;

      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Parse
          (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Key_Blob),
           "ssh-ed25519",
           Certificate_CA_Key);
      if Status_Value /= Ok then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Key_Blob),
              "ecdsa-sha2-nistp256",
              Certificate_CA_Key);
      end if;
      if Status_Value /= Ok then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Key_Blob),
              "rsa-sha2-512",
              Certificate_CA_Key);
      end if;
      if Status_Value /= Ok then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Key_Blob),
              "rsa-sha2-256",
              Certificate_CA_Key);
      end if;
      if Status_Value /= Ok then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Key_Blob),
              "ssh-rsa",
              Certificate_CA_Key);
      end if;
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      declare
         Signature_Name  : Unbounded_String;
         Signature_Bytes : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      begin
         Status_Value :=
           Signature_Algorithm
             (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Blob),
              Signature_Name,
              Signature_Bytes);
         if Status_Value = Internal_Error then
            return Internal_Error;
         elsif Status_Value /= Ok then
            return Authentication_Failed;
         end if;
         if not Is_Supported_Certificate_Signature_Algorithm
                  (To_String (Signature_Name))
         then
            SSH_Lib.Protocol.Buffers.Clear (Signature_Bytes);
            return Authentication_Failed;
         end if;
         if not Certificate_Signature_Algorithm_Compatible
                  (To_String (Signature_Name),
                   SSH_Lib.Keys.Algorithm (Certificate_CA_Key))
         then
            SSH_Lib.Protocol.Buffers.Clear (Signature_Bytes);
            return Authentication_Failed;
         end if;

         Status_Value :=
           SSH_Lib.Signatures.Verify
             (To_String (Signature_Name),
              SSH_Lib.Keys.Internal.Raw_Blob (Certificate_CA_Key),
              SSH_Lib.Protocol.Buffers.To_Array (Signature_Bytes),
              SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signed_Portion));
         SSH_Lib.Protocol.Buffers.Clear (Signature_Bytes);
         if Status_Value /= Ok then
            return Authentication_Failed;
         end if;
      end;

      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Validate_User_Certificate_For_Auth;

   function Certificate_Matches_Signing_Key
     (Certificate_Blob      : Stream_Element_Array;
      Certificate_Algorithm : String;
      Signing_Key_Blob      : Stream_Element_Array) return Status
   is
      Parsed               : Parsed_Certificate;
      Certificate_Host_Key : SSH_Lib.Keys.Public_Key;
      Certificate_CA_Key   : SSH_Lib.Keys.Public_Key;
      Signing_Key          : SSH_Lib.Keys.Public_Key;
      Status_Value         : Status;
      Raw_Name             : constant String :=
        Raw_Algorithm_For_Certificate (Certificate_Algorithm);
   begin
      Status_Value :=
        Parse_Certificate (Certificate_Blob, Certificate_Algorithm, Parsed);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Raw_Name'Length = 0 then
         return Unsupported_Feature;
      end if;
      if Parsed.Certificate_Type /= User_Certificate_Type then
         return Authentication_Failed;
      end if;

      if not SSH_String_List_Well_Formed
               (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Principals))
      then
         return Authentication_Failed;
      end if;

      Status_Value :=
        Validate_User_Critical_Options
          (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Critical_Options));
      if Status_Value = Internal_Error then
         return Internal_Error;
      elsif Status_Value /= Ok then
         return Authentication_Failed;
      end if;
      Status_Value :=
        Validate_Certificate_Option_Map
          (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Extensions));
      if Status_Value = Internal_Error then
         return Internal_Error;
      elsif Status_Value /= Ok then
         return Authentication_Failed;
      end if;

      if not Certificate_Validity_Window_Is_Canonical
               (Parsed.Valid_After, Parsed.Valid_Before)
      then
         return Authentication_Failed;
      end if;

      declare
         Now_Seconds : constant Interfaces.Unsigned_64 := Current_Unix_Time;
      begin
         if Parsed.Valid_After > Now_Seconds then
            return Authentication_Failed;
         end if;
         if Parsed.Valid_Before /= Forever_Valid_Before
           and then Now_Seconds >= Parsed.Valid_Before
         then
            return Authentication_Failed;
         end if;
      end;

      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Parse
          (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Host_Key_Blob),
           Raw_Name,
           Certificate_Host_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Parse
          (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Key_Blob),
           "ssh-ed25519",
           Certificate_CA_Key);
      if Status_Value /= Ok then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Key_Blob),
              "ecdsa-sha2-nistp256",
              Certificate_CA_Key);
      end if;
      if Status_Value /= Ok then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Key_Blob),
              "rsa-sha2-512",
              Certificate_CA_Key);
      end if;
      if Status_Value /= Ok then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Key_Blob),
              "rsa-sha2-256",
              Certificate_CA_Key);
      end if;
      if Status_Value /= Ok then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Key_Blob),
              "ssh-rsa",
              Certificate_CA_Key);
      end if;
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      declare
         Signature_Name  : Unbounded_String;
         Signature_Bytes : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      begin
         Status_Value :=
           Signature_Algorithm
             (SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signature_Blob),
              Signature_Name,
              Signature_Bytes);
         if Status_Value = Internal_Error then
            return Internal_Error;
         elsif Status_Value /= Ok then
            return Authentication_Failed;
         end if;
         if not Is_Supported_Certificate_Signature_Algorithm
                  (To_String (Signature_Name))
         then
            SSH_Lib.Protocol.Buffers.Clear (Signature_Bytes);
            return Authentication_Failed;
         end if;
         if not Certificate_Signature_Algorithm_Compatible
                  (To_String (Signature_Name),
                   SSH_Lib.Keys.Algorithm (Certificate_CA_Key))
         then
            SSH_Lib.Protocol.Buffers.Clear (Signature_Bytes);
            return Authentication_Failed;
         end if;

         Status_Value :=
           SSH_Lib.Signatures.Verify
             (To_String (Signature_Name),
              SSH_Lib.Keys.Internal.Raw_Blob (Certificate_CA_Key),
              SSH_Lib.Protocol.Buffers.To_Array (Signature_Bytes),
              SSH_Lib.Protocol.Buffers.To_Array (Parsed.Signed_Portion));
         SSH_Lib.Protocol.Buffers.Clear (Signature_Bytes);
         if Status_Value /= Ok then
            return Authentication_Failed;
         end if;
      end;

      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Parse
          (Signing_Key_Blob, Raw_Name, Signing_Key);
      if Status_Value /= Ok
        and then Raw_Name /= "ssh-ed25519"
        and then Raw_Name /= "ecdsa-sha2-nistp256"
        and then Raw_Name /= "sk-ssh-ed25519@openssh.com"
        and then Raw_Name /= "sk-ecdsa-sha2-nistp256@openssh.com"
      then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Parse
             (Signing_Key_Blob, "ssh-rsa", Signing_Key);
      end if;
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if CryptoLib.Constant_Time.Equal
           (SSH_Lib.Keys.Internal.Raw_Blob (Certificate_Host_Key),
            SSH_Lib.Keys.Internal.Raw_Blob (Signing_Key))
      then
         return Ok;
      else
         return Authentication_Failed;
      end if;
   exception
      when others =>
         return Internal_Error;
   end Certificate_Matches_Signing_Key;

end SSH_Lib.Protocol.Certificates;
