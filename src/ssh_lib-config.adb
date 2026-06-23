with Ada.Characters.Handling;
with Ada.Containers;
with Ada.Directories; use Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Text_IO;
with SSH_Lib.Algorithms;
with SSH_Lib.Platform.Paths;

package body SSH_Lib.Config is

   use type Ada.Containers.Count_Type;
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;

   Max_Config_Line_Length : constant Positive := 16 * 1024;
   Max_Include_Depth      : constant Natural := 16;

   function Equal_Text (Left, Right : Stored_Text) return Boolean is
   begin
      return To_String (Left) = To_String (Right);
   end Equal_Text;

   function Equal_Directive
     (Left : Config_Directive; Right : Config_Directive) return Boolean is
   begin
      return
        Left.Kind = Right.Kind
        and then Equal_Text (Left.Value, Right.Value)
        and then Left.Status = Right.Status;
   end Equal_Directive;

   function Equal_Block (Left : Host_Block; Right : Host_Block) return Boolean
   is
   begin
      return
        Pattern_Vectors."=" (Left.Patterns, Right.Patterns)
        and then Directive_Vectors."=" (Left.Directives, Right.Directives);
   end Equal_Block;

   package Token_Vectors is new
     Ada.Containers.Vectors
       (Index_Type   => Natural,
        Element_Type => Unbounded_String);

   type Assignment_State is record
      Host_Set                                 : Boolean := False;
      User_Set                                 : Boolean := False;
      Port_Set                                 : Boolean := False;
      Identity_File_Set                        : Boolean := False;
      Certificate_File_Set                     : Boolean := False;
      User_Known_Hosts_File_Set                : Boolean := False;
      Global_Known_Hosts_File_Set              : Boolean := False;
      Host_Key_Alias_Set                       : Boolean := False;
      Revoked_Host_Keys_Set                    : Boolean := False;
      Identity_Agent_Set                       : Boolean := False;
      Preferred_Authentications_Set            : Boolean := False;
      Pubkey_Accepted_Algorithms_Set           : Boolean := False;
      Host_Key_Algorithms_Set                  : Boolean := False;
      Kex_Algorithms_Set                       : Boolean := False;
      Ciphers_Set                              : Boolean := False;
      Macs_Set                                 : Boolean := False;
      Compression_Set                          : Boolean := False;
      Canonicalize_Hostname_Set                : Boolean := False;
      Certificate_Authority_File_Set           : Boolean := False;
      Trusted_User_CA_Keys_Set                 : Boolean := False;
      Allowed_Cert_Critical_Options_Set        : Boolean := False;
      Reject_Unknown_Cert_Critical_Options_Set : Boolean := False;
      Identities_Only_Set                      : Boolean := False;
      Proxy_Jump_Set                           : Boolean := False;
      Proxy_Command_Set                        : Boolean := False;
      Control_Master_Set                       : Boolean := False;
      Control_Path_Set                         : Boolean := False;
      Control_Persist_Set                      : Boolean := False;
      Local_Forward_Set                        : Boolean := False;
      Remote_Forward_Set                       : Boolean := False;
      Dynamic_Forward_Set                      : Boolean := False;
      Send_Env_Set                             : Boolean := False;
      Set_Env_Set                              : Boolean := False;
   end record;

   function Is_Space (Value : Character) return Boolean is
   begin
      return Value = ' ' or else Value = Character'Val (9);
   end Is_Space;

   function Has_NUL_CR_LF (Value : String) return Boolean is
   begin
      for Ch of Value loop
         if Ch = Character'Val (0)
           or else Ch = Character'Val (10)
           or else Ch = Character'Val (13)
         then
            return True;
         end if;
      end loop;
      return False;
   end Has_NUL_CR_LF;

   function Is_None_Text (Value : String) return Boolean is
      Trimmed_Value : constant String :=
        Ada.Strings.Fixed.Trim (Value, Ada.Strings.Both);
   begin
      return Ada.Characters.Handling.To_Lower (Trimmed_Value) = "none";
   end Is_None_Text;

   function Starts_With_Ssh_Scheme (Value : String) return Boolean is
      Prefix      : constant String := "ssh://";
      Lower_Value : constant String :=
        Ada.Characters.Handling.To_Lower (Value);
   begin
      return
        Value'Length >= Prefix'Length
        and then
          Lower_Value
            (Lower_Value'First .. Lower_Value'First + Prefix'Length - 1)
          = Prefix;
   end Starts_With_Ssh_Scheme;

   function Control_Break_Is_In_Remote_Repository
     (Value : String) return Boolean is
   begin
      if not Has_NUL_CR_LF (Value) then
         return False;
      end if;

      if Starts_With_Ssh_Scheme (Value) then
         declare
            Prefix          : constant String := "ssh://";
            Remainder_First : constant Natural := Value'First + Prefix'Length;
            Slash_Position  : constant Natural :=
              Ada.Strings.Fixed.Index
                (Value (Remainder_First .. Value'Last), "/");
         begin
            if Slash_Position = 0 then
               return False;
            end if;

            for Index_Value in Slash_Position + 1 .. Value'Last loop
               if Value (Index_Value) = Character'Val (0)
                 or else Value (Index_Value) = Character'Val (10)
                 or else Value (Index_Value) = Character'Val (13)
               then
                  return True;
               end if;
            end loop;

            return False;
         end;
      else
         declare
            Colon_Position : constant Natural :=
              Ada.Strings.Fixed.Index (Value, ":");
         begin
            if Colon_Position = 0 or else Colon_Position = Value'Last then
               return False;
            end if;

            for Index_Value in Colon_Position + 1 .. Value'Last loop
               if Value (Index_Value) = Character'Val (0)
                 or else Value (Index_Value) = Character'Val (10)
                 or else Value (Index_Value) = Character'Val (13)
               then
                  return True;
               end if;
            end loop;

            return False;
         end;
      end if;
   exception
      when others =>
         return False;
   end Control_Break_Is_In_Remote_Repository;

   function Is_Valid_Name_Text (Value : String) return Boolean is
   begin
      if Value'Length = 0 or else Has_NUL_CR_LF (Value) then
         return False;
      end if;

      for Ch of Value loop
         if Character'Pos (Ch) < 32 or else Character'Pos (Ch) = 127 then
            return False;
         end if;
      end loop;

      return True;
   end Is_Valid_Name_Text;

   function Is_Valid_Keyword (Value : String) return Boolean is
   begin
      if Value'Length = 0 then
         return False;
      end if;

      for Ch of Value loop
         if not (Ch in 'A' .. 'Z' or else Ch in 'a' .. 'z') then
            return False;
         end if;
      end loop;

      return True;
   end Is_Valid_Keyword;

   function Is_Valid_Host_Text (Value : String) return Boolean is
   begin
      return Is_Valid_Name_Text (Value);
   end Is_Valid_Host_Text;

   function Is_Valid_User_Text (Value : String) return Boolean is
   begin
      if not Is_Valid_Name_Text (Value) then
         return False;
      end if;

      for Ch of Value loop
         if Ch = ':' then
            return False;
         end if;
      end loop;

      return True;
   end Is_Valid_User_Text;

   function Parse_Port_Status
     (Value : String; Port_Value : out Natural) return CryptoLib.Errors.Status
   is
      Accumulator : Natural := 0;
   begin
      Port_Value := 0;
      if Value'Length = 0 then
         return CryptoLib.Errors.Invalid_Port;
      end if;

      for Ch of Value loop
         if Ch not in '0' .. '9' then
            return CryptoLib.Errors.Invalid_Port;
         end if;

         Accumulator :=
           Accumulator * 10 + (Character'Pos (Ch) - Character'Pos ('0'));
         if Accumulator > 65_535 then
            return CryptoLib.Errors.Invalid_Port;
         end if;
      end loop;

      if Accumulator = 0 then
         return CryptoLib.Errors.Invalid_Port;
      end if;

      Port_Value := Accumulator;
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Port_Value := 0;
         return CryptoLib.Errors.Invalid_Port;
   end Parse_Port_Status;

   function Boolean_Value (Value : String; Item : out Boolean) return Boolean
   is
      Lower : constant String := Ada.Characters.Handling.To_Lower (Value);
   begin
      if Lower = "yes"
        or else Lower = "true"
        or else Lower = "on"
        or else Lower = "1"
      then
         Item := True;
         return True;
      elsif Lower = "no"
        or else Lower = "false"
        or else Lower = "off"
        or else Lower = "0"
      then
         Item := False;
         return True;
      else
         Item := False;
         return False;
      end if;
   end Boolean_Value;

   function Canonicalize_Hostname_Value
     (Value : String; Item : out Boolean) return Boolean
   is
      Lower : constant String := Ada.Characters.Handling.To_Lower (Value);
   begin
      --  OpenSSH accepts CanonicalizeHostname yes/no/always.  The Session
      --  options currently expose this as a Boolean transport-policy flag, so
      --  "always" is represented as True rather than being rejected or silently
      --  ignored.  Richer canonicalization policy knobs can be layered onto the
      --  options record later without making this parser incompatible.
      if Lower = "always" then
         Item := True;
         return True;
      else
         return Boolean_Value (Value, Item);
      end if;
   end Canonicalize_Hostname_Value;

   function Is_Valid_Config_Name_List (Value : String) return Boolean is
   begin
      return SSH_Lib.Algorithms.Validate_Name_List (Value);
   exception
      when others =>
         return False;
   end Is_Valid_Config_Name_List;

   function Is_Valid_OpenSSH_Algorithm_List (Value : String) return Boolean is
   begin
      --  OpenSSH algorithm preference directives accept either a complete
      --  comma-separated name-list or one of the list modifiers below.  The
      --  modifier is not part of the SSH name-list grammar; validate only the
      --  payload after the modifier and reject empty payloads.
      if Value'Length = 0 then
         return False;
      elsif (Value (Value'First) = '+'
             or else Value (Value'First) = '-'
             or else Value (Value'First) = '^')
        and then Value'Length > 1
      then
         return
           SSH_Lib.Algorithms.Validate_Name_List
             (Value (Value'First + 1 .. Value'Last));
      elsif Value (Value'First) = '+'
        or else Value (Value'First) = '-'
        or else Value (Value'First) = '^'
      then
         return False;
      else
         return SSH_Lib.Algorithms.Validate_Name_List (Value);
      end if;
   exception
      when others =>
         return False;
   end Is_Valid_OpenSSH_Algorithm_List;

   function Is_Valid_Auth_List (Value : String) return Boolean is
      Start_Index : Positive := Value'First;
      Stop_Index  : Natural;
      Candidate   : Unbounded_String;
   begin
      if Value'Length = 0 then
         return False;
      end if;

      loop
         Stop_Index := Start_Index;
         while Stop_Index <= Value'Last and then Value (Stop_Index) /= ',' loop
            Stop_Index := Stop_Index + 1;
         end loop;

         if Stop_Index = Start_Index then
            return False;
         end if;

         Candidate :=
           To_Unbounded_String
             (Ada.Characters.Handling.To_Lower
                (Value (Start_Index .. Stop_Index - 1)));
         if To_String (Candidate) /= "publickey"
           and then To_String (Candidate) /= "password"
           and then To_String (Candidate) /= "none"
           and then To_String (Candidate) /= "keyboard-interactive"
         then
            return False;
         end if;

         exit when Stop_Index > Value'Last;
         Start_Index := Stop_Index + 1;
      end loop;
      return True;
   exception
      when others =>
         return False;
   end Is_Valid_Auth_List;

   function Tokenize
     (Line_Text : String; Tokens : out Token_Vectors.Vector) return Boolean
   is
      Index_Value : Positive := Line_Text'First;
      In_Quote    : Boolean := False;
      Quote_Char  : Character := Character'Val (0);
      Current     : Unbounded_String := Null_Unbounded_String;
      Have_Token  : Boolean := False;
   begin
      Tokens.Clear;

      for Ch of Line_Text loop
         if Ch = Character'Val (0) then
            return False;
         elsif Ch /= Character'Val (9) and then Character'Pos (Ch) < 32 then
            return False;
         end if;
      end loop;

      while Index_Value <= Line_Text'Last loop
         declare
            Ch : constant Character := Line_Text (Index_Value);
         begin
            if In_Quote then
               if Ch = Quote_Char then
                  In_Quote := False;
               else
                  Append (Current, Ch);
                  Have_Token := True;
               end if;
            elsif Is_Space (Ch) then
               if Have_Token then
                  Tokens.Append (Current);
                  Current := Null_Unbounded_String;
                  Have_Token := False;
               end if;
            elsif Ch = '#' then
               exit;
            elsif Ch = Character'Val (39) or else Ch = '"' then
               In_Quote := True;
               Quote_Char := Ch;
               Have_Token := True;
            else
               Append (Current, Ch);
               Have_Token := True;
            end if;
         end;
         Index_Value := Index_Value + 1;
      end loop;

      if In_Quote then
         return False;
      end if;

      if Have_Token then
         Tokens.Append (Current);
      end if;

      return True;
   end Tokenize;

   function Join_Tokens
     (Tokens      : Token_Vectors.Vector;
      First_Index : Natural;
      Separator   : Character) return String
   is
      Result : Unbounded_String := Null_Unbounded_String;
   begin
      if Tokens.Is_Empty or else First_Index > Natural (Tokens.Last_Index) then
         return "";
      end if;

      for Token_Index in First_Index .. Natural (Tokens.Last_Index) loop
         if Token_Index > First_Index then
            Append (Result, Separator);
         end if;
         Append (Result, To_String (Tokens.Element (Token_Index)));
      end loop;

      return To_String (Result);
   exception
      when others =>
         return "";
   end Join_Tokens;

   function Rest_After_First_Token (Line_Text : String) return String is
      Index_Value : Natural := Line_Text'First;
   begin
      while Index_Value <= Line_Text'Last
        and then Is_Space (Line_Text (Index_Value))
      loop
         Index_Value := Index_Value + 1;
      end loop;

      while Index_Value <= Line_Text'Last
        and then not Is_Space (Line_Text (Index_Value))
      loop
         Index_Value := Index_Value + 1;
      end loop;

      while Index_Value <= Line_Text'Last
        and then Is_Space (Line_Text (Index_Value))
      loop
         Index_Value := Index_Value + 1;
      end loop;

      if Index_Value > Line_Text'Last then
         return "";
      else
         return Line_Text (Index_Value .. Line_Text'Last);
      end if;
   exception
      when others =>
         return "";
   end Rest_After_First_Token;

   function Strip_Trailing_Comment (Value : String) return String is
      In_Quote   : Boolean := False;
      Quote_Char : Character := Character'Val (0);
      Last_Index : Natural := Value'Last;
   begin
      for Index_Value in Value'Range loop
         declare
            Ch : constant Character := Value (Index_Value);
         begin
            if In_Quote then
               if Ch = Quote_Char then
                  In_Quote := False;
               end if;
            elsif Ch = Character'Val (39) or else Ch = '"' then
               In_Quote := True;
               Quote_Char := Ch;
            elsif Ch = '#' then
               if Index_Value = Value'First
                 or else Is_Space (Value (Index_Value - 1))
               then
                  Last_Index := Index_Value - 1;
                  exit;
               end if;
            end if;
         end;
      end loop;

      while Last_Index >= Value'First and then Is_Space (Value (Last_Index))
      loop
         Last_Index := Last_Index - 1;
      end loop;

      if Last_Index < Value'First then
         return "";
      else
         return Value (Value'First .. Last_Index);
      end if;
   exception
      when others =>
         return Value;
   end Strip_Trailing_Comment;

   function Make_Directive
     (Kind : Directive_Kind; Value : String) return Config_Directive
   is
      Item         : Config_Directive;
      Port_Ignored : Natural;
      Bool_Ignored : Boolean;
   begin
      Item.Kind := Kind;
      Item.Value := To_Unbounded_String (Value);
      Item.Status := CryptoLib.Errors.Ok;

      case Kind is
         when Host_Name_Directive                            =>
            if not Is_Valid_Host_Text (Value) then
               Item.Status := CryptoLib.Errors.Invalid_Host;
            end if;

         when User_Directive                                 =>
            if not Is_Valid_User_Text (Value) then
               Item.Status := CryptoLib.Errors.Invalid_User;
            end if;

         when Port_Directive                                 =>
            Item.Status := Parse_Port_Status (Value, Port_Ignored);

         when Identity_File_Directive                        =>
            if not Is_Valid_Name_Text (Value) then
               Item.Status := CryptoLib.Errors.Internal_Error;
            end if;

         when Certificate_File_Directive                     =>
            if not Is_Valid_Name_Text (Value) then
               Item.Status := CryptoLib.Errors.Internal_Error;
            end if;

         when User_Known_Hosts_File_Directive
            | Global_Known_Hosts_File_Directive
            | Revoked_Host_Keys_Directive
            | Identity_Agent_Directive
            | Certificate_Authority_File_Directive
            | Trusted_User_CA_Keys_Directive                 =>
            if not Is_Valid_Name_Text (Value) then
               Item.Status := CryptoLib.Errors.Internal_Error;
            end if;

         when Host_Key_Alias_Directive                       =>
            if not Is_Valid_Host_Text (Value) then
               Item.Status := CryptoLib.Errors.Invalid_Host;
            end if;

         when Preferred_Authentications_Directive            =>
            if not Is_Valid_Auth_List (Value) then
               Item.Status := CryptoLib.Errors.Unsupported_Feature;
            end if;

         when Pubkey_Accepted_Algorithms_Directive
            | Host_Key_Algorithms_Directive
            | Kex_Algorithms_Directive
            | Ciphers_Directive
            | Macs_Directive                                 =>
            if not Is_Valid_OpenSSH_Algorithm_List (Value) then
               Item.Status := CryptoLib.Errors.Unsupported_Feature;
            end if;

         when Allowed_Cert_Critical_Options_Directive        =>
            if not Is_Valid_Config_Name_List (Value) then
               Item.Status := CryptoLib.Errors.Unsupported_Feature;
            end if;

         when Compression_Directive                          =>
            declare
               Lower_Value : constant String :=
                 Ada.Characters.Handling.To_Lower (Value);
            begin
               if Lower_Value /= "yes"
                 and then Lower_Value /= "no"
                 and then not Is_Valid_OpenSSH_Algorithm_List (Value)
               then
                  Item.Status := CryptoLib.Errors.Unsupported_Feature;
               end if;
            end;

         when Canonicalize_Hostname_Directive                =>
            if not Canonicalize_Hostname_Value (Value, Bool_Ignored) then
               Item.Status := CryptoLib.Errors.Internal_Error;
            end if;

         when Reject_Unknown_Cert_Critical_Options_Directive =>
            if not Boolean_Value (Value, Bool_Ignored) then
               Item.Status := CryptoLib.Errors.Internal_Error;
            end if;

         when Identities_Only_Directive                      =>
            if not Boolean_Value (Value, Bool_Ignored) then
               Item.Status := CryptoLib.Errors.Internal_Error;
            end if;

         when Proxy_Jump_Directive                           =>
            if not Is_Valid_Name_Text (Value) then
               Item.Status := CryptoLib.Errors.Invalid_Host;
            end if;

         when Proxy_Command_Directive                        =>
            if not Is_Valid_Name_Text (Value) then
               Item.Status := CryptoLib.Errors.Unsupported_Feature;
            else
               Item.Status := CryptoLib.Errors.Unsupported_Feature;
            end if;

         when Control_Master_Directive                       =>
            declare
               Lower_Value : constant String :=
                 Ada.Characters.Handling.To_Lower (Value);
            begin
               if Lower_Value /= "yes"
                 and then Lower_Value /= "no"
                 and then Lower_Value /= "auto"
                 and then Lower_Value /= "ask"
                 and then Lower_Value /= "autoask"
               then
                  Item.Status := CryptoLib.Errors.Invalid_Command;
               end if;
            end;

         when Control_Path_Directive
            | Control_Persist_Directive                      =>
            if not Is_Valid_Name_Text (Value) then
               Item.Status := CryptoLib.Errors.Invalid_Command;
            end if;

         when Local_Forward_Directive
            | Remote_Forward_Directive
            | Dynamic_Forward_Directive
            | Send_Env_Directive
            | Set_Env_Directive                              =>
            if not Is_Valid_Name_Text (Value) then
               Item.Status := CryptoLib.Errors.Invalid_Command;
            end if;
      end case;

      return Item;
   end Make_Directive;

   procedure Start_Inactive_Block
     (Config : in out Host_Config; Current_Block : in out Natural)
   is
      Block_Item : Host_Block;
   begin
      Config.Blocks.Append (Block_Item);
      Current_Block := Config.Blocks.Last_Index;
   end Start_Inactive_Block;

   procedure Add_Directive
     (Config        : in out Host_Config;
      Current_Block : Natural;
      Item          : Config_Directive) is
   begin
      if Current_Block = Natural'Last then
         Config.Globals.Append (Item);
      else
         declare
            Block_Item : Host_Block := Config.Blocks.Element (Current_Block);
         begin
            Block_Item.Directives.Append (Item);
            Config.Blocks.Replace_Element (Current_Block, Block_Item);
         end;
      end if;
   end Add_Directive;

   procedure Parse_Line
     (Config        : in out Host_Config;
      Current_Block : in out Natural;
      Line_Text     : String)
   is
      Tokens        : Token_Vectors.Vector;
      Lower_Keyword : Unbounded_String;
   begin
      if not Tokenize (Line_Text, Tokens) or else Tokens.Is_Empty then
         return;
      end if;

      if not Is_Valid_Keyword (To_String (Tokens.Element (0))) then
         return;
      end if;

      Lower_Keyword :=
        To_Unbounded_String
          (Ada.Characters.Handling.To_Lower (To_String (Tokens.Element (0))));

      if To_String (Lower_Keyword) = "host" then
         if Tokens.Length <= 1 then
            Start_Inactive_Block (Config, Current_Block);
            return;
         end if;

         declare
            Block_Item : Host_Block;
         begin
            for Token_Index in 1 .. Natural (Tokens.Length) - 1 loop
               declare
                  Pattern_Text : constant String :=
                    To_String (Tokens.Element (Token_Index));
               begin
                  if Is_Valid_Name_Text (Pattern_Text) then
                     Block_Item.Patterns.Append
                       (To_Unbounded_String (Pattern_Text));
                  end if;
               end;
            end loop;

            if not Block_Item.Patterns.Is_Empty then
               Config.Blocks.Append (Block_Item);
               Current_Block := Config.Blocks.Last_Index;
            else
               Start_Inactive_Block (Config, Current_Block);
            end if;
         end;
      elsif To_String (Lower_Keyword) = "match" then
         --  Safe subset of OpenSSH Match support.  Match all behaves like
         --  Host *, and Match host <patterns...> reuses the existing Host
         --  pattern machinery.  Other predicates depend on runtime context
         --  not represented by Version's SSH transport options, so they are
         --  ignored as inactive blocks rather than guessed.
         if Tokens.Length >= 2
           and then
             Ada.Characters.Handling.To_Lower (To_String (Tokens.Element (1)))
             = "all"
         then
            declare
               Block_Item : Host_Block;
            begin
               Block_Item.Patterns.Append (To_Unbounded_String ("*"));
               Config.Blocks.Append (Block_Item);
               Current_Block := Config.Blocks.Last_Index;
            end;
         elsif Tokens.Length >= 3
           and then
             (Ada.Characters.Handling.To_Lower (To_String (Tokens.Element (1)))
              = "host"
              or else
                Ada.Characters.Handling.To_Lower
                  (To_String (Tokens.Element (1)))
                = "originalhost")
         then
            --  OpenSSH supports both "Match host" and "Match originalhost".
            --  The resolver currently receives the original lookup name as its
            --  only host selector, so both predicates are represented by the
            --  same pattern machinery.  This is safer than treating
            --  originalhost as unsupported/inactive and silently dropping
            --  user policy intended for the exact remote name.
            declare
               Block_Item : Host_Block;
            begin
               for Token_Index in 2 .. Natural (Tokens.Length) - 1 loop
                  declare
                     Pattern_Text : constant String :=
                       To_String (Tokens.Element (Token_Index));
                  begin
                     if Is_Valid_Name_Text (Pattern_Text) then
                        Block_Item.Patterns.Append
                          (To_Unbounded_String (Pattern_Text));
                     end if;
                  end;
               end loop;
               if not Block_Item.Patterns.Is_Empty then
                  Config.Blocks.Append (Block_Item);
                  Current_Block := Config.Blocks.Last_Index;
               else
                  Start_Inactive_Block (Config, Current_Block);
               end if;
            end;
         else
            Start_Inactive_Block (Config, Current_Block);
         end if;
      elsif To_String (Lower_Keyword) = "proxycommand" then
         --  Preserve the literal command tail as data.  Sessions.Open expands
         --  OpenSSH-style percent tokens and executes it only at the explicit
         --  ProxyCommand transport boundary; config load/resolve never shells
         --  out.  Tokenizing here would discard spaces and shell-like
         --  metacharacters and change the caller's configured command.
         Add_Directive
           (Config,
            Current_Block,
            Make_Directive
              (Proxy_Command_Directive,
               Strip_Trailing_Comment (Rest_After_First_Token (Line_Text))));
      elsif To_String (Lower_Keyword) = "controlmaster" then
         Add_Directive
           (Config,
            Current_Block,
            Make_Directive
              (Control_Master_Directive,
               Strip_Trailing_Comment (Rest_After_First_Token (Line_Text))));
      elsif To_String (Lower_Keyword) = "controlpath" then
         Add_Directive
           (Config,
            Current_Block,
            Make_Directive
              (Control_Path_Directive,
               Strip_Trailing_Comment (Rest_After_First_Token (Line_Text))));
      elsif To_String (Lower_Keyword) = "controlpersist" then
         Add_Directive
           (Config,
            Current_Block,
            Make_Directive
              (Control_Persist_Directive,
               Strip_Trailing_Comment (Rest_After_First_Token (Line_Text))));
      elsif To_String (Lower_Keyword) = "localforward" then
         --  Preserve OpenSSH forwarding directive tails as data.  The config
         --  resolver never binds sockets or opens channels; callers may feed
         --  these values into SSH_Lib.Forwarding explicitly.
         Add_Directive
           (Config,
            Current_Block,
            Make_Directive
              (Local_Forward_Directive,
               Strip_Trailing_Comment (Rest_After_First_Token (Line_Text))));
      elsif To_String (Lower_Keyword) = "remoteforward" then
         Add_Directive
           (Config,
            Current_Block,
            Make_Directive
              (Remote_Forward_Directive,
               Strip_Trailing_Comment (Rest_After_First_Token (Line_Text))));
      elsif To_String (Lower_Keyword) = "dynamicforward" then
         Add_Directive
           (Config,
            Current_Block,
            Make_Directive
              (Dynamic_Forward_Directive,
               Strip_Trailing_Comment (Rest_After_First_Token (Line_Text))));
      elsif To_String (Lower_Keyword) = "sendenv" then
         Add_Directive
           (Config,
            Current_Block,
            Make_Directive
              (Send_Env_Directive,
               Strip_Trailing_Comment (Rest_After_First_Token (Line_Text))));
      elsif To_String (Lower_Keyword) = "setenv" then
         Add_Directive
           (Config,
            Current_Block,
            Make_Directive
              (Set_Env_Directive,
               Strip_Trailing_Comment (Rest_After_First_Token (Line_Text))));
      elsif Tokens.Length >= 2
        and then To_String (Lower_Keyword) = "userknownhostsfile"
      then
         --  OpenSSH permits UserKnownHostsFile to name a whitespace-separated
         --  list of files.  Store the parsed token list as a comma-separated
         --  internal path list; each path remains data-only and is expanded
         --  independently during resolution.
         Add_Directive
           (Config,
            Current_Block,
            Make_Directive
              (User_Known_Hosts_File_Directive, Join_Tokens (Tokens, 1, ',')));
      elsif Tokens.Length >= 2
        and then To_String (Lower_Keyword) = "globalknownhostsfile"
      then
         --  Keep GlobalKnownHostsFile list handling aligned with
         --  UserKnownHostsFile.  Missing entries are handled by the existing
         --  known-hosts verifier as non-fatal unknown sources.
         Add_Directive
           (Config,
            Current_Block,
            Make_Directive
              (Global_Known_Hosts_File_Directive,
               Join_Tokens (Tokens, 1, ',')));
      elsif Tokens.Length >= 2
        and then To_String (Lower_Keyword) = "revokedhostkeys"
      then
         --  OpenSSH permits RevokedHostKeys to name policy data files.  Accept
         --  a whitespace-separated list in the same internal comma-list form
         --  used for known-host path lists.  Each element remains data-only;
         --  KRL magic and @revoked fail-closed checks are applied per element
         --  by the host-trust path.
         Add_Directive
           (Config,
            Current_Block,
            Make_Directive
              (Revoked_Host_Keys_Directive, Join_Tokens (Tokens, 1, ',')));
      elsif Tokens.Length >= 2
        and then To_String (Lower_Keyword) = "certificateauthorityfile"
      then
         --  Treat CertificateAuthorityFile as a deterministic path list so
         --  deployments can split host CA trust anchors across files without
         --  relying on shell expansion or subprocess helpers.
         Add_Directive
           (Config,
            Current_Block,
            Make_Directive
              (Certificate_Authority_File_Directive,
               Join_Tokens (Tokens, 1, ',')));
      elsif Tokens.Length >= 2
        and then To_String (Lower_Keyword) = "trustedusercakeys"
      then
         --  Preserve TrustedUserCAKeys as a safe data-only path list for user
         --  certificate policy plumbing.  The core library does not execute or
         --  interpret paths beyond independent leading-tilde expansion.
         Add_Directive
           (Config,
            Current_Block,
            Make_Directive
              (Trusted_User_CA_Keys_Directive, Join_Tokens (Tokens, 1, ',')));
      elsif Tokens.Length = 2 then
         declare
            Value_Text : constant String := To_String (Tokens.Element (1));
         begin
            if To_String (Lower_Keyword) = "hostname" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive (Host_Name_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "user" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive (User_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "port" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive (Port_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "identityfile" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive (Identity_File_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "certificatefile" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive (Certificate_File_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "userknownhostsfile" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive
                    (User_Known_Hosts_File_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "globalknownhostsfile" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive
                    (Global_Known_Hosts_File_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "hostkeyalias" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive (Host_Key_Alias_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "revokedhostkeys" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive (Revoked_Host_Keys_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "identityagent" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive (Identity_Agent_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "preferredauthentications" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive
                    (Preferred_Authentications_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "pubkeyacceptedalgorithms"
              or else To_String (Lower_Keyword) = "pubkeyacceptedkeytypes"
            then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive
                    (Pubkey_Accepted_Algorithms_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "hostkeyalgorithms" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive (Host_Key_Algorithms_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "kexalgorithms" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive (Kex_Algorithms_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "ciphers" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive (Ciphers_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "macs" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive (Macs_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "compression" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive (Compression_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "canonicalizehostname" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive
                    (Canonicalize_Hostname_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "certificateauthorityfile" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive
                    (Certificate_Authority_File_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "trustedusercakeys" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive (Trusted_User_CA_Keys_Directive, Value_Text));
            elsif To_String (Lower_Keyword)
              = "allowedcertificatecriticaloptions"
            then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive
                    (Allowed_Cert_Critical_Options_Directive, Value_Text));
            elsif To_String (Lower_Keyword)
              = "rejectunknowncertificatecriticaloptions"
            then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive
                    (Reject_Unknown_Cert_Critical_Options_Directive,
                     Value_Text));
            elsif To_String (Lower_Keyword) = "identitiesonly" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive (Identities_Only_Directive, Value_Text));
            elsif To_String (Lower_Keyword) = "proxyjump" then
               Add_Directive
                 (Config,
                  Current_Block,
                  Make_Directive (Proxy_Jump_Directive, Value_Text));
            end if;
         end;
      end if;
   exception
      when others =>
         null;
   end Parse_Line;

   function Load_File_With_Depth
     (Path               : String;
      Missing_Path_Is_Ok : Boolean;
      Item               : out Host_Config;
      Include_Depth      : Natural) return CryptoLib.Errors.Status;

   procedure Merge_Config (Target : in out Host_Config; Source : Host_Config)
   is
   begin
      for Directive_Item of Source.Globals loop
         Target.Globals.Append (Directive_Item);
      end loop;
      for Block_Item of Source.Blocks loop
         Target.Blocks.Append (Block_Item);
      end loop;
   end Merge_Config;

   function Resolve_Include_Path
     (Base_Path : String; Include_Text : String) return String is
   begin
      if Include_Text'Length = 0 then
         return "";
      elsif Include_Text (Include_Text'First) = '~' then
         return SSH_Lib.Platform.Paths.Expand_Leading_Tilde (Include_Text);
      elsif Include_Text (Include_Text'First) = '/' then
         return Include_Text;
      else
         declare
            Directory_Text : constant String :=
              Ada.Directories.Containing_Directory (Base_Path);
         begin
            if Directory_Text'Length = 0 then
               return Include_Text;
            else
               return Directory_Text & "/" & Include_Text;
            end if;
         end;
      end if;
   exception
      when others =>
         return "";
   end Resolve_Include_Path;

   function Contains_Include_Glob (Path_Text : String) return Boolean is
   begin
      for Char of Path_Text loop
         if Char = '*' or else Char = '?' or else Char = '[' then
            return True;
         end if;
      end loop;

      return False;
   end Contains_Include_Glob;

   procedure Sort_Text_Vector (Items : in out Token_Vectors.Vector) is
   begin
      if Items.Length < 2 then
         return;
      end if;

      for Left_Index in 0 .. Natural (Items.Length) - 2 loop
         for Right_Index in Left_Index + 1 .. Natural (Items.Length) - 1 loop
            if To_String (Items.Element (Right_Index))
              < To_String (Items.Element (Left_Index))
            then
               declare
                  Left_Item  : constant Unbounded_String :=
                    Items.Element (Left_Index);
                  Right_Item : constant Unbounded_String :=
                    Items.Element (Right_Index);
               begin
                  Items.Replace_Element (Left_Index, Right_Item);
                  Items.Replace_Element (Right_Index, Left_Item);
               end;
            end if;
         end loop;
      end loop;
   end Sort_Text_Vector;

   procedure Load_Include_File
     (Path_Text : String; Target : in out Host_Config; Include_Depth : Natural)
   is
      Included_Config : Host_Config;
      Status_Value    : CryptoLib.Errors.Status;
   begin
      if Path_Text'Length > 0
        and then Ada.Directories.Exists (Path_Text)
        and then
          Ada.Directories.Kind (Path_Text) = Ada.Directories.Ordinary_File
      then
         if Include_Depth >= Max_Include_Depth then
            return;
         end if;

         Status_Value :=
           Load_File_With_Depth
             (Path_Text, True, Included_Config, Include_Depth + 1);
         if Status_Value = CryptoLib.Errors.Ok then
            Merge_Config (Target, Included_Config);
         end if;
      end if;
   exception
      when others =>
         null;
   end Load_Include_File;

   procedure Load_Include_Glob
     (Path_Text : String; Target : in out Host_Config; Include_Depth : Natural)
   is
      Directory_Text : constant String :=
        Ada.Directories.Containing_Directory (Path_Text);
      Pattern_Text   : constant String :=
        Ada.Directories.Simple_Name (Path_Text);
      Search_Item    : Ada.Directories.Search_Type;
      Entry_Item     : Ada.Directories.Directory_Entry_Type;
      Matches        : Token_Vectors.Vector;
      Search_Open    : Boolean := False;
   begin
      if Directory_Text'Length = 0
        or else Pattern_Text'Length = 0
        or else not Ada.Directories.Exists (Directory_Text)
        or else
          Ada.Directories.Kind (Directory_Text) /= Ada.Directories.Directory
      then
         return;
      end if;

      Ada.Directories.Start_Search
        (Search    => Search_Item,
         Directory => Directory_Text,
         Pattern   => Pattern_Text,
         Filter    =>
           [Ada.Directories.Ordinary_File => True, others => False]);

      Search_Open := True;

      while Ada.Directories.More_Entries (Search_Item) loop
         Ada.Directories.Get_Next_Entry (Search_Item, Entry_Item);
         Matches.Append
           (To_Unbounded_String (Ada.Directories.Full_Name (Entry_Item)));
      end loop;

      Ada.Directories.End_Search (Search_Item);
      Search_Open := False;
      Sort_Text_Vector (Matches);

      for Match_Item of Matches loop
         Load_Include_File (To_String (Match_Item), Target, Include_Depth);
      end loop;
   exception
      when others =>
         if Search_Open then
            begin
               Ada.Directories.End_Search (Search_Item);
            exception
               when others =>
                  null;
            end;
         end if;
   end Load_Include_Glob;

   function Try_Parse_Include
     (Line_Text     : String;
      Base_Path     : String;
      Target        : in out Host_Config;
      Include_Depth : Natural) return Boolean
   is
      Tokens : Token_Vectors.Vector;
   begin
      if not Tokenize (Line_Text, Tokens) or else Tokens.Is_Empty then
         return False;
      end if;

      if Ada.Characters.Handling.To_Lower (To_String (Tokens.Element (0)))
        /= "include"
      then
         return False;
      end if;

      for Token_Index in 1 .. Natural (Tokens.Length) - 1 loop
         declare
            Include_Path : constant String :=
              Resolve_Include_Path
                (Base_Path, To_String (Tokens.Element (Token_Index)));
         begin
            if Include_Depth >= Max_Include_Depth then
               null;
            elsif Contains_Include_Glob (Include_Path) then
               Load_Include_Glob (Include_Path, Target, Include_Depth);
            else
               Load_Include_File (Include_Path, Target, Include_Depth);
            end if;
         end;
      end loop;

      return True;
   exception
      when others =>
         return True;
   end Try_Parse_Include;

   procedure Discard_Rest_Of_Line (Input_File : in out Ada.Text_IO.File_Type)
   is
      Buffer : String (1 .. 1024);
      Last   : Natural;
   begin
      while not Ada.Text_IO.End_Of_Line (Input_File)
        and then not Ada.Text_IO.End_Of_File (Input_File)
      loop
         Ada.Text_IO.Get_Line (Input_File, Buffer, Last);
         exit when Last < Buffer'Last;
      end loop;
   exception
      when others =>
         null;
   end Discard_Rest_Of_Line;

   function Load_File_With_Depth
     (Path               : String;
      Missing_Path_Is_Ok : Boolean;
      Item               : out Host_Config;
      Include_Depth      : Natural) return CryptoLib.Errors.Status
   is
      Input_File    : Ada.Text_IO.File_Type;
      Line_Buffer   : String (1 .. Max_Config_Line_Length);
      Last          : Natural;
      Current_Block : Natural := Natural'Last;
   begin
      Item := (Loaded => True, Globals => <>, Blocks => <>);

      if Path'Length = 0 then
         return CryptoLib.Errors.Internal_Error;
      end if;

      if Include_Depth > Max_Include_Depth then
         return CryptoLib.Errors.Internal_Error;
      end if;

      if not Ada.Directories.Exists (Path) then
         if Missing_Path_Is_Ok then
            return CryptoLib.Errors.Ok;
         else
            return CryptoLib.Errors.Internal_Error;
         end if;
      end if;

      Ada.Text_IO.Open (Input_File, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (Input_File) loop
         Ada.Text_IO.Get_Line (Input_File, Line_Buffer, Last);
         if Last = Line_Buffer'Last
           and then not Ada.Text_IO.End_Of_Line (Input_File)
           and then not Ada.Text_IO.End_Of_File (Input_File)
         then
            Discard_Rest_Of_Line (Input_File);
            Start_Inactive_Block (Item, Current_Block);
         else
            if not Try_Parse_Include
                     (Line_Buffer (1 .. Last), Path, Item, Include_Depth)
            then
               Parse_Line (Item, Current_Block, Line_Buffer (1 .. Last));
            end if;
         end if;
      end loop;
      Ada.Text_IO.Close (Input_File);
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (Input_File) then
            Ada.Text_IO.Close (Input_File);
         end if;
         Item := (Loaded => True, Globals => <>, Blocks => <>);
         return CryptoLib.Errors.Internal_Error;
   end Load_File_With_Depth;

   function Load_File
     (Path : String; Missing_Path_Is_Ok : Boolean; Item : out Host_Config)
      return CryptoLib.Errors.Status is
   begin
      return Load_File_With_Depth (Path, Missing_Path_Is_Ok, Item, 0);
   end Load_File;

   function Expand_Home_Path (Value : String) return String is
   begin
      return SSH_Lib.Platform.Paths.Expand_Leading_Tilde (Value);
   end Expand_Home_Path;

   function Expand_Home_Path_List (Value : String) return String is
      Result      : Unbounded_String := Null_Unbounded_String;
      Start_Index : Positive := Value'First;
      Stop_Index  : Natural;
   begin
      if Value'Length = 0 then
         return "";
      end if;

      loop
         Stop_Index := Start_Index;
         while Stop_Index <= Value'Last and then Value (Stop_Index) /= ',' loop
            Stop_Index := Stop_Index + 1;
         end loop;

         declare
            Path_Text : constant String :=
              Value (Start_Index .. Stop_Index - 1);
         begin
            if Path_Text'Length = 0 then
               return Value;
            end if;
            if Length (Result) > 0 then
               Append (Result, ',');
            end if;
            Append (Result, Expand_Home_Path (Path_Text));
         end;

         exit when Stop_Index > Value'Last;
         Start_Index := Stop_Index + 1;
      end loop;

      return To_String (Result);
   exception
      when others =>
         return Value;
   end Expand_Home_Path_List;

   function Default_Config_Path return String is
   begin
      return SSH_Lib.Platform.Paths.Default_SSH_Config_Path;
   end Default_Config_Path;

   function Pattern_Matches (Pattern : String; Host : String) return Boolean is
      Pattern_Lower : constant String :=
        Ada.Characters.Handling.To_Lower (Pattern);
      Host_Lower    : constant String :=
        Ada.Characters.Handling.To_Lower (Host);

      function Match_At
        (Pattern_Index : Positive; Host_Index : Positive) return Boolean is
      begin
         if Pattern_Index > Pattern_Lower'Last then
            return Host_Index > Host_Lower'Last;
         elsif Pattern_Lower (Pattern_Index) = '*' then
            if Match_At (Pattern_Index + 1, Host_Index) then
               return True;
            end if;

            return
              Host_Index <= Host_Lower'Last
              and then Match_At (Pattern_Index, Host_Index + 1);
         elsif Host_Index > Host_Lower'Last then
            return False;
         elsif Pattern_Lower (Pattern_Index) = '?' then
            return Match_At (Pattern_Index + 1, Host_Index + 1);
         elsif Pattern_Lower (Pattern_Index) = Host_Lower (Host_Index) then
            return Match_At (Pattern_Index + 1, Host_Index + 1);
         else
            return False;
         end if;
      end Match_At;
   begin
      if Pattern'Length = 0 then
         return False;
      end if;

      return Match_At (Pattern_Lower'First, Host_Lower'First);
   end Pattern_Matches;

   function Block_Matches
     (Block_Item : Host_Block; Host : String) return Boolean
   is
      Positive_Match : Boolean := False;
   begin
      for Pattern_Item of Block_Item.Patterns loop
         declare
            Pattern_Text : constant String := To_String (Pattern_Item);
         begin
            if Pattern_Text'Length > 0
              and then Pattern_Text (Pattern_Text'First) = '!'
            then
               if Pattern_Text'Length > 1
                 and then
                   Pattern_Matches
                     (Pattern_Text
                        (Pattern_Text'First + 1 .. Pattern_Text'Last),
                      Host)
               then
                  return False;
               end if;
            elsif Pattern_Matches (Pattern_Text, Host) then
               Positive_Match := True;
            end if;
         end;
      end loop;

      return Positive_Match;
   end Block_Matches;

   function Contains_List_Name
     (List_Text : String; Name_Text : String) return Boolean
   is
      Start_Index : Positive := List_Text'First;
      Stop_Index  : Natural;
   begin
      if List_Text'Length = 0 or else Name_Text'Length = 0 then
         return False;
      end if;
      loop
         Stop_Index := Start_Index;
         while Stop_Index <= List_Text'Last
           and then List_Text (Stop_Index) /= ','
         loop
            Stop_Index := Stop_Index + 1;
         end loop;
         if Stop_Index = Start_Index then
            return False;
         elsif List_Text (Start_Index .. Stop_Index - 1) = Name_Text then
            return True;
         end if;
         exit when Stop_Index > List_Text'Last;
         Start_Index := Stop_Index + 1;
      end loop;
      return False;
   exception
      when others =>
         return False;
   end Contains_List_Name;

   function Append_Unique_List_Name
     (Result : in out Unbounded_String; Name_Text : String) return Boolean is
   begin
      if Name_Text'Length = 0 then
         return False;
      end if;

      if not Contains_List_Name (To_String (Result), Name_Text) then
         if Length (Result) > 0 then
            Append (Result, ",");
         end if;
         Append (Result, Name_Text);
      end if;

      return True;
   exception
      when others =>
         return False;
   end Append_Unique_List_Name;

   function Append_Missing_List
     (Base_Text : String; Extra_Text : String) return String
   is
      Result      : Unbounded_String := Null_Unbounded_String;
      Start_Index : Positive;
      Stop_Index  : Natural;
   begin
      if Base_Text'Length > 0 then
         Start_Index := Base_Text'First;
         loop
            Stop_Index := Start_Index;
            while Stop_Index <= Base_Text'Last
              and then Base_Text (Stop_Index) /= ','
            loop
               Stop_Index := Stop_Index + 1;
            end loop;
            if not Append_Unique_List_Name
                     (Result, Base_Text (Start_Index .. Stop_Index - 1))
            then
               return Base_Text;
            end if;
            exit when Stop_Index > Base_Text'Last;
            Start_Index := Stop_Index + 1;
         end loop;
      end if;

      if Extra_Text'Length > 0 then
         Start_Index := Extra_Text'First;
         loop
            Stop_Index := Start_Index;
            while Stop_Index <= Extra_Text'Last
              and then Extra_Text (Stop_Index) /= ','
            loop
               Stop_Index := Stop_Index + 1;
            end loop;
            if not Append_Unique_List_Name
                     (Result, Extra_Text (Start_Index .. Stop_Index - 1))
            then
               return Base_Text;
            end if;
            exit when Stop_Index > Extra_Text'Last;
            Start_Index := Stop_Index + 1;
         end loop;
      end if;

      return To_String (Result);
   exception
      when others =>
         return Base_Text;
   end Append_Missing_List;

   function Remove_List_Names
     (Base_Text : String; Remove_Text : String) return String
   is
      Result      : Unbounded_String := Null_Unbounded_String;
      Start_Index : Positive := Base_Text'First;
      Stop_Index  : Natural;
   begin
      if Base_Text'Length = 0 then
         return "";
      end if;
      loop
         Stop_Index := Start_Index;
         while Stop_Index <= Base_Text'Last
           and then Base_Text (Stop_Index) /= ','
         loop
            Stop_Index := Stop_Index + 1;
         end loop;
         declare
            Name_Text : constant String :=
              Base_Text (Start_Index .. Stop_Index - 1);
         begin
            if Name_Text'Length = 0 then
               return Base_Text;
            elsif not Contains_List_Name (Remove_Text, Name_Text)
              and then not Append_Unique_List_Name (Result, Name_Text)
            then
               return Base_Text;
            end if;
         end;
         exit when Stop_Index > Base_Text'Last;
         Start_Index := Stop_Index + 1;
      end loop;
      return To_String (Result);
   exception
      when others =>
         return Base_Text;
   end Remove_List_Names;

   function OpenSSH_Algorithm_List
     (Class_Item : SSH_Lib.Algorithms.Algorithm_Class; Value : String)
      return Unbounded_String
   is
      Default_Text : constant String :=
        SSH_Lib.Algorithms.Advertised_Name_List (Class_Item);
   begin
      if Value'Length = 0 then
         return Null_Unbounded_String;
      elsif Value (Value'First) = '+' and then Value'Length > 1 then
         return
           To_Unbounded_String
             (Append_Missing_List
                (Default_Text, Value (Value'First + 1 .. Value'Last)));
      elsif Value (Value'First) = '^' and then Value'Length > 1 then
         return
           To_Unbounded_String
             (Append_Missing_List
                (Value (Value'First + 1 .. Value'Last), Default_Text));
      elsif Value (Value'First) = '-' and then Value'Length > 1 then
         return
           To_Unbounded_String
             (Remove_List_Names
                (Default_Text, Value (Value'First + 1 .. Value'Last)));
      else
         return To_Unbounded_String (Value);
      end if;
   exception
      when others =>
         return To_Unbounded_String (Value);
   end OpenSSH_Algorithm_List;

   function Default_Userauth_Publickey_List return String is
   begin
      --  This list mirrors SSH_Lib.Public_Key_Blobs
      --  Is_Default_Userauth_Algorithm, but is kept local to avoid making the
      --  parser depend on private key-blob decoding code.  It provides the
      --  OpenSSH base list needed for PubkeyAcceptedAlgorithms modifiers.
      return
        "ssh-ed25519,"
        & "ecdsa-sha2-nistp256,"
        & "sk-ssh-ed25519@openssh.com,"
        & "sk-ecdsa-sha2-nistp256@openssh.com,"
        & "sk-ssh-ed25519-cert-v01@openssh.com,"
        & "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,"
        & "rsa-sha2-512,"
        & "rsa-sha2-256,"
        & "ssh-rsa";
   end Default_Userauth_Publickey_List;

   function OpenSSH_Userauth_Algorithm_List
     (Value : String) return Unbounded_String
   is
      Default_Text : constant String := Default_Userauth_Publickey_List;
   begin
      if Value'Length = 0 then
         return Null_Unbounded_String;
      elsif Value (Value'First) = '+' and then Value'Length > 1 then
         return
           To_Unbounded_String
             (Append_Missing_List
                (Default_Text, Value (Value'First + 1 .. Value'Last)));
      elsif Value (Value'First) = '^' and then Value'Length > 1 then
         return
           To_Unbounded_String
             (Append_Missing_List
                (Value (Value'First + 1 .. Value'Last), Default_Text));
      elsif Value (Value'First) = '-' and then Value'Length > 1 then
         return
           To_Unbounded_String
             (Remove_List_Names
                (Default_Text, Value (Value'First + 1 .. Value'Last)));
      else
         return To_Unbounded_String (Value);
      end if;
   exception
      when others =>
         return To_Unbounded_String (Value);
   end OpenSSH_Userauth_Algorithm_List;

   procedure Append_Config_Line
     (Target : in out Unbounded_String;
      Value  : Unbounded_String) is
   begin
      if Length (Value) = 0 then
         return;
      elsif Length (Target) > 0 then
         Append (Target, Character'Val (10));
      end if;
      Append (Target, To_String (Value));
   exception
      when others =>
         null;
   end Append_Config_Line;

   function Apply_Directive
     (Item    : Config_Directive;
      Options : in out SSH_Lib.Sessions.Session_Options;
      State   : in out Assignment_State) return CryptoLib.Errors.Status
   is
      Port_Value : Natural;
      Bool_Value : Boolean;
   begin
      case Item.Kind is
         when Host_Name_Directive                            =>
            if not State.Host_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Host := Item.Value;
               State.Host_Set := True;
            end if;

         when User_Directive                                 =>
            if not State.User_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.User := Item.Value;
               State.User_Set := True;
            end if;

         when Port_Directive                                 =>
            if not State.Port_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               if Parse_Port_Status (To_String (Item.Value), Port_Value)
                 /= CryptoLib.Errors.Ok
               then
                  return CryptoLib.Errors.Invalid_Port;
               end if;
               Options.Port := Port_Value;
               State.Port_Set := True;
            end if;

         when Identity_File_Directive                        =>
            if not State.Identity_File_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Identity_File :=
                 To_Unbounded_String
                   (Expand_Home_Path (To_String (Item.Value)));
               State.Identity_File_Set := True;
            end if;

         when Certificate_File_Directive                     =>
            if not State.Certificate_File_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Certificate_File :=
                 To_Unbounded_String
                   (Expand_Home_Path (To_String (Item.Value)));
               State.Certificate_File_Set := True;
            end if;

         when User_Known_Hosts_File_Directive                =>
            if not State.User_Known_Hosts_File_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.User_Known_Hosts_File :=
                 To_Unbounded_String
                   (Expand_Home_Path_List (To_String (Item.Value)));
               Options.Known_Hosts_File := Options.User_Known_Hosts_File;
               State.User_Known_Hosts_File_Set := True;
            end if;

         when Global_Known_Hosts_File_Directive              =>
            if not State.Global_Known_Hosts_File_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Global_Known_Hosts_File :=
                 To_Unbounded_String
                   (Expand_Home_Path_List (To_String (Item.Value)));
               State.Global_Known_Hosts_File_Set := True;
            end if;

         when Host_Key_Alias_Directive                       =>
            if not State.Host_Key_Alias_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Host_Key_Alias := Item.Value;
               State.Host_Key_Alias_Set := True;
            end if;

         when Revoked_Host_Keys_Directive                    =>
            if not State.Revoked_Host_Keys_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Revoked_Host_Keys_File :=
                 To_Unbounded_String
                   (Expand_Home_Path_List (To_String (Item.Value)));
               State.Revoked_Host_Keys_Set := True;
            end if;

         when Identity_Agent_Directive                       =>
            if not State.Identity_Agent_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               if Ada.Characters.Handling.To_Lower (To_String (Item.Value))
                 = "none"
               then
                  Options.Use_Agent := False;
               else
                  Options.Identity_Agent :=
                    To_Unbounded_String
                      (Expand_Home_Path (To_String (Item.Value)));
                  Options.Use_Agent := True;
               end if;
               State.Identity_Agent_Set := True;
            end if;

         when Preferred_Authentications_Directive            =>
            if not State.Preferred_Authentications_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Preferred_Authentications := Item.Value;
               State.Preferred_Authentications_Set := True;
            end if;

         when Pubkey_Accepted_Algorithms_Directive           =>
            if not State.Pubkey_Accepted_Algorithms_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Pubkey_Accepted_Algorithms :=
                 OpenSSH_Userauth_Algorithm_List (To_String (Item.Value));
               State.Pubkey_Accepted_Algorithms_Set := True;
            end if;

         when Host_Key_Algorithms_Directive                  =>
            if not State.Host_Key_Algorithms_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Host_Key_Algorithms :=
                 OpenSSH_Algorithm_List
                   (SSH_Lib.Algorithms.Server_Host_Key,
                    To_String (Item.Value));
               State.Host_Key_Algorithms_Set := True;
            end if;

         when Kex_Algorithms_Directive                       =>
            if not State.Kex_Algorithms_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Kex_Algorithms :=
                 OpenSSH_Algorithm_List
                   (SSH_Lib.Algorithms.Key_Exchange, To_String (Item.Value));
               State.Kex_Algorithms_Set := True;
            end if;

         when Ciphers_Directive                              =>
            if not State.Ciphers_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Cipher_Algorithms :=
                 OpenSSH_Algorithm_List
                   (SSH_Lib.Algorithms.Encryption_Client_To_Server,
                    To_String (Item.Value));
               State.Ciphers_Set := True;
            end if;

         when Macs_Directive                                 =>
            if not State.Macs_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Mac_Algorithms :=
                 OpenSSH_Algorithm_List
                   (SSH_Lib.Algorithms.Mac_Client_To_Server,
                    To_String (Item.Value));
               State.Macs_Set := True;
            end if;

         when Compression_Directive                          =>
            if not State.Compression_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               if Ada.Characters.Handling.To_Lower (To_String (Item.Value))
                 = "yes"
               then
                  Options.Compression_Algorithms :=
                    To_Unbounded_String ("zlib@openssh.com,zlib,none");
               elsif Ada.Characters.Handling.To_Lower (To_String (Item.Value))
                 = "no"
               then
                  Options.Compression_Algorithms :=
                    To_Unbounded_String ("none");
               else
                  Options.Compression_Algorithms :=
                    OpenSSH_Algorithm_List
                      (SSH_Lib.Algorithms.Compression_Client_To_Server,
                       To_String (Item.Value));
               end if;
               State.Compression_Set := True;
            end if;

         when Canonicalize_Hostname_Directive                =>
            if not State.Canonicalize_Hostname_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               if not Canonicalize_Hostname_Value
                        (To_String (Item.Value), Bool_Value)
               then
                  return CryptoLib.Errors.Internal_Error;
               end if;
               Options.Canonicalize_Hostname := Bool_Value;
               State.Canonicalize_Hostname_Set := True;
            end if;

         when Certificate_Authority_File_Directive           =>
            if not State.Certificate_Authority_File_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Certificate_Authority_File :=
                 To_Unbounded_String
                   (Expand_Home_Path_List (To_String (Item.Value)));
               State.Certificate_Authority_File_Set := True;
            end if;

         when Trusted_User_CA_Keys_Directive                 =>
            if not State.Trusted_User_CA_Keys_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Trusted_User_CA_Keys_File :=
                 To_Unbounded_String
                   (Expand_Home_Path_List (To_String (Item.Value)));
               State.Trusted_User_CA_Keys_Set := True;
            end if;

         when Allowed_Cert_Critical_Options_Directive        =>
            if not State.Allowed_Cert_Critical_Options_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Allowed_Certificate_Critical_Options := Item.Value;
               State.Allowed_Cert_Critical_Options_Set := True;
            end if;

         when Reject_Unknown_Cert_Critical_Options_Directive =>
            if not State.Reject_Unknown_Cert_Critical_Options_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               if not Boolean_Value (To_String (Item.Value), Bool_Value) then
                  return CryptoLib.Errors.Internal_Error;
               end if;
               Options.Reject_Unknown_Certificate_Critical_Options :=
                 Bool_Value;
               State.Reject_Unknown_Cert_Critical_Options_Set := True;
            end if;

         when Identities_Only_Directive                      =>
            if not State.Identities_Only_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               if not Boolean_Value (To_String (Item.Value), Bool_Value) then
                  return CryptoLib.Errors.Internal_Error;
               end if;
               Options.Use_Agent := not Bool_Value;
               State.Identities_Only_Set := True;
            end if;

         when Proxy_Jump_Directive                           =>
            if not State.Proxy_Jump_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Proxy_Jump := Item.Value;
               State.Proxy_Jump_Set := True;
            end if;

         when Proxy_Command_Directive                        =>
            if not State.Proxy_Command_Set then
               if Is_None_Text (To_String (Item.Value)) then
                  Options.Proxy_Command := Null_Unbounded_String;
               else
                  Options.Proxy_Command := Item.Value;
               end if;
               State.Proxy_Command_Set := True;
            end if;

         when Control_Master_Directive                       =>
            if not State.Control_Master_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Control_Master := Item.Value;
               State.Control_Master_Set := True;
            end if;

         when Control_Path_Directive                         =>
            if not State.Control_Path_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Control_Path := Item.Value;
               State.Control_Path_Set := True;
            end if;

         when Control_Persist_Directive                      =>
            if not State.Control_Persist_Set then
               if Item.Status /= CryptoLib.Errors.Ok then
                  return Item.Status;
               end if;
               Options.Control_Persist := Item.Value;
               State.Control_Persist_Set := True;
            end if;

         when Local_Forward_Directive                        =>
            if Item.Status /= CryptoLib.Errors.Ok then
               return Item.Status;
            end if;
            Append_Config_Line (Options.Local_Forwards, Item.Value);
            State.Local_Forward_Set := True;

         when Remote_Forward_Directive                       =>
            if Item.Status /= CryptoLib.Errors.Ok then
               return Item.Status;
            end if;
            Append_Config_Line (Options.Remote_Forwards, Item.Value);
            State.Remote_Forward_Set := True;

         when Dynamic_Forward_Directive                      =>
            if Item.Status /= CryptoLib.Errors.Ok then
               return Item.Status;
            end if;
            Append_Config_Line (Options.Dynamic_Forwards, Item.Value);
            State.Dynamic_Forward_Set := True;

         when Send_Env_Directive                             =>
            if Item.Status /= CryptoLib.Errors.Ok then
               return Item.Status;
            end if;
            Append_Config_Line (Options.Send_Env, Item.Value);
            State.Send_Env_Set := True;

         when Set_Env_Directive                              =>
            if Item.Status /= CryptoLib.Errors.Ok then
               return Item.Status;
            end if;
            Append_Config_Line (Options.Set_Env, Item.Value);
            State.Set_Env_Set := True;
      end case;

      Options.Verify_Known_Host := True;
      Options.Strict_Host_Key := True;
      return CryptoLib.Errors.Ok;
   end Apply_Directive;

   function Apply_Directives
     (Items   : Directive_Vectors.Vector;
      Options : in out SSH_Lib.Sessions.Session_Options;
      State   : in out Assignment_State) return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status;
   begin
      for Directive_Item of Items loop
         Status_Value := Apply_Directive (Directive_Item, Options, State);
         if Status_Value /= CryptoLib.Errors.Ok then
            return Status_Value;
         end if;
      end loop;
      return CryptoLib.Errors.Ok;
   end Apply_Directives;

   function Load_Default return Host_Config is
      Result       : Host_Config;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := Load_File (Default_Config_Path, True, Result);
      if Status_Value /= CryptoLib.Errors.Ok then
         return (Loaded => True, Globals => <>, Blocks => <>);
      end if;
      return Result;
   end Load_Default;

   function Load
     (Path : String; Item : out Host_Config) return CryptoLib.Errors.Status is
   begin
      return Load_File (Path, False, Item);
   end Load;

   function Has_Unsupported_Feature
     (Config : Host_Config; Host : String) return Boolean is
      pragma Unreferenced (Config, Host);
   begin
      return False;
   exception
      when others =>
         return True;
   end Has_Unsupported_Feature;

   function Resolve
     (Config : Host_Config; Host : String)
      return SSH_Lib.Sessions.Session_Options
   is
      Options      : SSH_Lib.Sessions.Session_Options;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := Resolve (Config, Host, Options);
      if Status_Value /= CryptoLib.Errors.Ok then
         Options :=
           (Host                         => To_Unbounded_String (Host),
            Port                         => 22,
            User                         => Null_Unbounded_String,
            Connect_Timeout_MS           => 30_000,
            Read_Timeout_MS              => 30_000,
            Write_Timeout_MS             => 30_000,
            Verify_Known_Host            => True,
            Known_Hosts_File             => Null_Unbounded_String,
            Identity_File                => Null_Unbounded_String,
            Certificate_File             => Null_Unbounded_String,
            Use_Agent                    => True,
            Strict_Host_Key              => True,
            Proxy_Jump                   => Null_Unbounded_String,
            Proxy_Command                => Null_Unbounded_String,
            Use_Password                 => False,
            Password                     => Null_Unbounded_String,
            Use_Identity_Passphrase      => False,
            Identity_Passphrase          => Null_Unbounded_String,
            Password_Callback            => null,
            Identity_Passphrase_Callback => null,
            Password_Change_Callback     => null,
            others                       => <>);
      end if;
      return Options;
   end Resolve;

   function Resolve
     (Config : Host_Config;
      Host   : String;
      Item   : out SSH_Lib.Sessions.Session_Options)
      return CryptoLib.Errors.Status is
   begin
      return Resolve (Config, Host, "", Item);
   end Resolve;

   function Resolve
     (Config       : Host_Config;
      Host         : String;
      Default_User : String;
      Item         : out SSH_Lib.Sessions.Session_Options)
      return CryptoLib.Errors.Status
   is
      State        : Assignment_State;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Item :=
        (Host                         => To_Unbounded_String (Host),
         Port                         => 22,
         User                         => Null_Unbounded_String,
         Connect_Timeout_MS           => 30_000,
         Read_Timeout_MS              => 30_000,
         Write_Timeout_MS             => 30_000,
         Verify_Known_Host            => True,
         Known_Hosts_File             => Null_Unbounded_String,
         Identity_File                => Null_Unbounded_String,
         Certificate_File             => Null_Unbounded_String,
         Use_Agent                    => True,
         Strict_Host_Key              => True,
         Proxy_Jump                   => Null_Unbounded_String,
         Proxy_Command                => Null_Unbounded_String,
         Use_Password                 => False,
         Password                     => Null_Unbounded_String,
         Use_Identity_Passphrase      => False,
         Identity_Passphrase          => Null_Unbounded_String,
         Password_Callback            => null,
         Identity_Passphrase_Callback => null,
         Password_Change_Callback     => null,
         others                       => <>);

      if not Is_Valid_Host_Text (Host) then
         Item.Host := Null_Unbounded_String;
         return CryptoLib.Errors.Invalid_Host;
      end if;

      Status_Value := Apply_Directives (Config.Globals, Item, State);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      for Block_Item of Config.Blocks loop
         if Block_Matches (Block_Item, Host) then
            Status_Value :=
              Apply_Directives (Block_Item.Directives, Item, State);
            if Status_Value /= CryptoLib.Errors.Ok then
               return Status_Value;
            end if;
         end if;
      end loop;

      if not State.User_Set and then Default_User'Length > 0 then
         if not Is_Valid_User_Text (Default_User) then
            return CryptoLib.Errors.Invalid_User;
         end if;
         Item.User := To_Unbounded_String (Default_User);
      end if;

      Item.Verify_Known_Host := True;
      Item.Strict_Host_Key := True;
      return CryptoLib.Errors.Ok;
   end Resolve;

   function Resolve_Remote
     (Config       : Host_Config;
      Remote_Text  : String;
      Default_User : String;
      Item         : out SSH_Lib.Sessions.Session_Options)
      return CryptoLib.Errors.Status
   is
      Remote_Item  : SSH_Lib.Remote_Names.Parsed_Remote;
      Status_Value : CryptoLib.Errors.Status;
   begin
      if Control_Break_Is_In_Remote_Repository (Remote_Text) then
         Item :=
           (Host                         => Null_Unbounded_String,
            Port                         => 22,
            User                         => Null_Unbounded_String,
            Connect_Timeout_MS           => 30_000,
            Read_Timeout_MS              => 30_000,
            Write_Timeout_MS             => 30_000,
            Verify_Known_Host            => True,
            Known_Hosts_File             => Null_Unbounded_String,
            Identity_File                => Null_Unbounded_String,
            Certificate_File             => Null_Unbounded_String,
            Use_Agent                    => True,
            Strict_Host_Key              => True,
            Proxy_Jump                   => Null_Unbounded_String,
            Proxy_Command                => Null_Unbounded_String,
            Use_Password                 => False,
            Password                     => Null_Unbounded_String,
            Use_Identity_Passphrase      => False,
            Identity_Passphrase          => Null_Unbounded_String,
            Password_Callback            => null,
            Identity_Passphrase_Callback => null,
            Password_Change_Callback     => null,
            others                       => <>);
         return CryptoLib.Errors.Invalid_Command;
      end if;

      Status_Value := SSH_Lib.Remote_Names.Parse (Remote_Text, Remote_Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         Item :=
           (Host                         => Null_Unbounded_String,
            Port                         => 22,
            User                         => Null_Unbounded_String,
            Connect_Timeout_MS           => 30_000,
            Read_Timeout_MS              => 30_000,
            Write_Timeout_MS             => 30_000,
            Verify_Known_Host            => True,
            Known_Hosts_File             => Null_Unbounded_String,
            Identity_File                => Null_Unbounded_String,
            Certificate_File             => Null_Unbounded_String,
            Use_Agent                    => True,
            Strict_Host_Key              => True,
            Proxy_Jump                   => Null_Unbounded_String,
            Proxy_Command                => Null_Unbounded_String,
            Use_Password                 => False,
            Password                     => Null_Unbounded_String,
            Use_Identity_Passphrase      => False,
            Identity_Passphrase          => Null_Unbounded_String,
            Password_Callback            => null,
            Identity_Passphrase_Callback => null,
            Password_Change_Callback     => null,
            others                       => <>);
         return Status_Value;
      end if;

      Status_Value :=
        Resolve
          (Config,
           SSH_Lib.Remote_Names.Host (Remote_Item),
           (if SSH_Lib.Remote_Names.Has_User (Remote_Item)
            then ""
            else Default_User),
           Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      if SSH_Lib.Remote_Names.Has_User (Remote_Item) then
         Item.User :=
           To_Unbounded_String (SSH_Lib.Remote_Names.User (Remote_Item));
      end if;

      if SSH_Lib.Remote_Names.Has_Explicit_Port (Remote_Text) then
         Item.Port := SSH_Lib.Remote_Names.Port (Remote_Item);
      end if;

      Item.Verify_Known_Host := True;
      Item.Strict_Host_Key := True;

      if Length (Item.User) = 0 then
         return CryptoLib.Errors.Invalid_User;
      end if;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Item :=
           (Host                         => Null_Unbounded_String,
            Port                         => 22,
            User                         => Null_Unbounded_String,
            Connect_Timeout_MS           => 30_000,
            Read_Timeout_MS              => 30_000,
            Write_Timeout_MS             => 30_000,
            Verify_Known_Host            => True,
            Known_Hosts_File             => Null_Unbounded_String,
            Identity_File                => Null_Unbounded_String,
            Certificate_File             => Null_Unbounded_String,
            Use_Agent                    => True,
            Strict_Host_Key              => True,
            Proxy_Jump                   => Null_Unbounded_String,
            Proxy_Command                => Null_Unbounded_String,
            Use_Password                 => False,
            Password                     => Null_Unbounded_String,
            Use_Identity_Passphrase      => False,
            Identity_Passphrase          => Null_Unbounded_String,
            Password_Callback            => null,
            Identity_Passphrase_Callback => null,
            Password_Change_Callback     => null,
            others                       => <>);
         return CryptoLib.Errors.Internal_Error;
   end Resolve_Remote;
   function Resolve_Remote
     (Config : Host_Config;
      Remote : SSH_Lib.Remote_Names.Remote_Name;
      Item   : out SSH_Lib.Sessions.Session_Options)
      return CryptoLib.Errors.Status
   is
      Status_Value : CryptoLib.Errors.Status;
   begin
      if not SSH_Lib.Remote_Names.Is_Valid (Remote) then
         Item :=
           (Host                         => Null_Unbounded_String,
            Port                         => 22,
            User                         => Null_Unbounded_String,
            Connect_Timeout_MS           => 30_000,
            Read_Timeout_MS              => 30_000,
            Write_Timeout_MS             => 30_000,
            Verify_Known_Host            => True,
            Known_Hosts_File             => Null_Unbounded_String,
            Identity_File                => Null_Unbounded_String,
            Certificate_File             => Null_Unbounded_String,
            Use_Agent                    => True,
            Strict_Host_Key              => True,
            Proxy_Jump                   => Null_Unbounded_String,
            Proxy_Command                => Null_Unbounded_String,
            Use_Password                 => False,
            Password                     => Null_Unbounded_String,
            Use_Identity_Passphrase      => False,
            Identity_Passphrase          => Null_Unbounded_String,
            Password_Callback            => null,
            Identity_Passphrase_Callback => null,
            Password_Change_Callback     => null,
            others                       => <>);
         return CryptoLib.Errors.Invalid_Host;
      end if;

      Status_Value :=
        Resolve (Config, SSH_Lib.Remote_Names.Host (Remote), Item);
      if Status_Value /= CryptoLib.Errors.Ok then
         return Status_Value;
      end if;

      if SSH_Lib.Remote_Names.Has_User (Remote) then
         Item.User := To_Unbounded_String (SSH_Lib.Remote_Names.User (Remote));
      end if;

      if SSH_Lib.Remote_Names.Port (Remote) /= 22 then
         Item.Port := SSH_Lib.Remote_Names.Port (Remote);
      end if;

      Item.Verify_Known_Host := True;
      Item.Strict_Host_Key := True;

      --  Keep the parsed-record overload deterministic for direct callers.
      --  It cannot distinguish an omitted ssh:// port from an explicit :22
      --  because Parsed_Remote stores only the effective port; callers that
      --  need that distinction must use the Remote_Text overload.  It should
      --  still reject the missing-user state instead of returning an unusable
      --  options record.
      if Length (Item.User) = 0 then
         return CryptoLib.Errors.Invalid_User;
      end if;

      return CryptoLib.Errors.Ok;
   end Resolve_Remote;
end SSH_Lib.Config;
