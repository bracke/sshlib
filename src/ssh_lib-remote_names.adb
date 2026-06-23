with Ada.Characters.Handling;
with Ada.Strings;
with Ada.Strings.Fixed;
with CryptoLib.Errors; use CryptoLib.Errors;
with SSH_Lib.Internal;

package body SSH_Lib.Remote_Names is
   use Ada.Strings.Unbounded;

   Maximum_Repository_Path_Length : constant Natural := 65_536;

   function Valid_Repository_Path (Value : String) return Boolean is
   begin
      if Value'Length = 0 or else Value'Length > Maximum_Repository_Path_Length
      then
         return False;
      end if;

      return not SSH_Lib.Internal.Has_Control_Break (Value);
   end Valid_Repository_Path;

   function Valid_Remote_User (Value : String) return Boolean is
   begin
      if not SSH_Lib.Internal.Valid_User (Value) then
         return False;
      end if;

      for User_Character of Value loop
         if User_Character = ':'
           or else User_Character = '/'
           or else User_Character = Character'Val (16#5C#)
           or else User_Character = '?'
           or else User_Character = '#'
           or else User_Character = '@'
         then
            return False;
         end if;
      end loop;

      return True;
   end Valid_Remote_User;

   function Valid_Remote_Host (Value : String) return Boolean is
   begin
      if not SSH_Lib.Internal.Valid_Host (Value) then
         return False;
      end if;

      for Host_Character of Value loop
         if Host_Character = '/'
           or else Host_Character = Character'Val (16#5C#)
           or else Host_Character = '?'
           or else Host_Character = '#'
         then
            return False;
         end if;
      end loop;

      return True;
   end Valid_Remote_Host;

   function Contains_Character
     (Value : String; Delimiter : Character) return Boolean is
   begin
      for Character_Value of Value loop
         if Character_Value = Delimiter then
            return True;
         end if;
      end loop;

      return False;
   end Contains_Character;

   function Contains_Query_Or_Fragment (Value : String) return Boolean is
   begin
      return
        Contains_Character (Value, '?')
        or else Contains_Character (Value, '#');
   end Contains_Query_Or_Fragment;

   function Parse_Natural
     (Value : String; Parsed_Value : out Natural) return Boolean
   is
      Accumulator : Natural := 0;
   begin
      if Value'Length = 0 then
         return False;
      end if;

      for Digit_Character of Value loop
         if Digit_Character not in '0' .. '9' then
            return False;
         end if;

         Accumulator :=
           Accumulator
           * 10
           + Character'Pos (Digit_Character)
           - Character'Pos ('0');

         if Accumulator > 65_535 then
            return False;
         end if;
      end loop;

      Parsed_Value := Accumulator;
      return Accumulator /= 0;
   exception
      when others =>
         return False;
   end Parse_Natural;

   function Parse_Host_Port
     (Value       : String;
      Parsed_Host : out Unbounded_String;
      Parsed_Port : out Natural) return CryptoLib.Errors.Status
   is
      Colon_Position : constant Natural :=
        Ada.Strings.Fixed.Index (Value, ":");
   begin
      Parsed_Host := Null_Unbounded_String;
      Parsed_Port := 22;

      if Value'Length = 0 then
         return CryptoLib.Errors.Invalid_Host;
      end if;

      if Value (Value'First) = '[' then
         declare
            Close_Bracket_Position : constant Natural :=
              Ada.Strings.Fixed.Index (Value, "]");
            Port_Value             : Natural := 22;
         begin
            if Close_Bracket_Position = 0
              or else Close_Bracket_Position <= Value'First + 1
            then
               return CryptoLib.Errors.Invalid_Host;
            end if;

            declare
               Host_Text : constant String :=
                 Value (Value'First + 1 .. Close_Bracket_Position - 1);
            begin
               if Contains_Character (Host_Text, '@')
                 or else Contains_Character (Host_Text, '[')
                 or else Contains_Character (Host_Text, ']')
                 or else not Valid_Remote_Host (Host_Text)
               then
                  return CryptoLib.Errors.Invalid_Host;
               end if;

               if Close_Bracket_Position = Value'Last then
                  Parsed_Host := To_Unbounded_String (Host_Text);
                  return CryptoLib.Errors.Ok;
               end if;

               if Value (Close_Bracket_Position + 1) /= ':' then
                  return CryptoLib.Errors.Invalid_Host;
               end if;

               if Close_Bracket_Position + 1 = Value'Last then
                  return CryptoLib.Errors.Invalid_Port;
               end if;

               if not Parse_Natural
                        (Value (Close_Bracket_Position + 2 .. Value'Last),
                         Port_Value)
               then
                  return CryptoLib.Errors.Invalid_Port;
               end if;

               Parsed_Host := To_Unbounded_String (Host_Text);
               Parsed_Port := Port_Value;
               return CryptoLib.Errors.Ok;
            end;
         end;
      end if;

      if Colon_Position = 0 then
         if Contains_Character (Value, '@')
           or else Contains_Character (Value, '[')
           or else Contains_Character (Value, ']')
           or else not Valid_Remote_Host (Value)
         then
            return CryptoLib.Errors.Invalid_Host;
         end if;

         Parsed_Host := To_Unbounded_String (Value);
         return CryptoLib.Errors.Ok;
      end if;

      if Colon_Position = Value'First then
         return CryptoLib.Errors.Invalid_Host;
      end if;

      if Colon_Position = Value'Last then
         return CryptoLib.Errors.Invalid_Port;
      end if;

      declare
         Host_Text  : constant String :=
           Value (Value'First .. Colon_Position - 1);
         Port_Text  : constant String :=
           Value (Colon_Position + 1 .. Value'Last);
         Port_Value : Natural := 22;
      begin
         if Contains_Character (Host_Text, '@')
           or else Contains_Character (Host_Text, '[')
           or else Contains_Character (Host_Text, ']')
           or else not Valid_Remote_Host (Host_Text)
         then
            return CryptoLib.Errors.Invalid_Host;
         end if;

         if not Parse_Natural (Port_Text, Port_Value) then
            return CryptoLib.Errors.Invalid_Port;
         end if;

         Parsed_Host := To_Unbounded_String (Host_Text);
         Parsed_Port := Port_Value;
         return CryptoLib.Errors.Ok;
      end;
   end Parse_Host_Port;

   function Parse_Ssh_Uri
     (Value : String; Item : out Parsed_Remote) return CryptoLib.Errors.Status
   is
      Prefix          : constant String := "ssh://";
      Remainder_First : constant Natural := Value'First + Prefix'Length;
   begin
      if Value'Length = Prefix'Length then
         return CryptoLib.Errors.Invalid_Host;
      end if;

      declare
         Remainder      : constant String :=
           Value (Remainder_First .. Value'Last);
         Slash_Position : constant Natural :=
           Ada.Strings.Fixed.Index (Remainder, "/");
      begin
         if Contains_Query_Or_Fragment (Remainder) then
            return CryptoLib.Errors.Invalid_Command;
         end if;

         if Slash_Position = 0 then
            return CryptoLib.Errors.Invalid_Command;
         end if;

         if Slash_Position = Remainder'First then
            return CryptoLib.Errors.Invalid_Host;
         end if;

         if Slash_Position = Remainder'Last then
            return CryptoLib.Errors.Invalid_Command;
         end if;

         declare
            Authority_Text  : constant String :=
              Remainder (Remainder'First .. Slash_Position - 1);
            Repository_Text : constant String :=
              Remainder (Slash_Position + 1 .. Remainder'Last);
            At_Position     : constant Natural :=
              Ada.Strings.Fixed.Index (Authority_Text, "@");
            Host_Port_Text  : Unbounded_String;
            Status_Value    : CryptoLib.Errors.Status;
         begin
            if Contains_Query_Or_Fragment (Repository_Text)
              or else not Valid_Repository_Path (Repository_Text)
            then
               return CryptoLib.Errors.Invalid_Command;
            end if;

            if At_Position = 0 then
               Host_Port_Text := To_Unbounded_String (Authority_Text);
               Item.User := Null_Unbounded_String;
            else
               if At_Position = Authority_Text'First then
                  return CryptoLib.Errors.Invalid_User;
               end if;

               if At_Position = Authority_Text'Last then
                  return CryptoLib.Errors.Invalid_Host;
               end if;

               declare
                  User_Text : constant String :=
                    Authority_Text (Authority_Text'First .. At_Position - 1);
               begin
                  if not Valid_Remote_User (User_Text) then
                     return CryptoLib.Errors.Invalid_User;
                  end if;

                  Item.User := To_Unbounded_String (User_Text);
               end;

               Host_Port_Text :=
                 To_Unbounded_String
                   (Authority_Text (At_Position + 1 .. Authority_Text'Last));
            end if;

            Status_Value :=
              Parse_Host_Port
                (To_String (Host_Port_Text), Item.Host, Item.Port);
            if Status_Value /= CryptoLib.Errors.Ok then
               return Status_Value;
            end if;

            Item.Kind := Ssh_Uri;
            Item.Repository := To_Unbounded_String (Repository_Text);
            return CryptoLib.Errors.Ok;
         end;
      end;
   end Parse_Ssh_Uri;

   function Parse_Scp_Like
     (Value : String; Item : out Parsed_Remote) return CryptoLib.Errors.Status
   is
      Colon_Position : constant Natural :=
        Ada.Strings.Fixed.Index (Value, ":");
      At_Position    : constant Natural :=
        Ada.Strings.Fixed.Index (Value, "@");
   begin
      if Colon_Position = 0 or else Colon_Position = Value'First then
         return CryptoLib.Errors.Invalid_Host;
      end if;

      if Colon_Position = Value'Last then
         return CryptoLib.Errors.Invalid_Command;
      end if;

      declare
         Host_Text       : Unbounded_String;
         Repository_Text : constant String :=
           Value (Colon_Position + 1 .. Value'Last);
      begin
         if not Valid_Repository_Path (Repository_Text) then
            return CryptoLib.Errors.Invalid_Command;
         end if;

         if At_Position = 0 or else At_Position > Colon_Position then
            Item.User := Null_Unbounded_String;
            Host_Text :=
              To_Unbounded_String (Value (Value'First .. Colon_Position - 1));
         else
            if At_Position = Value'First then
               return CryptoLib.Errors.Invalid_User;
            end if;

            if At_Position + 1 = Colon_Position then
               return CryptoLib.Errors.Invalid_Host;
            end if;

            declare
               User_Text : constant String :=
                 Value (Value'First .. At_Position - 1);
            begin
               if not Valid_Remote_User (User_Text) then
                  return CryptoLib.Errors.Invalid_User;
               end if;

               Item.User := To_Unbounded_String (User_Text);
            end;

            Host_Text :=
              To_Unbounded_String
                (Value (At_Position + 1 .. Colon_Position - 1));
         end if;

         if Contains_Character (To_String (Host_Text), '@')
           or else not Valid_Remote_Host (To_String (Host_Text))
         then
            return CryptoLib.Errors.Invalid_Host;
         end if;

         Item.Kind := Scp_Like;
         Item.Host := Host_Text;
         Item.Port := 22;
         Item.Repository := To_Unbounded_String (Repository_Text);
         return CryptoLib.Errors.Ok;
      end;
   end Parse_Scp_Like;

   function Parse
     (Value : String; Item : out Parsed_Remote) return CryptoLib.Errors.Status
   is
      Prefix       : constant String := "ssh://";
      Lower_Value  : constant String :=
        Ada.Characters.Handling.To_Lower (Value);
      Empty_Item   : constant Parsed_Remote :=
        (Kind       => Ssh_Uri,
         Host       => Null_Unbounded_String,
         Port       => 22,
         User       => Null_Unbounded_String,
         Repository => Null_Unbounded_String);
      Candidate    : Parsed_Remote := Empty_Item;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Item := Empty_Item;

      if Value'Length = 0 or else SSH_Lib.Internal.Has_Control_Break (Value)
      then
         return CryptoLib.Errors.Invalid_Host;
      end if;

      if Value'Length >= Prefix'Length
        and then
          Lower_Value
            (Lower_Value'First .. Lower_Value'First + Prefix'Length - 1)
          = Prefix
      then
         Status_Value := Parse_Ssh_Uri (Value, Candidate);
      elsif Ada.Strings.Fixed.Index (Value, "://") /= 0 then
         Status_Value := CryptoLib.Errors.Invalid_Host;
      else
         Status_Value := Parse_Scp_Like (Value, Candidate);
      end if;

      if Status_Value = CryptoLib.Errors.Ok then
         Item := Candidate;
      end if;

      return Status_Value;
   exception
      when others =>
         Item :=
           (Kind       => Ssh_Uri,
            Host       => Null_Unbounded_String,
            Port       => 22,
            User       => Null_Unbounded_String,
            Repository => Null_Unbounded_String);
         return CryptoLib.Errors.Internal_Error;
   end Parse;

   function Kind (Item : Parsed_Remote) return Remote_Kind is
   begin
      return Item.Kind;
   end Kind;

   function Kind_Image (Value : Remote_Kind) return String is
   begin
      case Value is
         when Ssh_Uri  =>
            return "ssh-url";

         when Scp_Like =>
            return "scp-like";
      end case;
   end Kind_Image;

   function Host_Needs_Brackets (Value : String) return Boolean is
   begin
      return Contains_Character (Value, ':');
   end Host_Needs_Brackets;

   function Host_Image (Value : String) return String is
   begin
      if Host_Needs_Brackets (Value) then
         return "[" & Value & "]";
      else
         return Value;
      end if;
   end Host_Image;

   function Port_Image (Value : Natural) return String is
   begin
      if Value = 22 then
         return "";
      else
         return
           ":"
           & Ada.Strings.Fixed.Trim (Natural'Image (Value), Ada.Strings.Left);
      end if;
   end Port_Image;

   function Image (Item : Parsed_Remote) return String is
      Host_Text       : constant String := To_String (Item.Host);
      User_Text       : constant String := To_String (Item.User);
      Repository_Text : constant String := To_String (Item.Repository);
      User_Prefix     : constant String :=
        (if User_Text'Length = 0 then "" else User_Text & "@");
   begin
      if not Is_Valid (Item) then
         return "";
      end if;

      case Item.Kind is
         when Ssh_Uri  =>
            declare
               Authority_Text : constant String :=
                 User_Prefix & Host_Image (Host_Text);
            begin
               return
                 "ssh://"
                 & Authority_Text
                 & Port_Image (Item.Port)
                 & "/"
                 & Repository_Text;
            end;

         when Scp_Like =>
            return User_Prefix & Host_Text & ":" & Repository_Text;
      end case;
   exception
      when others =>
         return "";
   end Image;

   function Is_Valid (Item : Parsed_Remote) return Boolean is
      Host_Text       : constant String := To_String (Item.Host);
      User_Text       : constant String := To_String (Item.User);
      Repository_Text : constant String := To_String (Item.Repository);
   begin
      if not Valid_Remote_Host (Host_Text)
        or else SSH_Lib.Internal.Validate_Port (Item.Port) /= CryptoLib.Errors.Ok
        or else not Valid_Repository_Path (Repository_Text)
      then
         return False;
      end if;

      if User_Text'Length > 0 and then not Valid_Remote_User (User_Text) then
         return False;
      end if;

      if Item.Kind = Scp_Like and then Host_Needs_Brackets (Host_Text) then
         return False;
      end if;

      return True;
   exception
      when others =>
         return False;
   end Is_Valid;

   function Host (Item : Parsed_Remote) return String is
   begin
      return To_String (Item.Host);
   end Host;

   function User (Item : Parsed_Remote) return String is
   begin
      return To_String (Item.User);
   end User;

   function Repository_Path (Item : Parsed_Remote) return String is
   begin
      return To_String (Item.Repository);
   end Repository_Path;

   function Port (Item : Parsed_Remote) return Natural is
   begin
      return Item.Port;
   end Port;

   function Has_Explicit_Port (Value : String) return Boolean is
      Prefix      : constant String := "ssh://";
      Lower_Value : constant String :=
        Ada.Characters.Handling.To_Lower (Value);
   begin
      if Value'Length < Prefix'Length
        or else
          Lower_Value
            (Lower_Value'First .. Lower_Value'First + Prefix'Length - 1)
          /= Prefix
      then
         return False;
      end if;

      declare
         Remainder_First : constant Natural := Value'First + Prefix'Length;
         Remainder       : constant String :=
           Value (Remainder_First .. Value'Last);
         Slash_Position  : constant Natural :=
           Ada.Strings.Fixed.Index (Remainder, "/");
      begin
         if Slash_Position = 0 or else Slash_Position = Remainder'First then
            return False;
         end if;

         declare
            Authority_Text  : constant String :=
              Remainder (Remainder'First .. Slash_Position - 1);
            At_Position     : constant Natural :=
              Ada.Strings.Fixed.Index (Authority_Text, "@");
            Host_Port_First : constant Natural :=
              (if At_Position = 0
               then Authority_Text'First
               else At_Position + 1);
            Host_Port_Text  : constant String :=
              Authority_Text (Host_Port_First .. Authority_Text'Last);
         begin
            if Host_Port_Text'Length = 0 then
               return False;
            end if;

            if Host_Port_Text (Host_Port_Text'First) = '[' then
               declare
                  Close_Bracket_Position : constant Natural :=
                    Ada.Strings.Fixed.Index (Host_Port_Text, "]");
               begin
                  return
                    Close_Bracket_Position /= 0
                    and then Close_Bracket_Position < Host_Port_Text'Last
                    and then Host_Port_Text (Close_Bracket_Position + 1) = ':';
               end;
            end if;

            return Ada.Strings.Fixed.Index (Host_Port_Text, ":") /= 0;
         end;
      end;
   exception
      when others =>
         return False;
   end Has_Explicit_Port;

   function Has_User (Item : Parsed_Remote) return Boolean is
   begin
      return Length (Item.User) > 0;
   end Has_User;

   function To_Session_Options
     (Item : Parsed_Remote) return SSH_Lib.Sessions.Session_Options
   is
      Options   : SSH_Lib.Sessions.Session_Options;
      Host_Text : constant String := To_String (Item.Host);
      User_Text : constant String := To_String (Item.User);
   begin
      if Valid_Remote_Host (Host_Text) then
         Options.Host := Item.Host;
      end if;

      if SSH_Lib.Internal.Validate_Port (Item.Port) = CryptoLib.Errors.Ok then
         Options.Port := Item.Port;
      else
         Options.Port := 0;
      end if;

      if User_Text'Length > 0 and then Valid_Remote_User (User_Text) then
         Options.User := Item.User;
      end if;

      return Options;
   exception
      when others =>
         return Options;
   end To_Session_Options;

   function To_Session_Options
     (Item : Parsed_Remote; Default_User : String)
      return SSH_Lib.Sessions.Session_Options
   is
      Options : SSH_Lib.Sessions.Session_Options := To_Session_Options (Item);
   begin
      if Length (Options.User) = 0 and then Valid_Remote_User (Default_User)
      then
         Options.User := To_Unbounded_String (Default_User);
      end if;

      return Options;
   end To_Session_Options;
end SSH_Lib.Remote_Names;
