with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Streams;
with CryptoLib.Hashes;
with SSH_Lib.Internal;
with SSH_Lib.Keys;
with SSH_Lib.Platform.Environment;

package body SSH_Lib.Config_Apply is
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;
   use type Interfaces.Unsigned_32;
   use type SSH_Lib.Mux.Mux_Message_Kind;
   use type SSH_Lib.Sessions.Control_Master_Approval_Callback_Access;

   Max_Configured_Environment : constant Positive := 64;
   subtype Configured_Environment_Range is
     Positive range 1 .. Max_Configured_Environment;
   subtype Configured_Environment_Array is
     SSH_Lib.Channels.Environment_Variable_Array
       (Configured_Environment_Range);

   function Trim_Text (Text : String) return String is
   begin
      return Ada.Strings.Fixed.Trim (Text, Ada.Strings.Both);
   end Trim_Text;

   function Parse_Port (Text : String; Port : out Natural) return Status is
      Value : Natural := 0;
   begin
      Port := 0;
      if Text'Length = 0 then
         return Invalid_Port;
      end if;
      for Ch of Text loop
         if Ch < '0' or else Ch > '9' then
            return Invalid_Port;
         end if;
         Value := Value * 10 + Character'Pos (Ch) - Character'Pos ('0');
         if Value > 65_535 then
            return Invalid_Port;
         end if;
      end loop;
      Port := Value;
      return SSH_Lib.Internal.Validate_Port (Port);
   exception
      when others =>
         Port := 0;
         return Invalid_Port;
   end Parse_Port;

   function Split_Host_Port
     (Text : String;
      Host : out Unbounded_String;
      Port : out Natural;
      Allow_Zero_Port : Boolean := False) return Status
   is
      Clean : constant String := Trim_Text (Text);
      Colon : constant Natural := Ada.Strings.Fixed.Index (Clean, ":");
      Status_Value : Status;
   begin
      Host := Null_Unbounded_String;
      Port := 0;
      if Colon = 0 or else Colon = Clean'First or else Colon = Clean'Last then
         return Invalid_Command;
      end if;
      declare
         Host_Text : constant String := Clean (Clean'First .. Colon - 1);
         Port_Text : constant String := Clean (Colon + 1 .. Clean'Last);
      begin
         if not SSH_Lib.Internal.Valid_Host (Host_Text) then
            return Invalid_Host;
         end if;
         Status_Value := Parse_Port (Port_Text, Port);
         if Status_Value = Invalid_Port and then Allow_Zero_Port then
            if Port_Text = "0" then
               Port := 0;
               Status_Value := Ok;
            end if;
         end if;
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         Host := To_Unbounded_String (Host_Text);
         return Ok;
      end;
   exception
      when others =>
         Host := Null_Unbounded_String;
         Port := 0;
         return Invalid_Command;
   end Split_Host_Port;

   function Environment_Name_Matches
     (Pattern : String;
      Name    : String)
      return Boolean
   is
      function Match_At (Pattern_Index : Natural; Name_Index : Natural) return Boolean is
      begin
         if Pattern_Index > Pattern'Last then
            return Name_Index > Name'Last;
         elsif Pattern (Pattern_Index) = '*' then
            return Match_At (Pattern_Index + 1, Name_Index)
              or else
                (Name_Index <= Name'Last
                 and then Match_At (Pattern_Index, Name_Index + 1));
         elsif Name_Index > Name'Last then
            return False;
         elsif Pattern (Pattern_Index) = '?'
           or else Pattern (Pattern_Index) = Name (Name_Index)
         then
            return Match_At (Pattern_Index + 1, Name_Index + 1);
         else
            return False;
         end if;
      end Match_At;
   begin
      if Pattern'Length = 0 or else Name'Length = 0 then
         return False;
      end if;
      return Match_At (Pattern'First, Name'First);
   exception
      when others =>
         return False;
   end Environment_Name_Matches;

   function Lower_Text (Text : String) return String is
      Result : String := Text;
   begin
      for Ch of Result loop
         if Ch in 'A' .. 'Z' then
            Ch := Character'Val
              (Character'Pos (Ch) - Character'Pos ('A') + Character'Pos ('a'));
         end if;
      end loop;
      return Result;
   end Lower_Text;

   function Short_Host_Name (Text : String) return String is
      Dot_Index : constant Natural := Ada.Strings.Fixed.Index (Text, ".");
   begin
      if Dot_Index = 0 then
         return Text;
      elsif Dot_Index = Text'First then
         return "";
      else
         return Text (Text'First .. Dot_Index - 1);
      end if;
   end Short_Host_Name;

   function To_Bytes (Text : String) return Ada.Streams.Stream_Element_Array is
      Result : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Text'Length));
   begin
      for Index in Text'Range loop
         Result
           (Ada.Streams.Stream_Element_Offset (Index - Text'First + 1)) :=
           Ada.Streams.Stream_Element (Character'Pos (Text (Index)));
      end loop;
      return Result;
   end To_Bytes;

   function Hex_Of (Digest : CryptoLib.Hashes.SHA1_Digest) return String is
      Hex    : constant String := "0123456789abcdef";
      Result : String (1 .. Digest'Length * 2);
      Cursor : Natural := Result'First;
      Value  : Natural;
   begin
      for Byte_Value of Digest loop
         Value := Natural (Byte_Value);
         Result (Cursor) := Hex (Value / 16 + 1);
         Result (Cursor + 1) := Hex (Value mod 16 + 1);
         Cursor := Cursor + 2;
      end loop;
      return Result;
   end Hex_Of;

   function Control_Master_Mode_Of
     (Options : SSH_Lib.Sessions.Session_Options)
      return Control_Master_Mode
   is
      Mode_Text : constant String :=
        Lower_Text (Trim_Text (To_String (Options.Control_Master)));
   begin
      if Mode_Text'Length = 0 then
         return Control_Master_Disabled;
      elsif Mode_Text = "no" or else Mode_Text = "false" then
         return Control_Master_No;
      elsif Mode_Text = "yes" or else Mode_Text = "true" then
         return Control_Master_Yes;
      elsif Mode_Text = "ask" then
         return Control_Master_Ask;
      elsif Mode_Text = "auto" then
         return Control_Master_Auto;
      elsif Mode_Text = "autoask" or else Mode_Text = "auto-ask" then
         return Control_Master_Auto_Ask;
      else
         return Control_Master_Invalid;
      end if;
   end Control_Master_Mode_Of;

   function Request_TTY_Mode_Of
     (Options : SSH_Lib.Sessions.Session_Options)
      return Request_TTY_Mode
   is
      Mode_Text : constant String :=
        Lower_Text (Trim_Text (To_String (Options.Request_TTY)));
   begin
      if Mode_Text'Length = 0
        or else Mode_Text = "auto"
      then
         return Request_TTY_Auto;
      elsif Mode_Text = "no" or else Mode_Text = "false" then
         return Request_TTY_No;
      elsif Mode_Text = "yes" or else Mode_Text = "true" then
         return Request_TTY_Yes;
      elsif Mode_Text = "force" then
         return Request_TTY_Force;
      else
         return Request_TTY_Invalid;
      end if;
   end Request_TTY_Mode_Of;

   function Session_Type_Mode_Of
     (Options : SSH_Lib.Sessions.Session_Options)
      return Session_Type_Mode
   is
      Mode_Text : constant String :=
        Lower_Text (Trim_Text (To_String (Options.Session_Type)));
   begin
      if Mode_Text'Length = 0
        or else Mode_Text = "default"
      then
         return Session_Type_Default;
      elsif Mode_Text = "none" then
         return Session_Type_None;
      elsif Mode_Text = "subsystem" then
         return Session_Type_Subsystem;
      else
         return Session_Type_Invalid;
      end if;
   end Session_Type_Mode_Of;

   function Expand_Control_Path
     (Options         : SSH_Lib.Sessions.Session_Options;
      Original_Host   : String;
      Local_Host_Name : String;
      Result          : out Unbounded_String)
      return Status
   is
      Template      : constant String := To_String (Options.Control_Path);
      Host_Text     : constant String := To_String (Options.Host);
      User_Text     : constant String := To_String (Options.User);
      Original_Text : constant String :=
        (if Original_Host'Length > 0 then Original_Host else Host_Text);
      Port_Text     : constant String :=
        Trim_Text (Natural'Image (Options.Port));
      Local_Text    : constant String :=
        (if Local_Host_Name'Length > 0 then Local_Host_Name else "localhost");
      Short_Local   : constant String := Short_Host_Name (Local_Text);
      Hash_Input    : constant String :=
        Local_Text & Host_Text & Port_Text & User_Text;
      Hash_Text     : constant String :=
        Hex_Of (CryptoLib.Hashes.SHA1 (To_Bytes (Hash_Input)));
      Cursor        : Natural := Template'First;
      Expanded      : Unbounded_String := Null_Unbounded_String;

      procedure Append_Token (Value : String) is
      begin
         Append (Expanded, Value);
      end Append_Token;
   begin
      Result := Null_Unbounded_String;
      if Template'Length = 0 then
         return Ok;
      elsif SSH_Lib.Internal.Has_Control_Break (Template)
        or else SSH_Lib.Internal.Has_Control_Break (Original_Host)
        or else SSH_Lib.Internal.Has_Control_Break (Local_Host_Name)
      then
         return Invalid_Command;
      end if;

      if Template (Template'First) = '~' then
         declare
            Home : constant String :=
              To_String (SSH_Lib.Internal.Home_Directory);
         begin
            if Home'Length = 0 then
               return No_Such_File;
            end if;
            Append_Token (Home);
            Cursor := Cursor + 1;
            if Cursor <= Template'Last and then Template (Cursor) = '/' then
               null;
            elsif Cursor <= Template'Last then
               return Unsupported_Feature;
            end if;
         end;
      end if;

      while Cursor <= Template'Last loop
         if Template (Cursor) /= '%' then
            Append (Expanded, Template (Cursor));
            Cursor := Cursor + 1;
         elsif Cursor = Template'Last then
            return Invalid_Command;
         else
            Cursor := Cursor + 1;
            case Template (Cursor) is
               when '%' =>
                  Append (Expanded, '%');
               when 'C' =>
                  Append_Token (Hash_Text);
               when 'h' =>
                  Append_Token (Host_Text);
               when 'n' =>
                  Append_Token (Original_Text);
               when 'p' =>
                  Append_Token (Port_Text);
               when 'r' =>
                  Append_Token (User_Text);
               when 'l' =>
                  Append_Token (Local_Text);
               when 'L' =>
                  Append_Token (Short_Local);
               when others =>
                  return Unsupported_Feature;
            end case;
            Cursor := Cursor + 1;
         end if;
      end loop;

      if SSH_Lib.Internal.Has_Control_Break (To_String (Expanded)) then
         return Invalid_Command;
      end if;
      Result := Expanded;
      return Ok;
   exception
      when others =>
         Result := Null_Unbounded_String;
         return Internal_Error;
   end Expand_Control_Path;

   function Control_Persist_Seconds
     (Options : SSH_Lib.Sessions.Session_Options;
      Seconds : out Natural)
      return Status
   is
      Text        : constant String :=
        Lower_Text (Trim_Text (To_String (Options.Control_Persist)));
      Cursor      : Natural := Text'First;
      Total       : Natural := 0;
      Value       : Natural := 0;
      Multiplier  : Natural := 1;
      Saw_Digit   : Boolean := False;
      Saw_Element : Boolean := False;

      function Add_Value return Status is
      begin
         if not Saw_Digit then
            return Invalid_Command;
         elsif Value > Natural'Last / Multiplier then
            return Unsupported_Feature;
         elsif Total > Natural'Last - Value * Multiplier then
            return Unsupported_Feature;
         end if;
         Total := Total + Value * Multiplier;
         Value := 0;
         Multiplier := 1;
         Saw_Digit := False;
         Saw_Element := True;
         return Ok;
      end Add_Value;

      Status_Value : Status;
   begin
      Seconds := 0;
      if Text'Length = 0 or else Text = "no" or else Text = "false" then
         return Ok;
      elsif Text = "yes" or else Text = "true" then
         Seconds := Natural'Last;
         return Ok;
      end if;

      while Cursor <= Text'Last loop
         if Text (Cursor) in '0' .. '9' then
            if Value > (Natural'Last - (Character'Pos (Text (Cursor)) - Character'Pos ('0'))) / 10 then
               return Unsupported_Feature;
            end if;
            Value :=
              Value * 10 + Character'Pos (Text (Cursor)) - Character'Pos ('0');
            Saw_Digit := True;
            Cursor := Cursor + 1;
         else
            case Text (Cursor) is
               when 's' =>
                  Multiplier := 1;
               when 'm' =>
                  Multiplier := 60;
               when 'h' =>
                  Multiplier := 60 * 60;
               when 'd' =>
                  Multiplier := 24 * 60 * 60;
               when 'w' =>
                  Multiplier := 7 * 24 * 60 * 60;
               when others =>
                  return Invalid_Command;
            end case;
            Status_Value := Add_Value;
            if Status_Value /= Ok then
               return Status_Value;
            end if;
            Cursor := Cursor + 1;
         end if;
      end loop;

      if Saw_Digit then
         Status_Value := Add_Value;
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      elsif not Saw_Element then
         return Invalid_Command;
      end if;

      Seconds := Total;
      return Ok;
   exception
      when others =>
         Seconds := 0;
      return Internal_Error;
   end Control_Persist_Seconds;

   function Plan_Control_Master
     (Options         : SSH_Lib.Sessions.Session_Options;
      Original_Host   : String;
      Local_Host_Name : String;
      Control_Path    : out Unbounded_String;
      Persist_Seconds : out Natural;
      Action          : out Control_Master_Action)
      return Status
   is
      Mode         : constant Control_Master_Mode :=
        Control_Master_Mode_Of (Options);
      Status_Value : Status;
      Path_Reusable : Boolean := False;

      function Control_Path_Reachable (Path_Text : String) return Boolean is
         Client        : SSH_Lib.Mux.Mux_Client;
         Response      : SSH_Lib.Mux.Mux_Message;
         Status_Value  : Status;
         Peer_Version   : Interfaces.Unsigned_32 := 0;
      begin
         if Path_Text'Length = 0
           or else not Ada.Directories.Exists (Path_Text)
         then
            return False;
         end if;

         Status_Value := SSH_Lib.Mux.Connect_Control (Path_Text, Client);
         if Status_Value /= Ok then
            SSH_Lib.Mux.Close (Client);
            return False;
         end if;

         Status_Value := SSH_Lib.Mux.Exchange_Hello (Client, Peer_Version);
         if Status_Value /= Ok then
            SSH_Lib.Mux.Close (Client);
            return False;
         end if;

         Status_Value := SSH_Lib.Mux.Alive_Check (Client, 1, Response);
         SSH_Lib.Mux.Close (Client);
         return Status_Value = Ok
           and then Response.Kind = SSH_Lib.Mux.Mux_Alive
           and then Response.Request_Id = 1;
      exception
         when others =>
            SSH_Lib.Mux.Close (Client);
            return False;
      end Control_Path_Reachable;
   begin
      Control_Path := Null_Unbounded_String;
      Persist_Seconds := 0;
      Action := Control_Master_Invalid_Action;

      case Mode is
         when Control_Master_Disabled | Control_Master_No =>
            Action := Control_Master_Do_Not_Use;
            return Ok;
         when Control_Master_Invalid =>
            return Invalid_Command;
         when others =>
            null;
      end case;

      Status_Value :=
        Expand_Control_Path
          (Options, Original_Host, Local_Host_Name, Control_Path);
      if Status_Value /= Ok then
         Action := Control_Master_Invalid_Action;
         return Status_Value;
      elsif Length (Control_Path) = 0 then
         Action := Control_Master_Invalid_Action;
         return Invalid_Command;
      end if;

      Status_Value := Control_Persist_Seconds (Options, Persist_Seconds);
      if Status_Value /= Ok then
         Action := Control_Master_Invalid_Action;
         return Status_Value;
      end if;

      Path_Reusable := Control_Path_Reachable (To_String (Control_Path));
      case Mode is
         when Control_Master_Yes | Control_Master_Auto =>
            Action :=
              (if Path_Reusable
               then Control_Master_Use_Existing
               else Control_Master_Start_Master);
         when Control_Master_Ask | Control_Master_Auto_Ask =>
            Action :=
              (if Path_Reusable
               then Control_Master_Use_Existing_Ask
               else Control_Master_Start_Master_Ask);
         when others =>
            Action := Control_Master_Invalid_Action;
            return Invalid_Command;
      end case;
      return Ok;
   exception
      when others =>
         Control_Path := Null_Unbounded_String;
         Persist_Seconds := 0;
         Action := Control_Master_Invalid_Action;
         return Internal_Error;
   end Plan_Control_Master;

   function Start_Planned_Control_Master
     (Options          : SSH_Lib.Sessions.Session_Options;
      Original_Host    : String;
      Local_Host_Name  : String;
      Master           : in out SSH_Lib.Mux.Mux_Master;
      Control_Path     : out Unbounded_String;
      Persist_Seconds  : out Natural;
      Action           : out Control_Master_Action;
      Replace_Existing : Boolean := False;
      Server_Pid       : Interfaces.Unsigned_32 := 0)
      return Status
   is
      Status_Value : Status;
   begin
      SSH_Lib.Mux.Close_Master (Master);
      Status_Value :=
        Plan_Control_Master
          (Options,
           Original_Host,
           Local_Host_Name,
           Control_Path,
           Persist_Seconds,
           Action);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      case Action is
         when Control_Master_Start_Master =>
            return SSH_Lib.Mux.Start_Master
              (To_String (Control_Path),
               Master,
               Replace_Existing => Replace_Existing,
               Persist_Seconds  => Persist_Seconds,
               Server_Pid       => Server_Pid);
         when Control_Master_Start_Master_Ask =>
            if Options.Control_Master_Approval_Callback = null
              or else not Options.Control_Master_Approval_Callback
                (To_String (Options.Host),
                 To_String (Options.User),
                 To_String (Control_Path),
                 True)
            then
               return Cancelled;
            end if;
            return SSH_Lib.Mux.Start_Master
              (To_String (Control_Path),
               Master,
               Replace_Existing => Replace_Existing,
               Persist_Seconds  => Persist_Seconds,
               Server_Pid       => Server_Pid);
         when others =>
            return Ok;
      end case;
   exception
      when others =>
         SSH_Lib.Mux.Close_Master (Master);
         Control_Path := Null_Unbounded_String;
         Persist_Seconds := 0;
         Action := Control_Master_Invalid_Action;
         return Internal_Error;
   end Start_Planned_Control_Master;

   function Expand_Local_Command
     (Options         : SSH_Lib.Sessions.Session_Options;
      Original_Host   : String;
      Local_Host_Name : String;
      Result          : out Unbounded_String)
      return Status
   is
      Template      : constant String := To_String (Options.Local_Command);
      Host_Text     : constant String := To_String (Options.Host);
      User_Text     : constant String := To_String (Options.User);
      Original_Text : constant String :=
        (if Original_Host'Length > 0 then Original_Host else Host_Text);
      Port_Text     : constant String :=
        Trim_Text (Natural'Image (Options.Port));
      Local_Text    : constant String :=
        (if Local_Host_Name'Length > 0 then Local_Host_Name else "localhost");
      Short_Local   : constant String := Short_Host_Name (Local_Text);
      Home_Text     : constant String :=
        To_String (SSH_Lib.Internal.Home_Directory);
      Cursor        : Natural := Template'First;
      Expanded      : Unbounded_String := Null_Unbounded_String;

      procedure Append_Token (Value : String) is
      begin
         Append (Expanded, Value);
      end Append_Token;
   begin
      Result := Null_Unbounded_String;
      if not Options.Permit_Local_Command or else Template'Length = 0 then
         return Ok;
      elsif SSH_Lib.Internal.Has_Control_Break (Template)
        or else SSH_Lib.Internal.Has_Control_Break (Original_Host)
        or else SSH_Lib.Internal.Has_Control_Break (Local_Host_Name)
      then
         return Invalid_Command;
      elsif Host_Text'Length = 0 or else User_Text'Length = 0 then
         return Invalid_Command;
      end if;

      while Cursor <= Template'Last loop
         if Template (Cursor) /= '%' then
            Append (Expanded, Template (Cursor));
            Cursor := Cursor + 1;
         elsif Cursor = Template'Last then
            return Invalid_Command;
         else
            Cursor := Cursor + 1;
            case Template (Cursor) is
               when '%' =>
                  Append (Expanded, '%');
               when 'd' =>
                  if Home_Text'Length = 0 then
                     return No_Such_File;
                  end if;
                  Append_Token (Home_Text);
               when 'h' =>
                  Append_Token (Host_Text);
               when 'n' =>
                  Append_Token (Original_Text);
               when 'p' =>
                  Append_Token (Port_Text);
               when 'r' =>
                  Append_Token (User_Text);
               when 'l' =>
                  Append_Token (Local_Text);
               when 'L' =>
                  Append_Token (Short_Local);
               when others =>
                  return Unsupported_Feature;
            end case;
            Cursor := Cursor + 1;
         end if;
      end loop;

      if SSH_Lib.Internal.Has_Control_Break (To_String (Expanded)) then
         return Invalid_Command;
      end if;
      Result := Expanded;
      return Ok;
   exception
      when others =>
         Result := Null_Unbounded_String;
         return Internal_Error;
   end Expand_Local_Command;

   function Expand_Known_Hosts_Command
     (Options         : SSH_Lib.Sessions.Session_Options;
      Original_Host   : String;
      Local_Host_Name : String;
      Reason          : String;
      Presented_Key   : SSH_Lib.Known_Hosts.Host_Key;
      Result          : out Unbounded_String)
      return Status
   is
      Template      : constant String := To_String (Options.Known_Hosts_Command);
      Host_Text     : constant String := To_String (Options.Host);
      User_Text     : constant String := To_String (Options.User);
      Original_Text : constant String :=
        (if Original_Host'Length > 0 then Original_Host else Host_Text);
      Port_Text     : constant String :=
        Trim_Text (Natural'Image (Options.Port));
      Local_Text    : constant String :=
        (if Local_Host_Name'Length > 0 then Local_Host_Name else "localhost");
      Short_Local   : constant String := Short_Host_Name (Local_Text);
      Cursor        : Natural := Template'First;
      Expanded      : Unbounded_String := Null_Unbounded_String;

      procedure Append_Token (Value : String) is
      begin
         Append (Expanded, Value);
      end Append_Token;

      function Append_Key_Fingerprint return Status is
         Fingerprint_Value : SSH_Lib.Keys.Fingerprint;
         Status_Value      : Status;
      begin
         Status_Value :=
           SSH_Lib.Known_Hosts.Fingerprint_With_Hash
             (Presented_Key,
              To_String (Options.Fingerprint_Hash),
              Fingerprint_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         Append_Token (SSH_Lib.Keys.Image (Fingerprint_Value));
         return Ok;
      end Append_Key_Fingerprint;

      Status_Value : Status;
   begin
      Result := Null_Unbounded_String;
      if Template'Length = 0 then
         return Ok;
      elsif SSH_Lib.Internal.Has_Control_Break (Template)
        or else SSH_Lib.Internal.Has_Control_Break (Original_Host)
        or else SSH_Lib.Internal.Has_Control_Break (Local_Host_Name)
        or else SSH_Lib.Internal.Has_Control_Break (Reason)
      then
         return Invalid_Command;
      elsif Host_Text'Length = 0 or else User_Text'Length = 0 then
         return Invalid_Command;
      end if;

      while Cursor <= Template'Last loop
         if Template (Cursor) /= '%' then
            Append (Expanded, Template (Cursor));
            Cursor := Cursor + 1;
         elsif Cursor = Template'Last then
            return Invalid_Command;
         else
            Cursor := Cursor + 1;
            case Template (Cursor) is
               when '%' =>
                  Append (Expanded, '%');
               when 'f' =>
                  Status_Value := Append_Key_Fingerprint;
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;
               when 'h' | 'H' =>
                  Append_Token (Host_Text);
               when 'I' =>
                  Append_Token (Reason);
               when 'K' =>
                  if SSH_Lib.Known_Hosts.Encoded (Presented_Key)'Length = 0 then
                     return Invalid_Command;
                  end if;
                  Append_Token (SSH_Lib.Known_Hosts.Encoded (Presented_Key));
               when 'l' =>
                  Append_Token (Local_Text);
               when 'L' =>
                  Append_Token (Short_Local);
               when 'n' =>
                  Append_Token (Original_Text);
               when 'p' =>
                  Append_Token (Port_Text);
               when 'r' =>
                  Append_Token (User_Text);
               when 't' =>
                  if SSH_Lib.Known_Hosts.Algorithm (Presented_Key)'Length = 0 then
                     return Invalid_Command;
                  end if;
                  Append_Token (SSH_Lib.Known_Hosts.Algorithm (Presented_Key));
               when others =>
                  return Unsupported_Feature;
            end case;
            Cursor := Cursor + 1;
         end if;
      end loop;

      if SSH_Lib.Internal.Has_Control_Break (To_String (Expanded)) then
         return Invalid_Command;
      end if;
      Result := Expanded;
      return Ok;
   exception
      when others =>
         Result := Null_Unbounded_String;
         return Internal_Error;
   end Expand_Known_Hosts_Command;

   function Next_Line
     (Text   : String;
      Cursor : in out Natural;
      Line   : out Unbounded_String) return Boolean
   is
      Start_Index : Natural;
      End_Index   : Natural;
   begin
      Line := Null_Unbounded_String;
      if Cursor > Text'Last then
         return False;
      end if;
      Start_Index := Cursor;
      End_Index := Start_Index;
      while End_Index <= Text'Last and then Text (End_Index) /= ASCII.LF loop
         End_Index := End_Index + 1;
      end loop;
      if End_Index > Start_Index then
         Line := To_Unbounded_String (Text (Start_Index .. End_Index - 1));
      end if;
      Cursor := End_Index + 1;
      return True;
   end Next_Line;

   function Start_Configured_Local_Forwards
     (Session  : in out SSH_Lib.Sessions.Session;
      Options  : SSH_Lib.Sessions.Session_Options;
      Services : in out Managed_Forward_Service_Array;
      Started  : out Natural)
      return Status
   is
      Text : constant String := To_String (Options.Local_Forwards);
      Cursor : Natural := Text'First;
      Line : Unbounded_String;
      Bind_Host : Unbounded_String;
      Target_Host : Unbounded_String;
      Bind_Port : Natural := 0;
      Target_Port : Natural := 0;
      Separator : Natural;
      Status_Value : Status;
   begin
      Started := 0;
      if Services'Length = 0 then
         return Invalid_Command;
      elsif Options.Clear_All_Forwardings or else Text'Length = 0 then
         return Ok;
      end if;

      while Next_Line (Text, Cursor, Line) loop
         declare
            Clean : constant String := Trim_Text (To_String (Line));
         begin
            if Clean'Length > 0 then
               if Started >= Services'Length then
                  return Unsupported_Feature;
               end if;
               Separator := Ada.Strings.Fixed.Index (Clean, " ");
               if Separator = 0 then
                  return Invalid_Command;
               end if;
               Status_Value :=
                 Split_Host_Port
                   (Clean (Clean'First .. Separator - 1),
                    Bind_Host,
                    Bind_Port,
                    Allow_Zero_Port => True);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Status_Value :=
                 Split_Host_Port
                   (Clean (Separator + 1 .. Clean'Last),
                    Target_Host,
                    Target_Port);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Status_Value :=
                 SSH_Lib.Forwarding.Start_Managed_Local_Forward_Service
                   (Session,
                    To_String (Bind_Host),
                    Bind_Port,
                    To_String (Target_Host),
                    Target_Port,
                    Services (Services'First + Started));
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Started := Started + 1;
            end if;
         end;
      end loop;
      return Ok;
   exception
      when others =>
         Started := 0;
         return Internal_Error;
   end Start_Configured_Local_Forwards;

   function Start_Configured_Dynamic_Forwards
     (Session  : in out SSH_Lib.Sessions.Session;
      Options  : SSH_Lib.Sessions.Session_Options;
      Services : in out Managed_Forward_Service_Array;
      Started  : out Natural)
      return Status
   is
      Text : constant String := To_String (Options.Dynamic_Forwards);
      Cursor : Natural := Text'First;
      Line : Unbounded_String;
      Bind_Host : Unbounded_String;
      Bind_Port : Natural := 0;
      Status_Value : Status;
   begin
      Started := 0;
      if Services'Length = 0 then
         return Invalid_Command;
      elsif Options.Clear_All_Forwardings or else Text'Length = 0 then
         return Ok;
      end if;

      while Next_Line (Text, Cursor, Line) loop
         declare
            Clean : constant String := Trim_Text (To_String (Line));
         begin
            if Clean'Length > 0 then
               if Started >= Services'Length then
                  return Unsupported_Feature;
               end if;
               Status_Value :=
                 Split_Host_Port
                   (Clean,
                    Bind_Host,
                    Bind_Port,
                    Allow_Zero_Port => True);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Status_Value :=
                 SSH_Lib.Forwarding.Start_Managed_Dynamic_Forward_Service
                   (Session,
                    To_String (Bind_Host),
                    Bind_Port,
                    Services (Services'First + Started));
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Started := Started + 1;
            end if;
         end;
      end loop;
      return Ok;
   exception
      when others =>
         Started := 0;
         return Internal_Error;
   end Start_Configured_Dynamic_Forwards;

   function Request_Configured_Remote_Forwards
     (Session     : in out SSH_Lib.Sessions.Session;
      Options     : SSH_Lib.Sessions.Session_Options;
      Bound_Ports : out Bound_Port_Array;
      Requested   : out Natural)
      return Status
   is
      Text : constant String := To_String (Options.Remote_Forwards);
      Cursor : Natural := Text'First;
      Line : Unbounded_String;
      Bind_Host : Unbounded_String;
      Bind_Port : Natural := 0;
      Target_Host : Unbounded_String;
      Target_Port : Natural := 0;
      Separator : Natural;
      Status_Value : Status;
   begin
      Bound_Ports := [others => 0];
      Requested := 0;
      if Bound_Ports'Length = 0 then
         return Invalid_Command;
      elsif Options.Clear_All_Forwardings or else Text'Length = 0 then
         return Ok;
      end if;

      while Next_Line (Text, Cursor, Line) loop
         declare
            Clean : constant String := Trim_Text (To_String (Line));
         begin
            if Clean'Length > 0 then
               if Requested >= Bound_Ports'Length then
                  return Unsupported_Feature;
               end if;
               Separator := Ada.Strings.Fixed.Index (Clean, " ");
               if Separator = 0 then
                  return Invalid_Command;
               end if;
               Status_Value :=
                 Split_Host_Port
                   (Clean (Clean'First .. Separator - 1),
                    Bind_Host,
                    Bind_Port,
                    Allow_Zero_Port => True);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Status_Value :=
                 Split_Host_Port
                   (Clean (Separator + 1 .. Clean'Last),
                    Target_Host,
                    Target_Port);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Status_Value :=
                 SSH_Lib.Sessions.Request_Remote_Forward
                   (Session,
                    To_String (Bind_Host),
                    Bind_Port,
                    Bound_Ports (Bound_Ports'First + Requested));
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Requested := Requested + 1;
            end if;
         end;
      end loop;
      return Ok;
   exception
      when others =>
         Bound_Ports := [others => 0];
         Requested := 0;
         return Internal_Error;
   end Request_Configured_Remote_Forwards;

   function Start_Configured_Remote_Forwards
     (Session     : in out SSH_Lib.Sessions.Session;
      Options     : SSH_Lib.Sessions.Session_Options;
      Services    : in out Managed_Forward_Service_Array;
      Bound_Ports : out Bound_Port_Array;
      Started     : out Natural)
      return Status
   is
      Text : constant String := To_String (Options.Remote_Forwards);
      Cursor : Natural := Text'First;
      Line : Unbounded_String;
      Bind_Host : Unbounded_String;
      Bind_Port : Natural := 0;
      Target_Host : Unbounded_String;
      Target_Port : Natural := 0;
      Separator : Natural;
      Status_Value : Status;
   begin
      Bound_Ports := [others => 0];
      Started := 0;
      if Services'Length = 0 or else Bound_Ports'Length = 0 then
         return Invalid_Command;
      elsif Options.Clear_All_Forwardings or else Text'Length = 0 then
         return Ok;
      end if;

      while Next_Line (Text, Cursor, Line) loop
         declare
            Clean : constant String := Trim_Text (To_String (Line));
         begin
            if Clean'Length > 0 then
               if Started >= Services'Length
                 or else Started >= Bound_Ports'Length
               then
                  return Unsupported_Feature;
               end if;
               Separator := Ada.Strings.Fixed.Index (Clean, " ");
               if Separator = 0 then
                  return Invalid_Command;
               end if;
               Status_Value :=
                 Split_Host_Port
                   (Clean (Clean'First .. Separator - 1),
                    Bind_Host,
                    Bind_Port,
                    Allow_Zero_Port => True);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Status_Value :=
                 Split_Host_Port
                   (Clean (Separator + 1 .. Clean'Last),
                    Target_Host,
                    Target_Port);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Status_Value :=
                 SSH_Lib.Forwarding.Start_Managed_Remote_Forward_Service
                   (Session,
                    To_String (Bind_Host),
                    Bind_Port,
                    To_String (Target_Host),
                    Target_Port,
                    Services (Services'First + Started));
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Bound_Ports (Bound_Ports'First + Started) :=
                 SSH_Lib.Forwarding.Managed_Forward_Service_Bound_Port
                   (Services (Services'First + Started));
               Started := Started + 1;
            end if;
         end;
      end loop;
      return Ok;
   exception
      when others =>
         Bound_Ports := [others => 0];
         Started := 0;
         return Internal_Error;
   end Start_Configured_Remote_Forwards;

   function Start_Configured_Forwards
     (Session          : in out SSH_Lib.Sessions.Session;
      Options          : SSH_Lib.Sessions.Session_Options;
      Local_Services   : in out Managed_Forward_Service_Array;
      Dynamic_Services : in out Managed_Forward_Service_Array;
      Remote_Services  : in out Managed_Forward_Service_Array;
      Remote_Ports     : out Bound_Port_Array;
      Local_Started    : out Natural;
      Dynamic_Started  : out Natural;
      Remote_Started   : out Natural)
      return Status
   is
      Status_Value : Status;
   begin
      Remote_Ports := [others => 0];
      Local_Started := 0;
      Dynamic_Started := 0;
      Remote_Started := 0;

      Status_Value :=
        Start_Configured_Local_Forwards
          (Session, Options, Local_Services, Local_Started);
      if Status_Value /= Ok and then Options.Exit_On_Forward_Failure then
         return Status_Value;
      end if;

      Status_Value :=
        Start_Configured_Dynamic_Forwards
          (Session, Options, Dynamic_Services, Dynamic_Started);
      if Status_Value /= Ok and then Options.Exit_On_Forward_Failure then
         return Status_Value;
      end if;

      Status_Value :=
        Start_Configured_Remote_Forwards
          (Session,
           Options,
           Remote_Services,
           Remote_Ports,
           Remote_Started);
      if Status_Value /= Ok and then Options.Exit_On_Forward_Failure then
         return Status_Value;
      end if;

      return Ok;
   exception
      when others =>
         Remote_Ports := [others => 0];
         Local_Started := 0;
         Dynamic_Started := 0;
         Remote_Started := 0;
         return Internal_Error;
   end Start_Configured_Forwards;

   function Apply_One_Environment_Token
     (Session : in out SSH_Lib.Sessions.Session;
      Channel : in out SSH_Lib.Channels.Channel;
      Token   : String;
      Is_Set  : Boolean) return Status
   is
      Equals_Index : constant Natural := Ada.Strings.Fixed.Index (Token, "=");
      Value : Unbounded_String;
   begin
      if Token'Length = 0 then
         return Ok;
      elsif Is_Set then
         if Equals_Index = 0 or else Equals_Index = Token'First then
            return Invalid_Command;
         end if;
         return SSH_Lib.Channels.Set_Environment
           (Session,
            Channel,
            Token (Token'First .. Equals_Index - 1),
            Token (Equals_Index + 1 .. Token'Last));
      else
         if Ada.Strings.Fixed.Index (Token, "*") /= 0
           or else Ada.Strings.Fixed.Index (Token, "?") /= 0
         then
            for Index in 1 .. SSH_Lib.Platform.Environment.Listed_Count loop
               declare
                  Name_Text : constant String :=
                    To_String (SSH_Lib.Platform.Environment.Listed_Name (Index));
               begin
                  if Name_Text'Length > 0
                    and then Environment_Name_Matches (Token, Name_Text)
                  then
                     Value :=
                       SSH_Lib.Platform.Environment.Listed_Value (Index);
                     if Length (Value) > 0 then
                        declare
                           Status_Value : constant Status :=
                             SSH_Lib.Channels.Set_Environment
                               (Session, Channel, Name_Text, To_String (Value));
                        begin
                           if Status_Value /= Ok then
                              return Status_Value;
                           end if;
                        end;
                     end if;
                  end if;
               end;
            end loop;
            return Ok;
         end if;
         Value := SSH_Lib.Platform.Environment.Getenv (Token);
         if Length (Value) = 0 then
            return Ok;
         end if;
         return SSH_Lib.Channels.Set_Environment
           (Session, Channel, Token, To_String (Value));
      end if;
   exception
      when others =>
         return Internal_Error;
   end Apply_One_Environment_Token;

   function Add_Configured_Environment
     (Environment : in out Configured_Environment_Array;
      Count       : in out Natural;
      Name        : String;
      Value       : String)
      return Status
   is
   begin
      if Name'Length = 0 then
         return Invalid_Command;
      elsif Value'Length = 0 then
         return Ok;
      end if;

      for Index in 1 .. Count loop
         if To_String (Environment (Index).Name) = Name then
            return Ok;
         end if;
      end loop;

      if Count >= Max_Configured_Environment then
         return Unsupported_Feature;
      end if;

      Count := Count + 1;
      Environment (Count).Name := To_Unbounded_String (Name);
      Environment (Count).Value := To_Unbounded_String (Value);
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Add_Configured_Environment;

   function Collect_One_Environment_Token
     (Environment : in out Configured_Environment_Array;
      Count       : in out Natural;
      Token       : String;
      Is_Set      : Boolean)
      return Status
   is
      Equals_Index : constant Natural := Ada.Strings.Fixed.Index (Token, "=");
      Value        : Unbounded_String;
      Status_Value : Status;
   begin
      if Token'Length = 0 then
         return Ok;
      elsif Is_Set then
         if Equals_Index = 0 or else Equals_Index = Token'First then
            return Invalid_Command;
         end if;
         return Add_Configured_Environment
           (Environment,
            Count,
            Token (Token'First .. Equals_Index - 1),
            Token (Equals_Index + 1 .. Token'Last));
      elsif Ada.Strings.Fixed.Index (Token, "*") /= 0
        or else Ada.Strings.Fixed.Index (Token, "?") /= 0
      then
         for Index in 1 .. SSH_Lib.Platform.Environment.Listed_Count loop
            declare
               Name_Text : constant String :=
                 To_String (SSH_Lib.Platform.Environment.Listed_Name (Index));
            begin
               if Name_Text'Length > 0
                 and then Environment_Name_Matches (Token, Name_Text)
               then
                  Status_Value :=
                    Add_Configured_Environment
                      (Environment,
                       Count,
                       Name_Text,
                       To_String
                         (SSH_Lib.Platform.Environment.Listed_Value (Index)));
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;
               end if;
            end;
         end loop;
         return Ok;
      else
         Value := SSH_Lib.Platform.Environment.Getenv (Token);
         return Add_Configured_Environment
           (Environment, Count, Token, To_String (Value));
      end if;
   exception
      when others =>
         return Internal_Error;
   end Collect_One_Environment_Token;

   function Collect_Environment_Text
     (Environment : in out Configured_Environment_Array;
      Count       : in out Natural;
      Text        : String;
      Is_Set      : Boolean)
      return Status
   is
      Cursor       : Natural := Text'First;
      Line         : Unbounded_String;
      Token_Start  : Natural;
      Token_End    : Natural;
      Status_Value : Status;
   begin
      if Text'Length = 0 then
         return Ok;
      end if;

      while Next_Line (Text, Cursor, Line) loop
         declare
            Clean : constant String := Trim_Text (To_String (Line));
         begin
            Token_Start := Clean'First;
            while Token_Start <= Clean'Last loop
               while Token_Start <= Clean'Last
                 and then Clean (Token_Start) = ' '
               loop
                  Token_Start := Token_Start + 1;
               end loop;
               exit when Token_Start > Clean'Last;
               Token_End := Token_Start;
               while Token_End <= Clean'Last and then Clean (Token_End) /= ' ' loop
                  Token_End := Token_End + 1;
               end loop;
               Status_Value :=
                 Collect_One_Environment_Token
                   (Environment,
                    Count,
                    Clean (Token_Start .. Token_End - 1),
                    Is_Set);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Token_Start := Token_End + 1;
            end loop;
         end;
      end loop;
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Collect_Environment_Text;

   function Apply_Environment_Text
     (Session : in out SSH_Lib.Sessions.Session;
      Channel : in out SSH_Lib.Channels.Channel;
      Text    : String;
      Is_Set  : Boolean) return Status
   is
      Cursor : Natural := Text'First;
      Line : Unbounded_String;
      Token_Start : Natural;
      Token_End : Natural;
      Status_Value : Status;
   begin
      if Text'Length = 0 then
         return Ok;
      end if;
      while Next_Line (Text, Cursor, Line) loop
         declare
            Clean : constant String := Trim_Text (To_String (Line));
         begin
            Token_Start := Clean'First;
            while Token_Start <= Clean'Last loop
               while Token_Start <= Clean'Last
                 and then Clean (Token_Start) = ' '
               loop
                  Token_Start := Token_Start + 1;
               end loop;
               exit when Token_Start > Clean'Last;
               Token_End := Token_Start;
               while Token_End <= Clean'Last and then Clean (Token_End) /= ' ' loop
                  Token_End := Token_End + 1;
               end loop;
               Status_Value :=
                 Apply_One_Environment_Token
                   (Session,
                    Channel,
                    Clean (Token_Start .. Token_End - 1),
                    Is_Set);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
               Token_Start := Token_End + 1;
            end loop;
         end;
      end loop;
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Apply_Environment_Text;

   function Apply_Configured_Environment
     (Session : in out SSH_Lib.Sessions.Session;
      Channel : in out SSH_Lib.Channels.Channel;
      Options : SSH_Lib.Sessions.Session_Options)
      return Status
   is
      Status_Value : Status;
   begin
      Status_Value :=
        Apply_Environment_Text
          (Session, Channel, To_String (Options.Set_Env), Is_Set => True);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      return Apply_Environment_Text
        (Session, Channel, To_String (Options.Send_Env), Is_Set => False);
   exception
      when others =>
         return Internal_Error;
   end Apply_Configured_Environment;

   function Open_Configured_Exec
     (Session         : in out SSH_Lib.Sessions.Session;
      Options         : SSH_Lib.Sessions.Session_Options;
      Default_Command : String;
      Channel         : in out SSH_Lib.Channels.Channel)
      return Status
   is
      Environment  : Configured_Environment_Array;
      Count        : Natural := 0;
      Status_Value : Status;
      Command_Text : constant String :=
        (if Length (Options.Remote_Command) > 0
         then To_String (Options.Remote_Command)
         else Default_Command);
      Session_Mode : constant Session_Type_Mode := Session_Type_Mode_Of (Options);
      TTY_Mode     : constant Request_TTY_Mode := Request_TTY_Mode_Of (Options);
   begin
      case Session_Mode is
         when Session_Type_Default =>
            null;
         when Session_Type_None =>
            return Ok;
         when Session_Type_Subsystem =>
            return Unsupported_Feature;
         when Session_Type_Invalid =>
            return Invalid_Command;
      end case;

      if TTY_Mode = Request_TTY_Invalid then
         return Invalid_Command;
      end if;

      Status_Value :=
        Collect_Environment_Text
          (Environment, Count, To_String (Options.Set_Env), Is_Set => True);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Collect_Environment_Text
          (Environment, Count, To_String (Options.Send_Env), Is_Set => False);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if TTY_Mode = Request_TTY_Yes or else TTY_Mode = Request_TTY_Force then
         Status_Value := SSH_Lib.Channels.Open_PTY_Exec_With_Environment
           (Session,
            Command_Text,
            Environment (1 .. Count),
            Channel);
      elsif Count = 0 then
         Status_Value :=
           SSH_Lib.Channels.Open_Exec (Session, Command_Text, Channel);
      else
         Status_Value := SSH_Lib.Channels.Open_Exec_With_Environment
           (Session,
            Command_Text,
            Environment (1 .. Count),
            Channel);
      end if;

      if Status_Value /= Ok or else not Options.Stdin_Null then
         return Status_Value;
      end if;
      return SSH_Lib.Channels.Send_EOF (Channel);
   exception
      when others =>
         return Internal_Error;
   end Open_Configured_Exec;

   function Open_Configured_Subsystem
     (Session           : in out SSH_Lib.Sessions.Session;
      Options           : SSH_Lib.Sessions.Session_Options;
      Default_Subsystem : String;
      Channel           : in out SSH_Lib.Channels.Channel)
      return Status
   is
      Environment    : Configured_Environment_Array;
      Count          : Natural := 0;
      Status_Value   : Status;
      Subsystem_Text : constant String :=
        (if Length (Options.Remote_Command) > 0
         then To_String (Options.Remote_Command)
         else Default_Subsystem);
      Session_Mode   : constant Session_Type_Mode :=
        Session_Type_Mode_Of (Options);
   begin
      case Session_Mode is
         when Session_Type_Default | Session_Type_Subsystem =>
            null;
         when Session_Type_None =>
            return Ok;
         when Session_Type_Invalid =>
            return Invalid_Command;
      end case;

      Status_Value :=
        Collect_Environment_Text
          (Environment, Count, To_String (Options.Set_Env), Is_Set => True);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Collect_Environment_Text
          (Environment, Count, To_String (Options.Send_Env), Is_Set => False);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Count = 0 then
         Status_Value := SSH_Lib.Channels.Open_Subsystem
           (Session, Subsystem_Text, Channel);
      else
         Status_Value := SSH_Lib.Channels.Open_Subsystem_With_Environment
           (Session,
            Subsystem_Text,
            Environment (1 .. Count),
            Channel);
      end if;

      if Status_Value /= Ok or else not Options.Stdin_Null then
         return Status_Value;
      end if;
      return SSH_Lib.Channels.Send_EOF (Channel);
   exception
      when others =>
         return Internal_Error;
   end Open_Configured_Subsystem;

   function Open_Configured_Shell
     (Session        : in out SSH_Lib.Sessions.Session;
      Options        : SSH_Lib.Sessions.Session_Options;
      Channel        : in out SSH_Lib.Channels.Channel;
      Terminal_Type  : String := "xterm";
      Columns        : Natural := 80;
      Rows           : Natural := 24;
      Width_Pixels   : Natural := 0;
      Height_Pixels  : Natural := 0;
      Terminal_Modes : SSH_Lib.Channels.Terminal_Mode_Array :=
        SSH_Lib.Channels.Empty_Terminal_Modes)
      return Status
   is
      Environment  : Configured_Environment_Array;
      Count        : Natural := 0;
      Status_Value : Status;
      TTY_Mode     : constant Request_TTY_Mode := Request_TTY_Mode_Of (Options);
      Session_Mode : constant Session_Type_Mode := Session_Type_Mode_Of (Options);
   begin
      case Session_Mode is
         when Session_Type_Default =>
            null;
         when Session_Type_None =>
            return Ok;
         when Session_Type_Subsystem =>
            return Unsupported_Feature;
         when Session_Type_Invalid =>
            return Invalid_Command;
      end case;

      if Length (Options.Remote_Command) > 0 then
         return Unsupported_Feature;
      end if;

      Status_Value :=
        Collect_Environment_Text
          (Environment, Count, To_String (Options.Set_Env), Is_Set => True);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Collect_Environment_Text
          (Environment, Count, To_String (Options.Send_Env), Is_Set => False);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      case TTY_Mode is
         when Request_TTY_Auto | Request_TTY_No =>
            if Count = 0 then
               Status_Value :=
                 SSH_Lib.Channels.Open_Shell (Session, Channel);
            else
               Status_Value := SSH_Lib.Channels.Open_Shell_With_Environment
                 (Session, Environment (1 .. Count), Channel);
            end if;
         when Request_TTY_Yes | Request_TTY_Force =>
            if Count = 0 then
               Status_Value := SSH_Lib.Channels.Open_PTY_Shell
                 (Session,
                  Channel,
                  Terminal_Type,
                  Columns,
                  Rows,
                  Width_Pixels,
                  Height_Pixels,
                  Terminal_Modes);
            else
               Status_Value := SSH_Lib.Channels.Open_PTY_Shell_With_Environment
                 (Session,
                  Environment (1 .. Count),
                  Channel,
                  Terminal_Type,
                  Columns,
                  Rows,
                  Width_Pixels,
                  Height_Pixels,
                  Terminal_Modes);
            end if;
         when Request_TTY_Invalid =>
            return Invalid_Command;
      end case;

      if Status_Value /= Ok or else not Options.Stdin_Null then
         return Status_Value;
      end if;
      return SSH_Lib.Channels.Send_EOF (Channel);
   exception
      when others =>
         return Internal_Error;
   end Open_Configured_Shell;
end SSH_Lib.Config_Apply;
