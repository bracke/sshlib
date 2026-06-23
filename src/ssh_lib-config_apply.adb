with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with SSH_Lib.Internal;
with SSH_Lib.Platform.Environment;

package body SSH_Lib.Config_Apply is
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;

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
      elsif Text'Length = 0 then
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
      elsif Text'Length = 0 then
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
      elsif Text'Length = 0 then
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
            return Unsupported_Feature;
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
end SSH_Lib.Config_Apply;
