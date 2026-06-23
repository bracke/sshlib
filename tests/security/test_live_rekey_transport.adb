with Ada.Environment_Variables;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with SSH_Lib.Channels;
with CryptoLib.Errors;
with SSH_Lib.Git;
with SSH_Lib.Sessions;

procedure Test_Live_Rekey_Transport is
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;

   function Env (Name_Text : String; Default_Text : String := "") return String is
   begin
      if Ada.Environment_Variables.Exists (Name_Text) then
         return Ada.Environment_Variables.Value (Name_Text);
      end if;
      return Default_Text;
   end Env;

   procedure Require_Ok (Where_Text : String; Status_Value : Status) is
   begin
      if Status_Value /= Ok then
         Ada.Text_IO.Put_Line
           ("FAIL live rekey transport: " & Where_Text
            & " returned " & Status'Image (Status_Value));
         raise Program_Error;
      end if;
   end Require_Ok;

   Enabled : constant Boolean := Env ("SSH_LIB_LIVE_REKEY") = "1";
   Options : SSH_Lib.Sessions.Session_Options;
   Session_Item : SSH_Lib.Sessions.Session;
   Channel_Item : SSH_Lib.Channels.Channel;
   Buffer : Ada.Streams.Stream_Element_Array (1 .. 8192);
   Last : Ada.Streams.Stream_Element_Offset;
   Exit_Code : Integer := 0;
   Command_Text : Unbounded_String;
   Status_Value : Status;
begin
   if not Enabled then
      Ada.Text_IO.Put_Line
        ("SKIP live rekey transport: set SSH_LIB_LIVE_REKEY=1 to enable");
      return;
   end if;

   Options.Host := To_Unbounded_String (Env ("SSH_LIB_LIVE_REKEY_HOST"));
   Options.User := To_Unbounded_String (Env ("SSH_LIB_LIVE_REKEY_USER"));
   Options.Known_Hosts_File :=
     To_Unbounded_String (Env ("SSH_LIB_LIVE_REKEY_KNOWN_HOSTS"));
   Options.Identity_File := To_Unbounded_String (Env ("SSH_LIB_LIVE_REKEY_IDENTITY"));
   Options.Proxy_Jump := To_Unbounded_String (Env ("SSH_LIB_LIVE_REKEY_PROXY_JUMP"));
   Options.Verify_Known_Host := True;
   Options.Strict_Host_Key := True;

   if Env ("SSH_LIB_LIVE_REKEY_PASSWORD")'Length > 0 then
      Options.Use_Password := True;
      Options.Password := To_Unbounded_String (Env ("SSH_LIB_LIVE_REKEY_PASSWORD"));
   end if;

   if Env ("SSH_LIB_LIVE_REKEY_IDENTITY_PASSPHRASE")'Length > 0 then
      Options.Use_Identity_Passphrase := True;
      Options.Identity_Passphrase :=
        To_Unbounded_String (Env ("SSH_LIB_LIVE_REKEY_IDENTITY_PASSPHRASE"));
   end if;

   Command_Text := To_Unbounded_String (Env ("SSH_LIB_LIVE_REKEY_COMMAND"));
   if Length (Command_Text) = 0 then
      Command_Text := To_Unbounded_String
        (SSH_Lib.Git.Upload_Pack_Command (Env ("SSH_LIB_LIVE_REKEY_REPO")));
   end if;

   Require_Ok ("Sessions.Open", SSH_Lib.Sessions.Open (Options, Session_Item));

   --  The first explicit rekey proves the authenticated protected transport
   --  can repeat KEX while preserving the original SSH session identifier.
   Require_Ok ("Sessions.Rekey before exec", SSH_Lib.Sessions.Rekey (Session_Item));

   Require_Ok
     ("Channels.Open_Exec",
      SSH_Lib.Channels.Open_Exec
        (Session_Item, To_String (Command_Text), Channel_Item));

   --  A second rekey while a channel exists proves the live channel path keeps
   --  using the retained transcript after keys are replaced.
   Require_Ok ("Sessions.Rekey after exec", SSH_Lib.Sessions.Rekey (Session_Item));

   Status_Value := SSH_Lib.Channels.Send_EOF (Channel_Item);
   if Status_Value /= Ok and then Status_Value /= End_Of_Stream then
      Require_Ok ("Channels.Send_EOF", Status_Value);
   end if;

   loop
      Status_Value := SSH_Lib.Channels.Read_Some (Channel_Item, Buffer, Last);
      exit when Status_Value = End_Of_Stream;
      Require_Ok ("Channels.Read_Some", Status_Value);
   end loop;

   Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
   if Status_Value /= Ok and then Status_Value /= Channel_Request_Failed then
      Require_Ok ("Channels.Exit_Status", Status_Value);
   end if;

   Require_Ok ("Channels.Close", SSH_Lib.Channels.Close (Channel_Item));
   Require_Ok ("Sessions.Close", SSH_Lib.Sessions.Close (Session_Item));
   Ada.Text_IO.Put_Line ("PASS live rekey transport");
exception
   when others =>
      declare
         Ignored_Close : constant Status := SSH_Lib.Sessions.Close (Session_Item);
      begin
         null;
      end;
      raise;
end Test_Live_Rekey_Transport;
