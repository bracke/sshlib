with Ada.Strings.Unbounded;
with Ada.Text_IO;
with SSH_Lib.Config;
with CryptoLib.Errors;
with SSH_Lib.Git_Transport;
with SSH_Lib.Remote_Names;
with SSH_Lib.Sessions;

procedure Git_Remote_Prepare is
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;

   Remote_Text  : constant String := "git@github.example:owner/repo.git";
   Config_Item  : constant SSH_Lib.Config.Host_Config := SSH_Lib.Config.Load_Default;
   Options_Item : SSH_Lib.Sessions.Session_Options;
   Command_Item : Unbounded_String;
   Remote_Item  : SSH_Lib.Remote_Names.Parsed_Remote;
   Status_Value : CryptoLib.Errors.Status;
   Parse_Status : CryptoLib.Errors.Status;

   function Yes_No (Value : Boolean) return String is
   begin
      if Value then
         return "yes";
      else
         return "no";
      end if;
   end Yes_No;
begin
   Parse_Status := SSH_Lib.Remote_Names.Parse (Remote_Text, Remote_Item);
   Status_Value := SSH_Lib.Git_Transport.Prepare
     (Remote_Text  => Remote_Text,
      Config       => Config_Item,
      Default_User => "git",
      Requested    => SSH_Lib.Git_Transport.Upload_Pack,
      Options      => Options_Item,
      Command      => Command_Item);

   if Parse_Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line
        ("remote parse failed: " & CryptoLib.Errors.Status'Image (Parse_Status));
      return;
   end if;

   if Status_Value /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line
        ("prepare failed: " & CryptoLib.Errors.Status'Image (Status_Value));
      return;
   end if;

   Ada.Text_IO.Put_Line ("connection host: " & To_String (Options_Item.Host));
   Ada.Text_IO.Put_Line ("port: " & Natural'Image (Options_Item.Port));
   Ada.Text_IO.Put_Line ("user: " & To_String (Options_Item.User));
   Ada.Text_IO.Put_Line
     ("repository path: " & SSH_Lib.Remote_Names.Repository_Path (Remote_Item));
   Ada.Text_IO.Put_Line ("service command: " & To_String (Command_Item));
   Ada.Text_IO.Put_Line
     ("identity file configured: " & Yes_No (Length (Options_Item.Identity_File) /= 0));
   Ada.Text_IO.Put_Line
     ("agent enabled: " & Yes_No (Options_Item.Use_Agent));
   Ada.Text_IO.Put_Line
     ("host-key verification enabled: " & Yes_No (Options_Item.Verify_Known_Host));
end Git_Remote_Prepare;
