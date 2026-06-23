with Ada.Strings.Unbounded;
with Ada.Text_IO;
with SSH_Lib.Config;
with CryptoLib.Errors;
with SSH_Lib.Remote_Names;
with SSH_Lib.Sessions;

procedure Git_Remote_Resolve is
   use Ada.Strings.Unbounded;

   Remote_Text    : constant String := "ssh://git@example.com:22/repo.git";
   Remote_Status  : CryptoLib.Errors.Status;
   Resolve_Status : CryptoLib.Errors.Status;
   Remote_Item    : SSH_Lib.Remote_Names.Parsed_Remote;
   Config_Item    : constant SSH_Lib.Config.Host_Config := SSH_Lib.Config.Load_Default;
   Options_Item   : SSH_Lib.Sessions.Session_Options;
   use type CryptoLib.Errors.Status;
begin
   Remote_Status := SSH_Lib.Remote_Names.Parse (Remote_Text, Remote_Item);

   if Remote_Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line
        ("remote parse failed: " & CryptoLib.Errors.Status'Image (Remote_Status));
      return;
   end if;

   --  Use the text-aware resolver for version-shaped composition.  It keeps
   --  the distinction between an omitted ssh:// port and an explicit :22, so
   --  direct Remote_Names + Config callers get the same merge semantics as
   --  SSH_Lib.Git_Transport.Prepare.
   Resolve_Status := SSH_Lib.Config.Resolve_Remote
     (Config       => Config_Item,
      Remote_Text  => Remote_Text,
      Default_User => "git",
      Item         => Options_Item);

   if Resolve_Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line
        ("remote resolve failed: " & CryptoLib.Errors.Status'Image (Resolve_Status));
      return;
   end if;

   Ada.Text_IO.Put_Line ("remote host=" & SSH_Lib.Remote_Names.Host (Remote_Item));
   Ada.Text_IO.Put_Line ("connection host=" & To_String (Options_Item.Host));
   Ada.Text_IO.Put_Line ("user=" & To_String (Options_Item.User));
   Ada.Text_IO.Put_Line ("port=" & Natural'Image (Options_Item.Port));
   Ada.Text_IO.Put_Line
     ("explicit port=" &
      Boolean'Image (SSH_Lib.Remote_Names.Has_Explicit_Port (Remote_Text)));
   Ada.Text_IO.Put_Line
     ("repo=" & SSH_Lib.Remote_Names.Repository_Path (Remote_Item));
   Ada.Text_IO.Put_Line
     ("verify_known_host=" & Boolean'Image (Options_Item.Verify_Known_Host));
   Ada.Text_IO.Put_Line
     ("strict_host_key=" & Boolean'Image (Options_Item.Strict_Host_Key));
end Git_Remote_Resolve;
