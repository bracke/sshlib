with Ada.Command_Line;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with CryptoLib.Errors;
with SSH_Lib.SFTP;
with SSH_Lib.Sessions;

procedure SFTP_V4_V6_Metadata is
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;

   Options      : SSH_Lib.Sessions.Session_Options;
   Session_Item : SSH_Lib.Sessions.Session;
   Client_Item  : SSH_Lib.SFTP.Client;
   Status_Value : CryptoLib.Errors.Status;
   Close_Status : CryptoLib.Errors.Status;
begin
   if Ada.Command_Line.Argument_Count < 5 then
      Ada.Text_IO.Put_Line
        ("usage: sftp_v4_v6_metadata HOST USER REMOTE_PATH MIME_TYPE OWNER:GROUP [IDENTITY_FILE]");
      return;
   end if;

   Options.Host := To_Unbounded_String (Ada.Command_Line.Argument (1));
   Options.User := To_Unbounded_String (Ada.Command_Line.Argument (2));
   Options.Verify_Known_Host := False;
   if Ada.Command_Line.Argument_Count >= 6 then
      Options.Identity_File := To_Unbounded_String (Ada.Command_Line.Argument (6));
   end if;

   Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
   if Status_Value /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line
        ("session open failed: " & CryptoLib.Errors.Status'Image (Status_Value));
      return;
   end if;

   Status_Value := SSH_Lib.SFTP.Open
     (Session_Item, Client_Item, SSH_Lib.SFTP.Maximum_Protocol_Version);
   if Status_Value = CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line
        ("negotiated SFTP version:" & Natural'Image (SSH_Lib.SFTP.Version (Client_Item)));
      Status_Value := SSH_Lib.SFTP.Set_Path_Mime_Type
        (Client_Item, Ada.Command_Line.Argument (3), Ada.Command_Line.Argument (4));
   end if;

   if Status_Value = CryptoLib.Errors.Ok then
      declare
         Owner_Group : constant String := Ada.Command_Line.Argument (5);
         Split       : Natural := 0;
      begin
         for Index in Owner_Group'Range loop
            if Owner_Group (Index) = ':' then
               Split := Index;
               exit;
            end if;
         end loop;
         if Split = 0 then
            Status_Value := CryptoLib.Errors.Invalid_Command;
         else
            Status_Value := SSH_Lib.SFTP.Set_Path_Owner_Group
              (Client_Item,
               Ada.Command_Line.Argument (3),
               Owner_Group (Owner_Group'First .. Split - 1),
               Owner_Group (Split + 1 .. Owner_Group'Last));
         end if;
      end;
   end if;

   Close_Status := SSH_Lib.SFTP.Close (Client_Item);
   if Close_Status = CryptoLib.Errors.Ok then
      Close_Status := SSH_Lib.Sessions.Close (Session_Item);
   end if;

   if Status_Value /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line
        ("metadata update failed: " & CryptoLib.Errors.Status'Image (Status_Value));
   elsif Close_Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line
        ("close failed: " & CryptoLib.Errors.Status'Image (Close_Status));
   else
      Ada.Text_IO.Put_Line ("metadata update complete");
   end if;
end SFTP_V4_V6_Metadata;
