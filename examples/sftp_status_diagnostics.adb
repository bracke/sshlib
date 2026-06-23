with Ada.Command_Line;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.SFTP;
with SSH_Lib.Sessions;

procedure SFTP_Status_Diagnostics is
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;

   Options      : SSH_Lib.Sessions.Session_Options;
   Session_Item : SSH_Lib.Sessions.Session;
   Result       : SSH_Lib.SFTP.SFTP_Result;
   Status_Value : CryptoLib.Errors.Status;
   Close_Status : CryptoLib.Errors.Status;
begin
   if Ada.Command_Line.Argument_Count < 3 then
      Ada.Text_IO.Put_Line
        ("usage: sftp_status_diagnostics HOST USER REMOTE_PATH [IDENTITY_FILE]");
      return;
   end if;

   Options.Host := To_Unbounded_String (Ada.Command_Line.Argument (1));
   Options.User := To_Unbounded_String (Ada.Command_Line.Argument (2));
   Options.Verify_Known_Host := False;
   if Ada.Command_Line.Argument_Count >= 4 then
      Options.Identity_File := To_Unbounded_String (Ada.Command_Line.Argument (4));
   end if;

   Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
   if Status_Value /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line
        ("session open failed: " & CryptoLib.Errors.Status'Image (Status_Value));
      return;
   end if;

   Status_Value := SSH_Lib.SFTP.Remove_File
     (Session_Item, Ada.Command_Line.Argument (3), Result);
   Close_Status := SSH_Lib.Sessions.Close (Session_Item);

   Ada.Text_IO.Put_Line
     ("operation: " & SSH_Lib.SFTP.SFTP_Operation'Image (Result.Operation));
   Ada.Text_IO.Put_Line
     ("status: " & CryptoLib.Errors.Status'Image (Status_Value));
   Ada.Text_IO.Put_Line
     ("remote code:" & Interfaces.Unsigned_32'Image (Result.Remote_Status_Code));
   Ada.Text_IO.Put_Line ("remote name: " & To_String (Result.Remote_Status_Name));
   Ada.Text_IO.Put_Line
     ("remote message: " & To_String (Result.Remote_Status_Message));
   Ada.Text_IO.Put_Line ("close: " & CryptoLib.Errors.Status'Image (Close_Status));
end SFTP_Status_Diagnostics;
