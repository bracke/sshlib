with Ada.Command_Line;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.SFTP;
with SSH_Lib.Sessions;

procedure SFTP_Check_File is
   use Ada.Strings.Unbounded;
   use type CryptoLib.Errors.Status;

   Options      : SSH_Lib.Sessions.Session_Options;
   Session_Item : SSH_Lib.Sessions.Session;
   Client_Item  : SSH_Lib.SFTP.Client;
   Algorithm    : Unbounded_String;
   Digest       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   Status_Value : CryptoLib.Errors.Status;
   Close_Status : CryptoLib.Errors.Status;
begin
   if Ada.Command_Line.Argument_Count < 3 then
      Ada.Text_IO.Put_Line
        ("usage: sftp_check_file HOST USER REMOTE_PATH [IDENTITY_FILE] [ALGORITHMS]");
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

   Status_Value := SSH_Lib.SFTP.Open
     (Session_Item, Client_Item, SSH_Lib.SFTP.Maximum_Protocol_Version);
   if Status_Value = CryptoLib.Errors.Ok then
      Status_Value := SSH_Lib.SFTP.Check_File
        (Client_Item,
         Ada.Command_Line.Argument (3),
         (if Ada.Command_Line.Argument_Count >= 5
          then Ada.Command_Line.Argument (5)
          else "sha1,sha256"),
         0,
         0,
         0,
         Algorithm,
         Digest);
   end if;

   Close_Status := SSH_Lib.SFTP.Close (Client_Item);
   if Close_Status = CryptoLib.Errors.Ok then
      Close_Status := SSH_Lib.Sessions.Close (Session_Item);
   end if;

   if Status_Value = CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("algorithm: " & To_String (Algorithm));
      Ada.Text_IO.Put_Line
        ("digest bytes:" & Natural'Image (SSH_Lib.Protocol.Buffers.Length (Digest)));
   elsif Status_Value = CryptoLib.Errors.Unsupported_Feature then
      Ada.Text_IO.Put_Line ("check-file unsupported by server");
   else
      Ada.Text_IO.Put_Line
        ("check-file failed: " & CryptoLib.Errors.Status'Image (Status_Value));
   end if;

   if Close_Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line
        ("close failed: " & CryptoLib.Errors.Status'Image (Close_Status));
   end if;
end SFTP_Check_File;
