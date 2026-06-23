with Ada.Command_Line;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.SFTP;
with SSH_Lib.Sessions;

procedure SFTP_Upload_Download is
   use Ada.Strings.Unbounded;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.Errors.Status;

   function Bytes (Text : String) return Ada.Streams.Stream_Element_Array is
      Result : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Text'Length));
      Cursor : Ada.Streams.Stream_Element_Offset := Result'First;
   begin
      for Character_Item of Text loop
         Result (Cursor) := Ada.Streams.Stream_Element (Character'Pos (Character_Item));
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end Bytes;

   Options      : SSH_Lib.Sessions.Session_Options;
   Session_Item : SSH_Lib.Sessions.Session;
   Data         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   Status_Value : CryptoLib.Errors.Status;
   Close_Status : CryptoLib.Errors.Status;
begin
   if Ada.Command_Line.Argument_Count < 3 then
      Ada.Text_IO.Put_Line
        ("usage: sftp_upload_download HOST USER REMOTE_PATH [IDENTITY_FILE]");
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

   Status_Value := SSH_Lib.SFTP.Upload_Data
     (Session_Item,
      Ada.Command_Line.Argument (3),
      Bytes ("hello from SSH_Lib SFTP" & Character'Val (10)),
      "0644");
   if Status_Value = CryptoLib.Errors.Ok then
      Status_Value := SSH_Lib.SFTP.Download_Data
        (Session_Item, Ada.Command_Line.Argument (3), Data);
   end if;

   Close_Status := SSH_Lib.Sessions.Close (Session_Item);
   if Status_Value /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line
        ("transfer failed: " & CryptoLib.Errors.Status'Image (Status_Value));
   elsif Close_Status /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line
        ("session close failed: " & CryptoLib.Errors.Status'Image (Close_Status));
   else
      Ada.Text_IO.Put_Line
        ("downloaded bytes:" &
         Natural'Image (SSH_Lib.Protocol.Buffers.To_Array (Data)'Length));
   end if;
end SFTP_Upload_Download;
