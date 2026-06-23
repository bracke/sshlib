with Ada.Calendar;
with Ada.Strings.Unbounded;
with SSH_Lib.Sessions.Channel_Table;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Protected_Packets;
with SSH_Lib.Sessions.Live_Attachment;
with System;

package body SSH_Lib.Sessions.Close_Pipeline is
   use Ada.Strings.Unbounded;

   procedure Scrub_Credentials (Options : in out Session_Options) is
   begin
      Options.Password := Null_Unbounded_String;
      Options.Identity_Passphrase := Null_Unbounded_String;
      Options.Password_Callback := null;
      Options.Identity_Passphrase_Callback := null;
      Options.Password_Change_Callback := null;
      Options.Keyboard_Interactive_Callback := null;
   end Scrub_Credentials;

   procedure Reset_To_Closed
     (Item         : in out Session;
      Status_Value : CryptoLib.Errors.Status) is
   begin
      SSH_Lib.Sessions.Live_Attachment.Close_Attached (Item);
      Item.Current_State := Closed;
      Item.Transport_Connected := False;
      Item.Identification_Complete := False;
      Item.Kexinit_Exchanged := False;
      Item.Algorithms_Negotiated := False;
      Item.Kex_Complete := False;
      Item.Keys_Derived := False;
      Item.Newkeys_Sent := False;
      Item.Newkeys_Received := False;
      Item.Encrypted_Outbound_Active := False;
      Item.Encrypted_Inbound_Active := False;
      Item.Host_Key_Signature_Verified := False;
      Item.Known_Host_Trusted := False;
      Item.Known_Host_Bypassed_Explicitly := False;
      Item.Userauth_Service_Accepted := False;
      Item.User_Authenticated := False;
      Item.Session_Open := False;
      Item.Session_Closed := True;
      Item.Failure_Status := Status_Value;
      Item.Session_Dirty := False;
      Item.Last_Operation_Cancelled := False;
      Item.Authenticated_User_Name := Null_Unbounded_String;
      Item.Authentication_Method_Used := No_Authentication_Method;
      --  Do not retain explicit password material in private session state
      --  across close/failure paths.  The public Options argument remains the
      --  caller's responsibility; the session object keeps only non-secret
      --  routing/auth policy state.
      Scrub_Credentials (Item.Stored_Options);
      SSH_Lib.Sessions.Channel_Table.Reset (Item);
      SSH_Lib.Protocol.Buffers.Clear (Item.Test_Channel_Open_Response);
      SSH_Lib.Protocol.Buffers.Clear (Item.Test_Channel_Exec_Response);
      SSH_Lib.Protocol.Buffers.Clear (Item.Test_Global_Response);
      SSH_Lib.Protocol.Buffers.Clear (Item.Test_Inbound_Forwarded_Open);
      SSH_Lib.Protocol.Buffers.Clear (Item.Test_Last_Channel_Open);
      SSH_Lib.Protocol.Buffers.Clear (Item.Test_Last_Exec_Request);
      Item.Live_Channel_IO_Enabled := False;
      Item.Live_Transcript_Address := System.Null_Address;
      Item.Live_Transcript_Attached := False;
      SSH_Lib.Protocol.Buffers.Clear (Item.Live_Session_Identifier);
      Item.Live_Rekey_Count := 0;
      Item.Live_Packets_Since_Rekey := 0;
      Item.Live_Bytes_Since_Rekey := 0;
      Item.Live_Rekey_Started := Ada.Calendar.Clock;
      Item.Live_Rekey_In_Progress := False;
      SSH_Lib.Protocol.Protected_Packets.Reset
        (Item.Live_Open_Protected_State, [1 .. 32 => 0]);
      SSH_Lib.Protocol.Buffers.Clear (Item.Live_Last_Protected_Channel);
      SSH_Lib.Protocol.Buffers.Clear (Item.Live_Last_Plain_Channel);
      Item.Live_Userauth_IO_Enabled := False;
      SSH_Lib.Protocol.Protected_Packets.Reset
        (Item.Live_Userauth_Protected_State, [1 .. 32 => 0]);
      SSH_Lib.Protocol.Buffers.Clear (Item.Live_Last_Protected_Userauth);
      SSH_Lib.Protocol.Buffers.Clear (Item.Live_Last_Plain_Userauth);
      SSH_Lib.Protocol.Buffers.Clear (Item.Live_Last_Protected_Userauth_Response);
      SSH_Lib.Protocol.Buffers.Clear (Item.Live_Last_Plain_Userauth_Response);
      SSH_Lib.Protocol.Buffers.Clear (Item.Live_Last_Protected_Service);
      SSH_Lib.Protocol.Buffers.Clear (Item.Live_Last_Plain_Service);
      SSH_Lib.Protocol.Buffers.Clear (Item.Live_Last_Protected_Service_Response);
      SSH_Lib.Protocol.Buffers.Clear (Item.Live_Last_Plain_Service_Response);
      SSH_Lib.Protocol.Buffers.Clear (Item.Live_Last_Agent_Sign_Request);
      SSH_Lib.Protocol.Buffers.Clear (Item.Live_Last_Agent_Sign_Response);
      SSH_Lib.Protocol.Buffers.Clear (Item.Test_Userauth_Response);
      Item.Test_Has_Open_Response := False;
      Item.Test_Has_Exec_Response := False;
      Item.Test_Has_Global_Response := False;
      Item.Test_Has_Inbound_Forwarded_Open := False;
      Item.Test_Write_Fails := False;
      Item.Test_Read_Open_Fails := False;
      Item.Test_Read_Exec_Fails := False;
      Item.Test_Open_Timeout := False;
      Item.Test_Exec_Timeout := False;
      Item.Test_Open_Cancelled := False;
      Item.Test_Exec_Cancelled := False;
      Item.Test_Partial_Channel_Write_Fails := False;
      Item.Test_Exec_Write_Timeout := False;
   end Reset_To_Closed;
end SSH_Lib.Sessions.Close_Pipeline;
