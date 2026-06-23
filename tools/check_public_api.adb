with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Text_IO;

procedure Check_Public_API is
   use Ada.Strings.Fixed;

   Failure_Count : Natural := 0;

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   function File_Contains (Path : String; Needle : String) return Boolean is
      File_Item : Ada.Text_IO.File_Type;
   begin
      if not Ada.Directories.Exists (Path) then
         return False;
      end if;

      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
         begin
            if Index (Line_Text, Needle) /= 0 then
               Ada.Text_IO.Close (File_Item);
               return True;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
      return False;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return False;
   end File_Contains;

   procedure Require_File (Path : String) is
   begin
      if not Ada.Directories.Exists (Path) then
         Fail ("missing public API file: " & Path);
      end if;
   end Require_File;

   procedure Require_Text (Path : String; Needle : String) is
   begin
      if not File_Contains (Path, Needle) then
         Fail ("missing text in " & Path & ": " & Needle);
      end if;
   end Require_Text;

begin
   Require_File ("../cryptolib/src/cryptolib-errors.ads");
   Require_File ("src/ssh_lib-clients.ads");
   Require_File ("src/ssh_lib-sessions.ads");
   Require_File ("src/ssh_lib-channels.ads");
   Require_File ("src/ssh_lib-known_hosts.ads");
   Require_File ("src/ssh_lib-keys.ads");
   Require_File ("src/ssh_lib-config.ads");
   Require_File ("src/ssh_lib-git.ads");
   Require_File ("src/ssh_lib-remote_names.ads");
   Require_File ("src/ssh_lib-forwarding.ads");

   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "type Status is");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Ok,");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Host_Key_Unknown");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Host_Key_Mismatch");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Remote_Exit_Nonzero");

   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "End_Of_Stream");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Invalid_Host");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Invalid_Port");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Invalid_User");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Invalid_Command");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "DNS_Failed");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Connection_Failed");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Timeout");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Handshake_Failed");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Authentication_Failed");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Channel_Open_Failed");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Channel_Request_Failed");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Read_Failed");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Write_Failed");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Cancelled");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Unsupported_Feature");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "Internal_Error");
   Require_Text ("../cryptolib/src/cryptolib-errors.ads", "function Is_Success");

   Require_Text ("src/ssh_lib-clients.ads", "function Create return Client");

   Require_Text ("src/ssh_lib-sessions.ads", "type Session_Options is record");
   Require_Text ("src/ssh_lib-sessions.ads", "Port");
   Require_Text ("src/ssh_lib-sessions.ads", "Connect_Timeout_MS");
   Require_Text ("src/ssh_lib-sessions.ads", "Read_Timeout_MS");
   Require_Text ("src/ssh_lib-sessions.ads", "Write_Timeout_MS");
   Require_Text ("src/ssh_lib-sessions.ads", "Verify_Known_Host");
   Require_Text ("src/ssh_lib-sessions.ads", "Use_Agent");
   Require_Text ("src/ssh_lib-sessions.ads", "Strict_Host_Key");
   Require_Text ("src/ssh_lib-sessions.ads", "Use_Password");
   Require_Text ("src/ssh_lib-sessions.ads", "Password");
   Require_Text ("src/ssh_lib-sessions.ads", "Control_Master");
   Require_Text ("src/ssh_lib-sessions.ads", "Control_Path");
   Require_Text ("src/ssh_lib-sessions.ads", "Control_Persist");
   Require_Text ("src/ssh_lib-sessions.ads", "Local_Forwards");
   Require_Text ("src/ssh_lib-sessions.ads", "Remote_Forwards");
   Require_Text ("src/ssh_lib-sessions.ads", "Dynamic_Forwards");
   Require_Text ("src/ssh_lib-sessions.ads", "function Open");
   Require_Text ("src/ssh_lib-sessions.ads", "function Close");
   Require_Text ("src/ssh_lib-sessions.ads", "function Request_Remote_Forward");
   Require_Text ("src/ssh_lib-sessions.ads", "function Cancel_Remote_Forward");
   Require_Text ("src/ssh_lib-sessions.ads", "Last_Proxy_Command_Diagnostics");

   Require_Text ("src/ssh_lib-channels.ads", "Ada.Streams.Stream_Element_Array");
   Require_Text ("src/ssh_lib-channels.ads", "function Open_Exec");
   Require_Text ("src/ssh_lib-channels.ads", "function Open_Shell");
   Require_Text ("src/ssh_lib-channels.ads", "function Open_PTY_Shell");
   Require_Text ("src/ssh_lib-channels.ads", "function Resize_PTY");
   Require_Text ("src/ssh_lib-channels.ads", "type Terminal_Mode");
   Require_Text ("src/ssh_lib-channels.ads", "Terminal_Mode_Array");
   Require_Text ("src/ssh_lib-channels.ads", "function Open_Direct_TCPIP");
   Require_Text ("src/ssh_lib-channels.ads", "function Accept_Forwarded_TCPIP");
   Require_Text ("src/ssh_lib-channels.ads", "function Read_Some");
   Require_Text ("src/ssh_lib-channels.ads", "function Read_Stderr");
   Require_Text ("src/ssh_lib-channels.ads", "function Write");
   Require_Text ("src/ssh_lib-channels.ads", "function Send_EOF");
   Require_Text ("src/ssh_lib-channels.ads", "function Exit_Status");

   Require_Text ("src/ssh_lib-forwarding.ads", "type Local_Forward_Listener");
   Require_Text ("src/ssh_lib-forwarding.ads", "type Local_Forward_Connection");
   Require_Text ("src/ssh_lib-forwarding.ads", "type Forward_Service");
   Require_Text ("src/ssh_lib-forwarding.ads", "type Managed_Forward_Service");
   Require_Text ("src/ssh_lib-forwarding.ads", "type Forward_Service_Mode");
   Require_Text ("src/ssh_lib-forwarding.ads", "type Local_Forward_Handler");
   Require_Text ("src/ssh_lib-forwarding.ads", "type Dynamic_Forward_Handler");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Open_Local_Forward_Listener");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Open_Dynamic_Forward_Listener");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Start_Local_Forward_Service");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Start_Dynamic_Forward_Service");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Start_Managed_Local_Forward_Service");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Start_Managed_Dynamic_Forward_Service");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Forward_Service_Running");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Forward_Service_Status");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Forward_Service_Accepted_Count");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Forward_Service_Max_Accepted");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Forward_Service_Bound_Port");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Forward_Service_Kind");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Managed_Forward_Service_Running");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Managed_Forward_Service_Status");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Managed_Forward_Service_Accepted_Count");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Managed_Forward_Service_Completed_Count");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Managed_Forward_Service_Active_Count");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Managed_Forward_Service_Failed_Count");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Managed_Forward_Service_Max_Concurrent");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Managed_Forward_Service_Max_Accepted");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Managed_Forward_Service_Bound_Port");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Managed_Forward_Service_Kind");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Accept_Local_Forward");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Accept_Dynamic_Forward");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Read_Local");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Write_Local");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Pump_Once");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Pump_Bounded");
   Require_Text ("src/ssh_lib-forwarding.ads", "type Pump_Direction");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Bound_Port");
   Require_Text ("src/ssh_lib-forwarding.ads", "type SOCKS5_Target");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Parse_SOCKS5_CONNECT_Request");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Read_SOCKS5_CONNECT_Request");
   Require_Text ("src/ssh_lib-forwarding.ads", "function Send_SOCKS5_Reply");
   Require_Text ("src/ssh_lib-forwarding.ads", "function SOCKS5_Host");
   Require_Text ("src/ssh_lib-forwarding.ads", "function SOCKS5_Port");

   Require_Text ("src/ssh_lib-config_apply.ads", "package SSH_Lib.Config_Apply");
   Require_Text ("src/ssh_lib-config_apply.ads", "function Start_Configured_Local_Forwards");
   Require_Text ("src/ssh_lib-config_apply.ads", "function Start_Configured_Dynamic_Forwards");
   Require_Text ("src/ssh_lib-config_apply.ads", "function Request_Configured_Remote_Forwards");
   Require_Text ("src/ssh_lib-config_apply.ads", "function Apply_Configured_Environment");

   Require_Text ("src/ssh_lib-security_keys.ads", "package SSH_Lib.Security_Keys");
   Require_Text ("src/ssh_lib-security_keys.ads", "type Security_Key_Signer");
   Require_Text ("src/ssh_lib-security_keys.ads", "function Build_Signed_Request");

   Require_Text ("src/ssh_lib-git.ads", "function Upload_Pack_Command");
   Require_Text ("src/ssh_lib-git.ads", "function Receive_Pack_Command");
   Require_Text ("src/ssh_lib-remote_names.ads", "function Parse");
   Require_Text ("src/ssh_lib-remote_names.ads", "Has_Explicit_Port");
   Require_Text ("src/ssh_lib-config.ads", "function Load_Default");
   Require_Text ("src/ssh_lib-config.ads", "function Resolve");
   Require_Text ("src/ssh_lib-config.ads", "Remote_Text  : String");
   Require_Text ("src/ssh_lib-known_hosts.ads", "function Load");
   Require_Text ("src/ssh_lib-known_hosts.ads", "function Check");
   Require_Text ("src/ssh_lib-keys.ads", "function Load_Public_Identity");

   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("public API guard passed");
   else
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Public_API;
