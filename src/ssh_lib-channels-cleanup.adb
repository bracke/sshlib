with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

use type CryptoLib.Errors.Status;

package body SSH_Lib.Channels.Cleanup is
   procedure Mark_Failed
     (Item   : in out Channel;
      Reason : CryptoLib.Errors.Status) is
   begin
      Item.Dirty := True;
      Item.Current_State := Channel_Failed;
      if Reason = CryptoLib.Errors.Ok then
         Item.Last_Failure_Status := CryptoLib.Errors.Internal_Error;
      else
         Item.Last_Failure_Status := Reason;
      end if;
   exception
      when others =>
         Item.Dirty := True;
         Item.Current_State := Channel_Failed;
         Item.Last_Failure_Status := CryptoLib.Errors.Internal_Error;
   end Mark_Failed;

   function Close_Local
     (Item : in out Channel)
      return CryptoLib.Errors.Status is
   begin
      Item.Current_State := Channel_Closed;
      Item.Allocated := False;
      Item.Channel_Open_Confirmed := False;
      Item.Exec_Request_Confirmed := False;
      Item.Eof_Sent := False;
      Item.Eof_Received := False;
      Item.Close_Sent := True;
      Item.Close_Received := True;
      Item.Remote_Exit_Status_Known := False;
      Item.Remote_Exit_Status := 0;
      Item.Outbound_Data_Bytes := 0;
      Item.Outbound_Data_Packets := 0;
      Item.Dirty := False;
      Item.Test_Write_Timeout_After_Partial := False;
      Item.Test_Send_EOF_Timeout := False;
      SSH_Lib.Protocol.Buffers.Clear (Item.Pending_Stdout);
      SSH_Lib.Protocol.Buffers.Clear (Item.Pending_Stderr);
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_Channel_Data);
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_EOF);
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_Close);
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_Window_Adjust);
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_Channel_Success);
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_Channel_Failure);
      return CryptoLib.Errors.Ok;
   exception
      when others =>
         Item.Current_State := Channel_Closed;
         Item.Allocated := False;
         Item.Channel_Open_Confirmed := False;
         Item.Exec_Request_Confirmed := False;
         Item.Eof_Sent := False;
         Item.Eof_Received := False;
         Item.Close_Sent := True;
         Item.Close_Received := True;
         Item.Remote_Exit_Status_Known := False;
         Item.Remote_Exit_Status := 0;
         Item.Outbound_Data_Bytes := 0;
         Item.Outbound_Data_Packets := 0;
         Item.Dirty := False;
         return CryptoLib.Errors.Ok;
   end Close_Local;
end SSH_Lib.Channels.Cleanup;
