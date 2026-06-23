with CryptoLib.Errors;

package SSH_Lib.Protocol.Failure_State is
   function Session_Must_Be_Dirtied
     (Status_Value : CryptoLib.Errors.Status)
      return Boolean;

   function Channel_Must_Be_Dirtied
     (Status_Value : CryptoLib.Errors.Status;
      Partial_IO   : Boolean := False)
      return Boolean;

   function Dirty_Session_Operation_Status
     (Default_Status : CryptoLib.Errors.Status := CryptoLib.Errors.Channel_Open_Failed)
      return CryptoLib.Errors.Status;

   function Dirty_Channel_Read_Status
     (Queued_Data_Available : Boolean)
      return CryptoLib.Errors.Status;

   function Dirty_Channel_Write_Status
      return CryptoLib.Errors.Status;

   function Dirty_Channel_Request_Status
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Failure_State;
