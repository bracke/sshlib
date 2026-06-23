package body SSH_Lib.Protocol.Failure_State is
   use CryptoLib.Errors;

   function Session_Must_Be_Dirtied
     (Status_Value : CryptoLib.Errors.Status)
      return Boolean is
   begin
      case Status_Value is
         when Ok | End_Of_Stream | Invalid_Command | Channel_Open_Failed |
              Channel_Request_Failed | Remote_Exit_Nonzero |
              Host_Key_Unknown | Host_Key_Mismatch |
              Authentication_Failed | Unsupported_Feature =>
            return False;
         when others =>
            return True;
      end case;
   exception
      when others =>
         return True;
   end Session_Must_Be_Dirtied;

   function Channel_Must_Be_Dirtied
     (Status_Value : CryptoLib.Errors.Status;
      Partial_IO   : Boolean := False)
      return Boolean is
   begin
      if Partial_IO then
         return Status_Value /= Ok;
      end if;

      case Status_Value is
         when Ok | End_Of_Stream | Channel_Request_Failed |
              Remote_Exit_Nonzero | Unsupported_Feature =>
            return False;
         when others =>
            return True;
      end case;
   exception
      when others =>
         return True;
   end Channel_Must_Be_Dirtied;

   function Dirty_Session_Operation_Status
     (Default_Status : CryptoLib.Errors.Status := CryptoLib.Errors.Channel_Open_Failed)
      return CryptoLib.Errors.Status is
   begin
      if Default_Status = Ok or else Default_Status = End_Of_Stream then
         return Channel_Open_Failed;
      else
         return Default_Status;
      end if;
   exception
      when others =>
         return Channel_Open_Failed;
   end Dirty_Session_Operation_Status;

   function Dirty_Channel_Read_Status
     (Queued_Data_Available : Boolean)
      return CryptoLib.Errors.Status is
   begin
      if Queued_Data_Available then
         return Ok;
      else
         return Read_Failed;
      end if;
   exception
      when others =>
         return Read_Failed;
   end Dirty_Channel_Read_Status;

   function Dirty_Channel_Write_Status
      return CryptoLib.Errors.Status is
   begin
      return Write_Failed;
   end Dirty_Channel_Write_Status;

   function Dirty_Channel_Request_Status
      return CryptoLib.Errors.Status is
   begin
      return Channel_Request_Failed;
   end Dirty_Channel_Request_Status;
end SSH_Lib.Protocol.Failure_State;
