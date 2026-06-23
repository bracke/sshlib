
package body SSH_Lib.Transport.Wait is
   use CryptoLib.Errors;

   function Check_Readiness
     (Transport : in out SSH_Lib.Transport.Transport_Handle;
      Limit     : SSH_Lib.Deadlines.Deadline;
      Failure   : CryptoLib.Errors.Status := CryptoLib.Errors.Ok)
      return CryptoLib.Errors.Status is
   begin
      if Failure /= Ok then
         SSH_Lib.Transport.Mark_Dirty (Transport, Failure);
         return Failure;
      elsif SSH_Lib.Deadlines.Expired (Limit) then
         SSH_Lib.Transport.Mark_Dirty (Transport, Timeout);
         return Timeout;
      elsif not SSH_Lib.Transport.Is_Open (Transport) then
         return Connection_Failed;
      else
         return Ok;
      end if;
   exception
      when others =>
         SSH_Lib.Transport.Mark_Dirty (Transport, Internal_Error);
         return Internal_Error;
   end Check_Readiness;

   function Complete_Read
     (Transport    : in out SSH_Lib.Transport.Transport_Handle;
      Limit        : SSH_Lib.Deadlines.Deadline;
      Bytes_Read   : Natural;
      Failure      : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Partial_Read : Boolean := False)
      return CryptoLib.Errors.Status is
   begin
      if Failure /= Ok then
         if Partial_Read or else Bytes_Read > 0 then
            SSH_Lib.Transport.Mark_Dirty (Transport, Failure);
         end if;
         return Failure;
      elsif SSH_Lib.Deadlines.Expired (Limit) then
         if Partial_Read or else Bytes_Read > 0 then
            SSH_Lib.Transport.Mark_Dirty (Transport, Timeout);
         end if;
         return Timeout;
      elsif not SSH_Lib.Transport.Is_Open (Transport) then
         return Connection_Failed;
      else
         return Ok;
      end if;
   exception
      when others =>
         SSH_Lib.Transport.Mark_Dirty (Transport, Internal_Error);
         return Internal_Error;
   end Complete_Read;

   function Complete_Write
     (Transport     : in out SSH_Lib.Transport.Transport_Handle;
      Limit         : SSH_Lib.Deadlines.Deadline;
      Bytes_Written : Natural;
      Total_Bytes   : Natural;
      Failure       : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Partial_Write : Boolean := False)
      return CryptoLib.Errors.Status is
   begin
      if Failure /= Ok then
         if Partial_Write or else Bytes_Written > 0 then
            SSH_Lib.Transport.Mark_Dirty (Transport, Failure);
         end if;
         return Failure;
      elsif not SSH_Lib.Transport.Is_Open (Transport) then
         return Connection_Failed;
      elsif Bytes_Written = Total_Bytes then
         return Ok;
      elsif SSH_Lib.Deadlines.Expired (Limit) then
         if Partial_Write or else Bytes_Written > 0 then
            SSH_Lib.Transport.Mark_Dirty (Transport, Timeout);
         end if;
         return Timeout;
      else
         if Bytes_Written > 0 then
            SSH_Lib.Transport.Mark_Dirty (Transport, Write_Failed);
            return Write_Failed;
         else
            return Timeout;
         end if;
      end if;
   exception
      when others =>
         SSH_Lib.Transport.Mark_Dirty (Transport, Internal_Error);
         return Internal_Error;
   end Complete_Write;
end SSH_Lib.Transport.Wait;
