with SSH_Lib.Deadlines;
with CryptoLib.Errors;

package SSH_Lib.Transport.Wait is
   function Check_Readiness
     (Transport : in out SSH_Lib.Transport.Transport_Handle;
      Limit     : SSH_Lib.Deadlines.Deadline;
      Failure   : CryptoLib.Errors.Status := CryptoLib.Errors.Ok)
      return CryptoLib.Errors.Status;

   function Complete_Read
     (Transport    : in out SSH_Lib.Transport.Transport_Handle;
      Limit        : SSH_Lib.Deadlines.Deadline;
      Bytes_Read   : Natural;
      Failure      : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Partial_Read : Boolean := False)
      return CryptoLib.Errors.Status;

   function Complete_Write
     (Transport     : in out SSH_Lib.Transport.Transport_Handle;
      Limit         : SSH_Lib.Deadlines.Deadline;
      Bytes_Written : Natural;
      Total_Bytes   : Natural;
      Failure       : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Partial_Write : Boolean := False)
      return CryptoLib.Errors.Status;
end SSH_Lib.Transport.Wait;
