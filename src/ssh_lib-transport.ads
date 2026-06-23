with CryptoLib.Errors;

package SSH_Lib.Transport is
   type Transport_Handle is limited private;

   procedure Mark_Open
     (Item : in out Transport_Handle);

   procedure Mark_Dirty
     (Item   : in out Transport_Handle;
      Reason : CryptoLib.Errors.Status);

   function Close
     (Item : in out Transport_Handle)
      return CryptoLib.Errors.Status;

   function Is_Open
     (Item : Transport_Handle)
      return Boolean;

   function Is_Dirty
     (Item : Transport_Handle)
      return Boolean;

   function Last_Failure
     (Item : Transport_Handle)
      return CryptoLib.Errors.Status;

private
   type Transport_State is (Transport_Closed, Transport_Open, Transport_Dirty);

   type Transport_Handle is limited record
      Current_State : Transport_State := Transport_Closed;
      Failure       : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
   end record;
end SSH_Lib.Transport;
