
package body SSH_Lib.Transport is
   use CryptoLib.Errors;

   procedure Mark_Open
     (Item : in out Transport_Handle) is
   begin
      Item.Current_State := Transport_Open;
      Item.Failure := Ok;
   exception
      when others =>
         Item.Current_State := Transport_Dirty;
         Item.Failure := Internal_Error;
   end Mark_Open;

   procedure Mark_Dirty
     (Item   : in out Transport_Handle;
      Reason : CryptoLib.Errors.Status) is
   begin
      Item.Current_State := Transport_Dirty;
      if Reason = Ok then
         Item.Failure := Internal_Error;
      else
         Item.Failure := Reason;
      end if;
   exception
      when others =>
         Item.Current_State := Transport_Dirty;
         Item.Failure := Internal_Error;
   end Mark_Dirty;

   function Close
     (Item : in out Transport_Handle)
      return CryptoLib.Errors.Status is
   begin
      Item.Current_State := Transport_Closed;
      Item.Failure := Ok;
      return Ok;
   exception
      when others =>
         Item.Current_State := Transport_Closed;
         Item.Failure := Internal_Error;
         return Ok;
   end Close;

   function Is_Open
     (Item : Transport_Handle)
      return Boolean is
   begin
      return Item.Current_State = Transport_Open;
   exception
      when others =>
         return False;
   end Is_Open;

   function Is_Dirty
     (Item : Transport_Handle)
      return Boolean is
   begin
      return Item.Current_State = Transport_Dirty;
   exception
      when others =>
         return True;
   end Is_Dirty;

   function Last_Failure
     (Item : Transport_Handle)
      return CryptoLib.Errors.Status is
   begin
      return Item.Failure;
   exception
      when others =>
         return Internal_Error;
   end Last_Failure;
end SSH_Lib.Transport;
