with CryptoLib.Errors;

use type CryptoLib.Errors.Status;

package body SSH_Lib.Testing.Failure_Injection is
   procedure Reset (Item : out Failure_Scenario) is
   begin
      Item.Point := No_Failure;
      Item.Status_Value := CryptoLib.Errors.Ok;
      Item.Partial_IO := False;
   end Reset;

   procedure Configure
     (Item         : out Failure_Scenario;
      Point        : Failure_Point;
      Status_Value : CryptoLib.Errors.Status;
      Partial_IO   : Boolean := False)
   is
   begin
      Item.Point := Point;
      if Point = No_Failure then
         Item.Status_Value := CryptoLib.Errors.Ok;
         Item.Partial_IO := False;
      elsif Status_Value = CryptoLib.Errors.Ok then
         Item.Status_Value := CryptoLib.Errors.Internal_Error;
         Item.Partial_IO := Partial_IO;
      else
         Item.Status_Value := Status_Value;
         Item.Partial_IO := Partial_IO;
      end if;
   exception
      when others =>
         Item.Point := During_Close;
         Item.Status_Value := CryptoLib.Errors.Internal_Error;
         Item.Partial_IO := True;
   end Configure;

   function Active_Point (Item : Failure_Scenario) return Failure_Point is
   begin
      return Item.Point;
   exception
      when others =>
         return During_Close;
   end Active_Point;

   function Injected_Status (Item : Failure_Scenario) return CryptoLib.Errors.Status is
   begin
      return Item.Status_Value;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Injected_Status;

   function Has_Partial_IO (Item : Failure_Scenario) return Boolean is
   begin
      return Item.Partial_IO;
   exception
      when others =>
         return True;
   end Has_Partial_IO;
end SSH_Lib.Testing.Failure_Injection;
