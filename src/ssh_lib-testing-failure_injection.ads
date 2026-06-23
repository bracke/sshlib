with CryptoLib.Errors;

package SSH_Lib.Testing.Failure_Injection is
   type Failure_Point is
     (No_Failure,
      Before_Connect,
      During_Identification_Read,
      During_Kex_Read,
      During_Userauth_Read,
      During_Channel_Open_Wait,
      During_Channel_Exec_Wait,
      During_Channel_Read,
      During_Channel_Write,
      During_Channel_EOF,
      During_Close);

   type Failure_Scenario is private;

   procedure Reset (Item : out Failure_Scenario);

   procedure Configure
     (Item         : out Failure_Scenario;
      Point        : Failure_Point;
      Status_Value : CryptoLib.Errors.Status;
      Partial_IO   : Boolean := False);

   function Active_Point (Item : Failure_Scenario) return Failure_Point;

   function Injected_Status (Item : Failure_Scenario) return CryptoLib.Errors.Status;

   function Has_Partial_IO (Item : Failure_Scenario) return Boolean;

private
   type Failure_Scenario is record
      Point        : Failure_Point := No_Failure;
      Status_Value : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Partial_IO   : Boolean := False;
   end record;
end SSH_Lib.Testing.Failure_Injection;
