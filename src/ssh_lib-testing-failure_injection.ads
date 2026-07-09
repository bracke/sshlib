with CryptoLib.Errors;

--  @summary Deterministic fault-injection points for exercising SSH error paths in tests.
--
--  A Failure_Scenario names one protocol phase (Failure_Point) at which the
--  session machinery should return a chosen error status, optionally after a
--  partial read/write, so tests can drive each failure branch reproducibly.
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

   --  Return Item to the inert No_Failure state so no fault is injected.
   --  @param Item the scenario to clear
   procedure Reset (Item : out Failure_Scenario);

   --  Arm Item to fail at Point with the given status, optionally with partial I/O.
   --  @param Item         the scenario to configure
   --  @param Point        the protocol phase at which the failure should trigger
   --  @param Status_Value the error status to inject when Point is reached
   --  @param Partial_IO   when True, model a short (partial) read/write before failing
   procedure Configure
     (Item         : out Failure_Scenario;
      Point        : Failure_Point;
      Status_Value : CryptoLib.Errors.Status;
      Partial_IO   : Boolean := False);

   --  Return the phase at which Item is configured to fail.
   --  @param Item the scenario to query
   --  @return the configured Failure_Point (No_Failure if inert)
   function Active_Point (Item : Failure_Scenario) return Failure_Point;

   --  Return the error status Item will inject at its failure point.
   --  @param Item the scenario to query
   --  @return the configured injected status
   function Injected_Status (Item : Failure_Scenario) return CryptoLib.Errors.Status;

   --  Report whether Item models a partial read/write before failing.
   --  @param Item the scenario to query
   --  @return True if partial I/O is requested
   function Has_Partial_IO (Item : Failure_Scenario) return Boolean;

private
   type Failure_Scenario is record
      Point        : Failure_Point := No_Failure;
      Status_Value : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Partial_IO   : Boolean := False;
   end record;
end SSH_Lib.Testing.Failure_Injection;
