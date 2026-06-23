with Ada.Streams;
with CryptoLib.Errors;

package SSH_Lib.Tests.Fixtures.Agent is
   type Response_Mode is
     (Identities_Available,
      Failure_Response,
      Malformed_Response,
      Oversized_Response,
      Delayed_Response);

   type Fixture is private;

   procedure Start (Item : out Fixture; Mode : Response_Mode);
   function Request_Identities (Item : Fixture) return CryptoLib.Errors.Status;
   function Sign_Request
     (Item : Fixture;
      Data : Ada.Streams.Stream_Element_Array) return CryptoLib.Errors.Status;
private
   type Fixture is record
      Active_Mode : Response_Mode := Failure_Response;
   end record;
end SSH_Lib.Tests.Fixtures.Agent;
