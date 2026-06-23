package body SSH_Lib.Tests.Fixtures.Agent is

   procedure Start (Item : out Fixture; Mode : Response_Mode) is
   begin
      Item.Active_Mode := Mode;
   end Start;

   function Mode_Status (Mode : Response_Mode) return CryptoLib.Errors.Status is
   begin
      case Mode is
         when Identities_Available => return CryptoLib.Errors.Ok;
         when Failure_Response => return CryptoLib.Errors.Authentication_Failed;
         when Malformed_Response => return CryptoLib.Errors.Authentication_Failed;
         when Oversized_Response => return CryptoLib.Errors.Authentication_Failed;
         when Delayed_Response => return CryptoLib.Errors.Timeout;
      end case;
   end Mode_Status;

   function Request_Identities (Item : Fixture) return CryptoLib.Errors.Status is
   begin
      return Mode_Status (Item.Active_Mode);
   end Request_Identities;

   function Sign_Request
     (Item : Fixture;
      Data : Ada.Streams.Stream_Element_Array) return CryptoLib.Errors.Status
   is
      pragma Unreferenced (Data);
   begin
      return Mode_Status (Item.Active_Mode);
   end Sign_Request;
end SSH_Lib.Tests.Fixtures.Agent;
