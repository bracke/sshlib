with Ada.Text_IO;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Negative_Tests;
with SSH_Lib.Tests.Fixtures.Exception_Containment;

procedure Test_Exception_Mapping is
   use type CryptoLib.Errors.Status;
   type Case_Array is array (Positive range <>) of SSH_Lib.Protocol.Negative_Tests.Negative_Case;

   Cases : constant Case_Array :=
     [SSH_Lib.Protocol.Negative_Tests.Socket_Exception,
      SSH_Lib.Protocol.Negative_Tests.Packet_Parse_Exception,
      SSH_Lib.Protocol.Negative_Tests.Crypto_Verification_Exception,
      SSH_Lib.Protocol.Negative_Tests.Known_Hosts_Read_Exception,
      SSH_Lib.Protocol.Negative_Tests.Config_Read_Exception,
      SSH_Lib.Protocol.Negative_Tests.Identity_Read_Exception,
      SSH_Lib.Protocol.Negative_Tests.Agent_Transport_Exception,
      SSH_Lib.Protocol.Negative_Tests.Channel_Dispatch_Exception,
      SSH_Lib.Protocol.Negative_Tests.Invalid_Remote_Host,
      SSH_Lib.Protocol.Negative_Tests.Invalid_Remote_Port,
      SSH_Lib.Protocol.Negative_Tests.Invalid_Remote_User,
      SSH_Lib.Protocol.Negative_Tests.Config_Proxy_Command,
      SSH_Lib.Protocol.Negative_Tests.Config_Proxy_Jump,
      SSH_Lib.Protocol.Negative_Tests.Config_Negated_Host_Pattern,
      SSH_Lib.Protocol.Negative_Tests.Config_Wildcard_Unsupported,
      SSH_Lib.Protocol.Negative_Tests.Config_IdentityFile_Not_Shell_Expanded,
      SSH_Lib.Protocol.Negative_Tests.Config_Cannot_Disable_Verify_Known_Host,
      SSH_Lib.Protocol.Negative_Tests.Config_Cannot_Disable_Strict_Host_Key,
      SSH_Lib.Protocol.Negative_Tests.Config_HostName_Cannot_Alter_Repository_Path,
      SSH_Lib.Protocol.Negative_Tests.Remote_User_Overrides_Config_User,
      SSH_Lib.Protocol.Negative_Tests.Remote_Port_Overrides_Config_Port];

   procedure Check_Case
     (Case_Item : SSH_Lib.Protocol.Negative_Tests.Negative_Case)
   is
      Actual : constant CryptoLib.Errors.Status :=
        SSH_Lib.Protocol.Negative_Tests.Expected_Status (Case_Item);
   begin
      if SSH_Lib.Protocol.Negative_Tests.Is_Preservation_Case (Case_Item) then
         if Actual /= CryptoLib.Errors.Ok then
            Ada.Text_IO.Put_Line
              ("FAILED preservation: "
               & SSH_Lib.Protocol.Negative_Tests.Case_Label (Case_Item));
            raise Program_Error;
         end if;
      elsif Actual = CryptoLib.Errors.Ok
        or else Actual = CryptoLib.Errors.End_Of_Stream
        or else Actual = CryptoLib.Errors.Cancelled
        or else Actual = CryptoLib.Errors.Remote_Exit_Nonzero
      then
         Ada.Text_IO.Put_Line
           ("FAILED failure mapping: "
            & SSH_Lib.Protocol.Negative_Tests.Case_Label (Case_Item));
         raise Program_Error;
      end if;
   end Check_Case;
begin
   for Case_Item of Cases loop
      Check_Case (Case_Item);
   end loop;

   SSH_Lib.Tests.Fixtures.Exception_Containment.Assert_Public_Api_Exception_Boundaries;
   Ada.Text_IO.Put_Line ("test_exception_mapping passed");
end Test_Exception_Mapping;
