with SSH_Lib.Sessions.Close_Pipeline;

package body SSH_Lib.Sessions.Cleanup is
   function Close_After_Failure
     (Item         : in out Session;
      Status_Value : CryptoLib.Errors.Status)
      return CryptoLib.Errors.Status is
   begin
      SSH_Lib.Sessions.Close_Pipeline.Reset_To_Closed (Item, Status_Value);
      return Status_Value;
   exception
      when others =>
         Item.Current_State := Closed;
         Item.Session_Open := False;
         Item.Session_Closed := True;
         Item.Session_Dirty := False;
         SSH_Lib.Sessions.Close_Pipeline.Scrub_Credentials
           (Item.Stored_Options);
         return CryptoLib.Errors.Internal_Error;
   end Close_After_Failure;
end SSH_Lib.Sessions.Cleanup;
