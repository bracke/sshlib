with CryptoLib.Errors;

package SSH_Lib.Sessions.Close_Pipeline is
   procedure Scrub_Credentials (Options : in out Session_Options);

   procedure Reset_To_Closed
     (Item         : in out Session;
      Status_Value : CryptoLib.Errors.Status);
end SSH_Lib.Sessions.Close_Pipeline;
