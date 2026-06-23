with CryptoLib.Errors;

package SSH_Lib.Sessions.Open_Pipeline is
   function Validate_Options
     (Options : Session_Options)
      return CryptoLib.Errors.Status;

   function Authentication_Configuration_Preflight
     (Options : Session_Options)
      return CryptoLib.Errors.Status;

   function Immediate_Timeout_Preflight
     (Options : Session_Options)
      return CryptoLib.Errors.Status;

end SSH_Lib.Sessions.Open_Pipeline;
