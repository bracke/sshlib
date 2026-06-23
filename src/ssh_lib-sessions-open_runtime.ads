with CryptoLib.Errors;

package SSH_Lib.Sessions.Open_Runtime is
   function Run
     (Options : Session_Options;
      Item    : in out Session)
      return CryptoLib.Errors.Status;
end SSH_Lib.Sessions.Open_Runtime;
