with CryptoLib.Errors;

package SSH_Lib.Sessions.State is
   function Is_Authenticated_Open (Item : Session) return Boolean;
   function Is_Closed (Item : Session) return Boolean;
   function Failure_Status (Item : Session) return CryptoLib.Errors.Status;
end SSH_Lib.Sessions.State;
