with CryptoLib.Errors;

--  @summary Predicates over a session's fully-reconciled lifecycle state.
--
--  Answers whether a session is genuinely authenticated-and-open or cleanly
--  closed by requiring every transport, handshake, encryption, host-key, and
--  authentication milestone flag to agree -- not just the coarse public state
--  -- so callers cannot mistake a partially-torn-down session for a usable one.
package SSH_Lib.Sessions.State is
   --  Report whether the session is fully authenticated and open with every
   --  transport, KEX, encryption, host-key, and userauth milestone satisfied.
   --  @param Item the session to inspect
   --  @return True only when all authenticated-open invariants hold
   function Is_Authenticated_Open (Item : Session) return Boolean;

   --  Report whether the session is cleanly closed with every milestone flag
   --  cleared, making it safe to reuse for later channel work.
   --  @param Item the session to inspect
   --  @return True only when every closed-state invariant holds
   function Is_Closed (Item : Session) return Boolean;

   --  Return the recorded failure status of the session.
   --  @param Item the session to inspect
   --  @return the session's stored failure status
   function Failure_Status (Item : Session) return CryptoLib.Errors.Status;
end SSH_Lib.Sessions.State;
