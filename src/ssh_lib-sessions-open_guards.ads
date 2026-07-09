with CryptoLib.Errors;

--  @summary Guard predicates that gate session-open state transitions,
--  ensuring a session is exposed only after each required stage holds.
package SSH_Lib.Sessions.Open_Guards is
   type Open_Success_Gate is
     (Gate_Transport_Connected,
      Gate_Identification_Complete,
      Gate_Kexinit_Exchanged,
      Gate_Algorithms_Negotiated,
      Gate_Kex_Complete,
      Gate_Keys_Derived,
      Gate_Newkeys_Sent,
      Gate_Newkeys_Received,
      Gate_Encrypted_Outbound_Active,
      Gate_Encrypted_Inbound_Active,
      Gate_Host_Key_Signature_Verified,
      Gate_Known_Host_Trusted,
      Gate_Userauth_Service_Accepted,
      Gate_User_Authenticated);

   --  Return a human-readable label describing a session-open gate.
   --  @param Gate the open-success gate to label
   --  @return a short description of the gate
   function Gate_Label (Gate : Open_Success_Gate) return String;

   --  Report whether a specific session-open gate has been satisfied.
   --  @param Item the session to inspect
   --  @param Gate the gate to check
   --  @return True if that stage of the handshake/auth is complete
   function Gate_Complete
     (Item : Session;
      Gate : Open_Success_Gate)
      return Boolean;

   --  Report whether every session-open gate is satisfied.
   --  @param Item the session to inspect
   --  @return True if all gates are complete
   function Success_Gates_Complete (Item : Session) return Boolean;

   --  Return the first (earliest) session-open gate that is not yet satisfied.
   --  @param Item the session to inspect
   --  @return the first incomplete gate, or Gate_User_Authenticated if all are complete
   function First_Missing_Gate
     (Item : Session)
      return Open_Success_Gate;

   --  Report whether the session's public open state is internally consistent and fully open.
   --  @param Item the session to inspect
   --  @return True if the session is Opened, undirtied, error-free, and all gates are complete
   function Public_Open_State_Consistent (Item : Session) return Boolean;

   --  Map the first missing gate to the error status that best explains the incomplete open.
   --  @param Item the session to inspect
   --  @return Ok if all gates are complete, otherwise the status describing the first missing gate
   function Status_For_Incomplete_Gates
     (Item : Session)
      return CryptoLib.Errors.Status;
end SSH_Lib.Sessions.Open_Guards;
