with CryptoLib.Errors;

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

   function Gate_Label (Gate : Open_Success_Gate) return String;

   function Gate_Complete
     (Item : Session;
      Gate : Open_Success_Gate)
      return Boolean;

   function Success_Gates_Complete (Item : Session) return Boolean;

   function First_Missing_Gate
     (Item : Session)
      return Open_Success_Gate;

   function Public_Open_State_Consistent (Item : Session) return Boolean;

   function Status_For_Incomplete_Gates
     (Item : Session)
      return CryptoLib.Errors.Status;
end SSH_Lib.Sessions.Open_Guards;
