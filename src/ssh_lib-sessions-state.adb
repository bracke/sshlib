package body SSH_Lib.Sessions.State is
   function Is_Authenticated_Open (Item : Session) return Boolean is
   begin
      return
        Item.Current_State = Opened
        and then Item.Session_Open
        and then not Item.Session_Closed
        and then not Item.Session_Dirty
        and then Item.Transport_Connected
        and then Item.Identification_Complete
        and then Item.Kexinit_Exchanged
        and then Item.Algorithms_Negotiated
        and then Item.Kex_Complete
        and then Item.Keys_Derived
        and then Item.Newkeys_Sent
        and then Item.Newkeys_Received
        and then Item.Encrypted_Outbound_Active
        and then Item.Encrypted_Inbound_Active
        and then Item.Host_Key_Signature_Verified
        and then
          (Item.Known_Host_Trusted or else Item.Known_Host_Bypassed_Explicitly)
        and then Item.Userauth_Service_Accepted
        and then Item.User_Authenticated;
   end Is_Authenticated_Open;

   function Is_Closed (Item : Session) return Boolean is
   begin
      --  Closed must mean more than "not publicly open".  The session is
      --  clean for later channel work only when every transport, handshake,
      --  encryption, host-key, and authentication milestone has been cleared.
      return
        Item.Current_State = Closed
        and then Item.Session_Closed
        and then not Item.Session_Open
        and then not Item.Transport_Connected
        and then not Item.Identification_Complete
        and then not Item.Kexinit_Exchanged
        and then not Item.Algorithms_Negotiated
        and then not Item.Kex_Complete
        and then not Item.Keys_Derived
        and then not Item.Newkeys_Sent
        and then not Item.Newkeys_Received
        and then not Item.Encrypted_Outbound_Active
        and then not Item.Encrypted_Inbound_Active
        and then not Item.Host_Key_Signature_Verified
        and then not Item.Known_Host_Trusted
        and then not Item.Known_Host_Bypassed_Explicitly
        and then not Item.Userauth_Service_Accepted
        and then not Item.User_Authenticated
        and then Item.Authentication_Method_Used = No_Authentication_Method
        and then not Item.Session_Dirty
        and then not Item.Last_Operation_Cancelled;
   end Is_Closed;

   function Failure_Status (Item : Session) return CryptoLib.Errors.Status is
   begin
      return Item.Failure_Status;
   end Failure_Status;

end SSH_Lib.Sessions.State;
