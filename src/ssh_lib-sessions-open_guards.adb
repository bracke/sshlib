
package body SSH_Lib.Sessions.Open_Guards is
   use type CryptoLib.Errors.Status;
   function Gate_Label (Gate : Open_Success_Gate) return String is
   begin
      case Gate is
         when Gate_Transport_Connected =>
            return "transport connected";
         when Gate_Identification_Complete =>
            return "server identification complete";
         when Gate_Kexinit_Exchanged =>
            return "kexinit exchanged";
         when Gate_Algorithms_Negotiated =>
            return "algorithms negotiated";
         when Gate_Kex_Complete =>
            return "key exchange complete";
         when Gate_Keys_Derived =>
            return "session keys derived";
         when Gate_Newkeys_Sent =>
            return "newkeys sent";
         when Gate_Newkeys_Received =>
            return "newkeys received";
         when Gate_Encrypted_Outbound_Active =>
            return "encrypted outbound active";
         when Gate_Encrypted_Inbound_Active =>
            return "encrypted inbound active";
         when Gate_Host_Key_Signature_Verified =>
            return "host-key signature verified";
         when Gate_Known_Host_Trusted =>
            return "known-host trust established";
         when Gate_Userauth_Service_Accepted =>
            return "userauth service accepted";
         when Gate_User_Authenticated =>
            return "user authenticated";
      end case;
   end Gate_Label;

   function Gate_Complete
     (Item : Session;
      Gate : Open_Success_Gate)
      return Boolean
   is
   begin
      case Gate is
         when Gate_Transport_Connected =>
            return Item.Transport_Connected;
         when Gate_Identification_Complete =>
            return Item.Identification_Complete;
         when Gate_Kexinit_Exchanged =>
            return Item.Kexinit_Exchanged;
         when Gate_Algorithms_Negotiated =>
            return Item.Algorithms_Negotiated;
         when Gate_Kex_Complete =>
            return Item.Kex_Complete;
         when Gate_Keys_Derived =>
            return Item.Keys_Derived;
         when Gate_Newkeys_Sent =>
            return Item.Newkeys_Sent;
         when Gate_Newkeys_Received =>
            return Item.Newkeys_Received;
         when Gate_Encrypted_Outbound_Active =>
            return Item.Encrypted_Outbound_Active;
         when Gate_Encrypted_Inbound_Active =>
            return Item.Encrypted_Inbound_Active;
         when Gate_Host_Key_Signature_Verified =>
            return Item.Host_Key_Signature_Verified;
         when Gate_Known_Host_Trusted =>
            return Item.Known_Host_Trusted or else Item.Known_Host_Bypassed_Explicitly;
         when Gate_Userauth_Service_Accepted =>
            return Item.Userauth_Service_Accepted;
         when Gate_User_Authenticated =>
            return Item.User_Authenticated;
      end case;
   exception
      when others =>
         return False;
   end Gate_Complete;

   function Success_Gates_Complete (Item : Session) return Boolean is
   begin
      for Gate in Open_Success_Gate loop
         if not Gate_Complete (Item, Gate) then
            return False;
         end if;
      end loop;
      return True;
   exception
      when others =>
         return False;
   end Success_Gates_Complete;

   function First_Missing_Gate
     (Item : Session)
      return Open_Success_Gate
   is
   begin
      for Gate in Open_Success_Gate loop
         if not Gate_Complete (Item, Gate) then
            return Gate;
         end if;
      end loop;
      return Gate_User_Authenticated;
   end First_Missing_Gate;

   function Public_Open_State_Consistent (Item : Session) return Boolean is
   begin
      return Item.Current_State = Opened
        and then Item.Session_Open
        and then not Item.Session_Closed
        and then not Item.Session_Dirty
        and then Item.Failure_Status = CryptoLib.Errors.Ok
        and then Success_Gates_Complete (Item);
   exception
      when others =>
         return False;
   end Public_Open_State_Consistent;

   function Status_For_Incomplete_Gates
     (Item : Session)
      return CryptoLib.Errors.Status
   is
   begin
      if Success_Gates_Complete (Item) then
         return CryptoLib.Errors.Ok;
      end if;

      case First_Missing_Gate (Item) is
         when Gate_Transport_Connected =>
            return CryptoLib.Errors.Connection_Failed;
         when Gate_Identification_Complete
            | Gate_Kexinit_Exchanged
            | Gate_Kex_Complete
            | Gate_Keys_Derived
            | Gate_Newkeys_Sent
            | Gate_Newkeys_Received
            | Gate_Encrypted_Outbound_Active
            | Gate_Encrypted_Inbound_Active
            | Gate_Host_Key_Signature_Verified =>
            return CryptoLib.Errors.Handshake_Failed;
         when Gate_Algorithms_Negotiated =>
            return CryptoLib.Errors.Unsupported_Feature;
         when Gate_Known_Host_Trusted =>
            return CryptoLib.Errors.Host_Key_Unknown;
         when Gate_Userauth_Service_Accepted
            | Gate_User_Authenticated =>
            return CryptoLib.Errors.Authentication_Failed;
      end case;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Status_For_Incomplete_Gates;
end SSH_Lib.Sessions.Open_Guards;
