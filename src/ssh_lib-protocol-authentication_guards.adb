
package body SSH_Lib.Protocol.Authentication_Guards is
   use type Ada.Streams.Stream_Element_Offset;
   use type Ada.Streams.Stream_Element;
   use type CryptoLib.Errors.Status;

   function Can_Start_Userauth
     (Encrypted_Mode_Active : Boolean;
      Host_Key_Trusted      : Boolean)
      return CryptoLib.Errors.Status
   is
   begin
      if not Encrypted_Mode_Active then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      if not Host_Key_Trusted then
         return CryptoLib.Errors.Host_Key_Unknown;
      end if;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Can_Start_Userauth;

   function Complete_Userauth
     (Precondition_Status : CryptoLib.Errors.Status;
      Reply               : SSH_Lib.Protocol.Userauth.Reply)
      return CryptoLib.Errors.Status
   is
   begin
      if Precondition_Status /= CryptoLib.Errors.Ok then
         return Precondition_Status;
      end if;

      case Reply.Kind is
         when SSH_Lib.Protocol.Userauth.Auth_Success =>
            return CryptoLib.Errors.Ok;

         when SSH_Lib.Protocol.Userauth.Auth_Failure =>
            --  USERAUTH_FAILURE with partial_success still means authentication is
            --  incomplete.  It must never be promoted to authenticated session state.
            return CryptoLib.Errors.Authentication_Failed;

         when SSH_Lib.Protocol.Userauth.Auth_Banner =>
            --  Banner is advisory text only.  It is safely parsed/ignored, but it is
            --  never an authentication completion signal.
            return CryptoLib.Errors.Authentication_Failed;

         when SSH_Lib.Protocol.Userauth.Public_Key_Ok
            | SSH_Lib.Protocol.Userauth.Password_Change_Required
            | SSH_Lib.Protocol.Userauth.Keyboard_Interactive_Info_Request
            | SSH_Lib.Protocol.Userauth.Unexpected_Reply =>
            return CryptoLib.Errors.Authentication_Failed;
      end case;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Complete_Userauth;

   function Signature_Payloads_Match
     (Expected_Payload : Ada.Streams.Stream_Element_Array;
      Actual_Payload   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status
   is
   begin
      if Expected_Payload'Length /= Actual_Payload'Length then
         return CryptoLib.Errors.Authentication_Failed;
      end if;

      for Offset_Value in 0 .. Expected_Payload'Length - 1 loop
         if Expected_Payload (Expected_Payload'First + Ada.Streams.Stream_Element_Offset (Offset_Value))
           /= Actual_Payload (Actual_Payload'First + Ada.Streams.Stream_Element_Offset (Offset_Value))
         then
            return CryptoLib.Errors.Authentication_Failed;
         end if;
      end loop;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Signature_Payloads_Match;
end SSH_Lib.Protocol.Authentication_Guards;
