with SSH_Lib.Protocol.Validation;

package body SSH_Lib.Protocol.Userauth.Agent_Identity is
   function Build_Signed_Request_From_Agent_Signature
     (Key_Blob             : Ada.Streams.Stream_Element_Array;
      Signature_Blob       : Ada.Streams.Stream_Element_Array;
      Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Public_Key_Algorithm : String;
      Request              : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      use CryptoLib.Errors;
      Payload_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;

      function Finish (Result : Status) return Status is
      begin
         SSH_Lib.Protocol.Buffers.Clear (Payload_Buffer);
         if Result /= Ok then
            SSH_Lib.Protocol.Buffers.Clear (Request);
         end if;
         return Result;
      end Finish;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Request);
      if Key_Blob'Length = 0
        or else Signature_Blob'Length = 0
        or else Session_Identifier'Length = 0
        or else not SSH_Lib.Protocol.Validation.Is_ASCII_Protocol_Name
                      (Public_Key_Algorithm)
      then
         return Finish (Authentication_Failed);
      end if;

      Payload_Buffer := SSH_Lib.Protocol.Userauth.Build_Publickey_Signature_Payload
        (Session_Identifier, User_Name, Public_Key_Algorithm, Key_Blob);
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload_Buffer) then
         return Finish (Authentication_Failed);
      end if;

      --  The signature itself is supplied by an ssh-agent-shaped backend.  This
      --  routine is intentionally limited to constructing the SSH userauth
      --  packet from already-validated public key and signature blobs; it does
      --  not talk to an agent socket and it does not mark a session
      --  authenticated.
      Request := SSH_Lib.Protocol.Userauth.Encode_Publickey_Signed_Request
        (User_Name, Public_Key_Algorithm, Key_Blob, Signature_Blob);
      if SSH_Lib.Protocol.Buffers.Is_Empty (Request) then
         return Finish (Authentication_Failed);
      end if;

      return Finish (Ok);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload_Buffer);
         SSH_Lib.Protocol.Buffers.Clear (Request);
         return CryptoLib.Errors.Internal_Error;
   end Build_Signed_Request_From_Agent_Signature;
end SSH_Lib.Protocol.Userauth.Agent_Identity;
