with SSH_Lib.Protocol.Userauth;

package body SSH_Lib.Security_Keys is
   function Build_Signed_Request
     (Signer               : Security_Key_Signer;
      Application          : String;
      Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Ada.Streams.Stream_Element_Array;
      Request              : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      use CryptoLib.Errors;
      Payload_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Sign_Result    : Security_Key_Sign_Result;

      function Finish (Result : Status) return Status is
      begin
         SSH_Lib.Protocol.Buffers.Clear (Payload_Buffer);
         SSH_Lib.Protocol.Buffers.Clear (Sign_Result.Signature_Blob);
         if Result /= Ok then
            SSH_Lib.Protocol.Buffers.Clear (Request);
         end if;
         return Result;
      end Finish;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Request);
      if Signer = null
        or else Application'Length = 0
        or else Public_Key_Algorithm'Length = 0
        or else Public_Key_Blob'Length = 0
      then
         return Finish (Invalid_Command);
      end if;

      Payload_Buffer :=
        SSH_Lib.Protocol.Userauth.Build_Publickey_Signature_Payload
          (Session_Identifier,
           User_Name,
           Public_Key_Algorithm,
           Public_Key_Blob);
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload_Buffer) then
         return Finish (Authentication_Failed);
      end if;

      Sign_Result :=
        Signer.all
          (Application,
           Public_Key_Algorithm,
           Public_Key_Blob,
           SSH_Lib.Protocol.Buffers.To_Array (Payload_Buffer));
      if not Sign_Result.Provided
        or else SSH_Lib.Protocol.Buffers.Is_Empty (Sign_Result.Signature_Blob)
      then
         return Finish (Authentication_Failed);
      end if;

      Request :=
        SSH_Lib.Protocol.Userauth.Encode_Publickey_Signed_Request
          (User_Name,
           Public_Key_Algorithm,
           Public_Key_Blob,
           SSH_Lib.Protocol.Buffers.To_Array (Sign_Result.Signature_Blob));
      if SSH_Lib.Protocol.Buffers.Is_Empty (Request) then
         return Finish (Authentication_Failed);
      end if;
      return Finish (Ok);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload_Buffer);
         SSH_Lib.Protocol.Buffers.Clear (Sign_Result.Signature_Blob);
         SSH_Lib.Protocol.Buffers.Clear (Request);
         return CryptoLib.Errors.Internal_Error;
   end Build_Signed_Request;
end SSH_Lib.Security_Keys;
