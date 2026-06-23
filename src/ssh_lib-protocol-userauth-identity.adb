with SSH_Lib.Private_Key_Signing;

package body SSH_Lib.Protocol.Userauth.Identity is
   function Build_Signed_Request_With_Public_Blob
     (Key                  : SSH_Lib.Identity_Files.Identity_Key;
      Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Ada.Streams.Stream_Element_Array;
      Signature_Algorithm  : String;
      Request              : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      use CryptoLib.Errors;
      Payload_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Signature_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : Status;

      function Finish (Result : Status) return Status is
      begin
         SSH_Lib.Protocol.Buffers.Clear (Payload_Buffer);
         SSH_Lib.Protocol.Buffers.Clear (Signature_Buffer);
         if Result /= Ok then
            SSH_Lib.Protocol.Buffers.Clear (Request);
         end if;
         return Result;
      end Finish;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Request);
      Payload_Buffer := SSH_Lib.Protocol.Userauth.Build_Publickey_Signature_Payload
        (Session_Identifier, User_Name, Public_Key_Algorithm, Public_Key_Blob);
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload_Buffer) then
         return Finish (Authentication_Failed);
      end if;
      Status_Value := SSH_Lib.Private_Key_Signing.Sign_Userauth
        (Key, Signature_Algorithm, SSH_Lib.Protocol.Buffers.To_Array (Payload_Buffer), Signature_Buffer);
      if Status_Value /= Ok then
         return Finish (Status_Value);
      end if;
      Request := SSH_Lib.Protocol.Userauth.Encode_Publickey_Signed_Request
        (User_Name, Public_Key_Algorithm, Public_Key_Blob, SSH_Lib.Protocol.Buffers.To_Array (Signature_Buffer));
      if SSH_Lib.Protocol.Buffers.Is_Empty (Request) then
         return Finish (Authentication_Failed);
      end if;
      return Finish (Ok);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload_Buffer);
         SSH_Lib.Protocol.Buffers.Clear (Signature_Buffer);
         SSH_Lib.Protocol.Buffers.Clear (Request);
         return CryptoLib.Errors.Internal_Error;
   end Build_Signed_Request_With_Public_Blob;

   function Build_Signed_Request_From_Identity
     (Key                  : SSH_Lib.Identity_Files.Identity_Key;
      Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Public_Key_Algorithm : String;
      Request              : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Public_Blob : constant Ada.Streams.Stream_Element_Array :=
        SSH_Lib.Identity_Files.Public_Key_Blob (Key);
   begin
      return Build_Signed_Request_With_Public_Blob
        (Key, Session_Identifier, User_Name, Public_Key_Algorithm,
         Public_Blob, Public_Key_Algorithm, Request);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Request);
         return CryptoLib.Errors.Internal_Error;
   end Build_Signed_Request_From_Identity;

   function Build_Signed_Request_From_Identity
     (Key                  : SSH_Lib.Identity_Files.Identity_Key;
      Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Request              : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status
   is
      Key_Algorithm_Text : constant String := SSH_Lib.Identity_Files.Algorithm_Name (Key);
      Algorithm_Text : constant String :=
        (if Key_Algorithm_Text = "ssh-rsa" then "rsa-sha2-512" else Key_Algorithm_Text);
   begin
      return Build_Signed_Request_From_Identity
        (Key, Session_Identifier, User_Name, Algorithm_Text, Request);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Request);
         return CryptoLib.Errors.Internal_Error;
   end Build_Signed_Request_From_Identity;
end SSH_Lib.Protocol.Userauth.Identity;
