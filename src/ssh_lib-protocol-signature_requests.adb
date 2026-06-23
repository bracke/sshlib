with Ada.Streams;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Userauth;

package body SSH_Lib.Protocol.Signature_Requests is
   function Build_Userauth_Publickey_Data
     (Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
   begin
      return SSH_Lib.Protocol.Userauth.Build_Publickey_Signature_Payload
        (Session_Identifier, User_Name, Public_Key_Algorithm, Public_Key_Blob);
   end Build_Userauth_Publickey_Data;
end SSH_Lib.Protocol.Signature_Requests;
