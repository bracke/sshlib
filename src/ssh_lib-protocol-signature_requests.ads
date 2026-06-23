with Ada.Streams;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Protocol.Signature_Requests is
   pragma Preelaborate;

   function Build_Userauth_Publickey_Data
     (Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;
end SSH_Lib.Protocol.Signature_Requests;
