with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Identity_Files;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Protocol.Userauth.Identity is
   function Build_Signed_Request_From_Identity
     (Key                  : SSH_Lib.Identity_Files.Identity_Key;
      Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Request              : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Build_Signed_Request_From_Identity
     (Key                  : SSH_Lib.Identity_Files.Identity_Key;
      Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Public_Key_Algorithm : String;
      Request              : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Build_Signed_Request_With_Public_Blob
     (Key                  : SSH_Lib.Identity_Files.Identity_Key;
      Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Ada.Streams.Stream_Element_Array;
      Signature_Algorithm  : String;
      Request              : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Userauth.Identity;
