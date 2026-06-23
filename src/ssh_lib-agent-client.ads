with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Agent.Client is
   function Request_Identities
     (Socket_Path : String;
      Identities  : out SSH_Lib.Agent.Identity_List)
      return CryptoLib.Errors.Status;

   function Request_Identities
     (Socket_Path : String;
      Timeout_MS  : Natural;
      Identities  : out SSH_Lib.Agent.Identity_List)
      return CryptoLib.Errors.Status;

   function Request_Signature
     (Socket_Path           : String;
      Key_Blob              : Ada.Streams.Stream_Element_Array;
      Data_To_Sign          : Ada.Streams.Stream_Element_Array;
      Public_Key_Algorithm  : String;
      Signature_Blob        : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Request_Signature
     (Socket_Path           : String;
      Timeout_MS            : Natural;
      Key_Blob              : Ada.Streams.Stream_Element_Array;
      Data_To_Sign          : Ada.Streams.Stream_Element_Array;
      Public_Key_Algorithm  : String;
      Signature_Blob        : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;
end SSH_Lib.Agent.Client;
