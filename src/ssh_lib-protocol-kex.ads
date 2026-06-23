with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Kexinit;

package SSH_Lib.Protocol.Kex is

   type Negotiated_Algorithms is record
      Key_Exchange                              : Ada.Strings.Unbounded.Unbounded_String;
      Server_Host_Key                           : Ada.Strings.Unbounded.Unbounded_String;
      Cipher_Client_To_Server                   : Ada.Strings.Unbounded.Unbounded_String;
      Cipher_Server_To_Client                   : Ada.Strings.Unbounded.Unbounded_String;
      Mac_Client_To_Server                      : Ada.Strings.Unbounded.Unbounded_String;
      Mac_Server_To_Client                      : Ada.Strings.Unbounded.Unbounded_String;
      Compression_Client_To_Server              : Ada.Strings.Unbounded.Unbounded_String;
      Compression_Server_To_Client              : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   procedure Clear (Item : out Negotiated_Algorithms);

   function Negotiate
     (Client_Item : SSH_Lib.Protocol.Kexinit.Kexinit_Message;
      Server_Item : SSH_Lib.Protocol.Kexinit.Kexinit_Message;
      Result_Item : out Negotiated_Algorithms)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Kex;
