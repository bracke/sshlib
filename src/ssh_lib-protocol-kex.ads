with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Kexinit;

--  @summary Key-exchange algorithm negotiation from paired KEXINIT messages.
--
--  Holds the set of algorithms chosen for a connection (key exchange, host key,
--  and the per-direction cipher, MAC, and compression) and derives them from
--  the client and server KEXINIT name-lists following the SSH negotiation rules.
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

   --  Reset every negotiated algorithm field to the empty string.
   --  @param Item the record to clear
   procedure Clear (Item : out Negotiated_Algorithms);

   --  Negotiate the connection's algorithms from the client and server KEXINIT
   --  name-lists, applying the SSH client-preference matching rules.
   --  @param Client_Item the client's KEXINIT message
   --  @param Server_Item the server's KEXINIT message
   --  @param Result_Item the negotiated algorithm set
   --  @return Ok if every category matches, an error status if any has no overlap
   function Negotiate
     (Client_Item : SSH_Lib.Protocol.Kexinit.Kexinit_Message;
      Server_Item : SSH_Lib.Protocol.Kexinit.Kexinit_Message;
      Result_Item : out Negotiated_Algorithms)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Kex;
