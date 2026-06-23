with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Protocol.Kexdh is
   SSH_MSG_KEXDH_INIT  : constant Ada.Streams.Stream_Element := 30;
   SSH_MSG_KEXDH_REPLY : constant Ada.Streams.Stream_Element := 31;

   --  RFC 5656 ECDH uses the same message numbers as classic KEXDH, but
   --  the public values Q_C/Q_S are SSH strings containing SEC1 encoded
   --  elliptic-curve points rather than mpints.  Keep explicit aliases so
   --  packet code does not accidentally depend on the finite-field helper
   --  semantics.
   SSH_MSG_KEX_ECDH_INIT  : constant Ada.Streams.Stream_Element := 30;
   SSH_MSG_KEX_ECDH_REPLY : constant Ada.Streams.Stream_Element := 31;

   SSH_MSG_KEX_DH_GEX_GROUP   : constant Ada.Streams.Stream_Element := 31;
   SSH_MSG_KEX_DH_GEX_INIT    : constant Ada.Streams.Stream_Element := 32;
   SSH_MSG_KEX_DH_GEX_REPLY   : constant Ada.Streams.Stream_Element := 33;
   SSH_MSG_KEX_DH_GEX_REQUEST : constant Ada.Streams.Stream_Element := 34;

   type Group_Exchange_Group is record
      Prime_Value     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Generator_Value : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;

   type Reply is record
      Host_Key_Blob       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Public_Value : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Signature_Blob      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;

   procedure Clear (Item : out Group_Exchange_Group);

   procedure Clear (Item : out Reply);

   function Encode_Group_Exchange_Request
     (Minimum_Bits   : Natural;
      Preferred_Bits : Natural;
      Maximum_Bits   : Natural;
      Payload        : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Parse_Group_Exchange_Group
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Group_Exchange_Group)
      return CryptoLib.Errors.Status;

   function Encode_Group_Exchange_Init
     (Client_Public_Value : Ada.Streams.Stream_Element_Array;
      Payload             : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Parse_Group_Exchange_Reply
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Reply)
      return CryptoLib.Errors.Status;

   function Encode_Group14_Init
     (Client_Public_Value : Ada.Streams.Stream_Element_Array;
      Payload             : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Parse_Group14_Reply
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Reply)
      return CryptoLib.Errors.Status;

   function Encode_Curve25519_Init
     (Client_Public_Key : Ada.Streams.Stream_Element_Array;
      Payload           : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Parse_Curve25519_Reply
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Reply)
      return CryptoLib.Errors.Status;

   function Encode_ECDH_Nistp256_Init
     (Client_Public_Key : Ada.Streams.Stream_Element_Array;
      Payload           : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Parse_ECDH_Nistp256_Reply
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Reply)
      return CryptoLib.Errors.Status;

   function Encode_Hybrid_PQ_Init
     (Client_Init : Ada.Streams.Stream_Element_Array;
      Payload     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Parse_Hybrid_PQ_Reply
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Reply)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Kexdh;
