with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Keys;
with SSH_Lib.Protocol.Encrypted_State;

--  @summary Server host-key parsing and exchange-hash signature verification.
--
--  Decode the wire host-key blob into a typed public key for the negotiated
--  algorithm, and verify the server's signature over the key-exchange hash
--  before recording the key in the KEX state.
package SSH_Lib.Protocol.Host_Keys is
   --  Parse a wire host-key blob into a typed public key for the negotiated
   --  host-key algorithm.
   --  @param Blob                 the SSH-encoded host-key blob from the server
   --  @param Negotiated_Algorithm the host-key algorithm agreed during KEX
   --  @param Item                 the decoded public key
   --  @return Ok on success, an error status on a malformed or mismatched blob
   function Parse
     (Blob                 : Ada.Streams.Stream_Element_Array;
      Negotiated_Algorithm : String;
      Item                 : out SSH_Lib.Keys.Public_Key)
      return CryptoLib.Errors.Status;

   --  Verify the server's signature over the exchange hash with the supplied
   --  host key and, on success, store the host key in the KEX state.
   --  @param Host_Key_Blob        the SSH-encoded server host-key blob
   --  @param Signature_Blob       the server signature over the exchange hash
   --  @param Negotiated_Algorithm the host-key algorithm agreed during KEX
   --  @param Exchange_Hash        the computed key-exchange hash to verify against
   --  @param State_Item           the KEX state updated with the trusted host key
   --  @return Ok on a verified signature, an error status otherwise
   function Verify_And_Store
     (Host_Key_Blob        : Ada.Streams.Stream_Element_Array;
      Signature_Blob       : Ada.Streams.Stream_Element_Array;
      Negotiated_Algorithm : String;
      Exchange_Hash        : Ada.Streams.Stream_Element_Array;
      State_Item           : in out SSH_Lib.Protocol.Encrypted_State.Kex_State)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Host_Keys;
