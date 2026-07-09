with Ada.Streams;
with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Keys;
with SSH_Lib.Protocol.Buffers;

--  @summary Parses and verifies SSH wire signature blobs against a public key.
--
--  A Parsed_Signature holds the algorithm name and raw signature bytes decoded
--  from an SSH "signature" blob (the algorithm-identifier string followed by the
--  algorithm-specific signature).  Parse validates the blob against the
--  negotiated algorithm, and Verify checks the signature over an exchange hash
--  with the peer's public key.
package SSH_Lib.Protocol.Signatures is
   type Parsed_Signature is private;

   --  Reset the parsed signature to empty, discarding any decoded bytes.
   --  @param Item the parsed signature to clear
   procedure Clear (Item : out Parsed_Signature);

   --  Return the signature's algorithm identifier.
   --  @param Item the parsed signature to inspect
   --  @return the algorithm name string, empty if none was parsed
   function Algorithm (Item : Parsed_Signature) return String;

   --  Return the raw algorithm-specific signature bytes.
   --  @param Item the parsed signature to inspect
   --  @return the decoded signature payload
   function Bytes
     (Item : Parsed_Signature)
      return Ada.Streams.Stream_Element_Array;

   --  Decode an SSH signature blob, checking it matches the negotiated algorithm.
   --  @param Blob                 the wire signature blob (algorithm name plus
   --                              signature payload)
   --  @param Negotiated_Algorithm the algorithm the signature must use
   --  @param Item                 the resulting parsed signature
   --  @return Ok if the blob is well formed and consistent, otherwise the
   --          failure status
   function Parse
     (Blob                 : Ada.Streams.Stream_Element_Array;
      Negotiated_Algorithm : String;
      Item                 : out Parsed_Signature)
      return CryptoLib.Errors.Status;

   --  Verify a parsed signature over an exchange hash with the peer public key.
   --  @param Negotiated_Algorithm the signature algorithm to verify under
   --  @param Key_Item             the public key that should have signed
   --  @param Signature_Item       the parsed signature to check
   --  @param Exchange_Hash        the signed data (the KEX exchange hash H)
   --  @return Ok if the signature verifies, otherwise the failure status
   function Verify
     (Negotiated_Algorithm : String;
      Key_Item             : SSH_Lib.Keys.Public_Key;
      Signature_Item       : Parsed_Signature;
      Exchange_Hash        : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

private
   type Parsed_Signature is record
      Present        : Boolean := False;
      Algorithm_Text : Ada.Strings.Unbounded.Unbounded_String;
      Signature_Data : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;
end SSH_Lib.Protocol.Signatures;
