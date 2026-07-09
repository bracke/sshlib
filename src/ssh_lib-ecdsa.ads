with Ada.Streams;
with CryptoLib.Errors;
with CryptoLib.Random;
with CryptoLib.Buffers;

--  @summary SSH ECDSA over the NIST P-256/P-384/P-521 curves: signature
--  verification and signing, key/point validation, and ephemeral ECDH.
--
--  Operates on SSH-wire encodings: public keys are the ecdsa-sha2-nistpNNN
--  blob (type string, curve name, SEC1 point), signatures are the wire blob
--  (type string plus mpint r, s), and private scalars are SSH mpints.  ECDH
--  helpers exchange raw SEC1 points and produce the raw shared X coordinate.
--  Verification and validation return Ok when accepted and a non-Ok Status
--  otherwise.
package SSH_Lib.ECDSA is

   --  Verify an ecdsa-sha2-nistp256 signature over a message with a public key.
   --  @param Public_Key_Blob the SSH-wire ecdsa-sha2-nistp256 public-key blob
   --  @param Signature_Bytes the SSH-wire ecdsa signature blob (mpint r, s)
   --  @param Message_Bytes   the message the signature is claimed to cover
   --  @return Ok when the signature is valid, a non-Ok Status otherwise
   function Verify_Nistp256
     (Public_Key_Blob : Ada.Streams.Stream_Element_Array;
      Signature_Bytes : Ada.Streams.Stream_Element_Array;
      Message_Bytes   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Validate that a P-256 public-key blob is well-formed and on the curve.
   --  @param Public_Key_Blob the SSH-wire ecdsa-sha2-nistp256 public-key blob
   --  @return Ok when the blob is a valid on-curve point, a non-Ok Status
   --          otherwise
   function Validate_Public_Nistp256
     (Public_Key_Blob : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Validate that a P-256 signature blob is well-formed (r and s in range).
   --  @param Signature_Bytes the SSH-wire ecdsa-sha2-nistp256 signature blob
   --  @return Ok when the signature encoding is valid, a non-Ok Status otherwise
   function Validate_Signature_Nistp256
     (Signature_Bytes : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Verify an ecdsa-sha2-nistp521 signature over a message with a public key.
   --  @param Public_Key_Blob the SSH-wire ecdsa-sha2-nistp521 public-key blob
   --  @param Signature_Bytes the SSH-wire ecdsa signature blob (mpint r, s)
   --  @param Message_Bytes   the message the signature is claimed to cover
   --  @return Ok when the signature is valid, a non-Ok Status otherwise
   function Verify_Nistp521
     (Public_Key_Blob : Ada.Streams.Stream_Element_Array;
      Signature_Bytes : Ada.Streams.Stream_Element_Array;
      Message_Bytes   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Validate that a P-521 public-key blob is well-formed and on the curve.
   --  @param Public_Key_Blob the SSH-wire ecdsa-sha2-nistp521 public-key blob
   --  @return Ok when the blob is a valid on-curve point, a non-Ok Status
   --          otherwise
   function Validate_Public_Nistp521
     (Public_Key_Blob : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Validate that a P-521 signature blob is well-formed (r and s in range).
   --  @param Signature_Bytes the SSH-wire ecdsa-sha2-nistp521 signature blob
   --  @return Ok when the signature encoding is valid, a non-Ok Status otherwise
   function Validate_Signature_Nistp521
     (Signature_Bytes : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Verify an ecdsa-sha2-nistp384 signature over a message with a public key.
   --  @param Public_Key_Blob the SSH-wire ecdsa-sha2-nistp384 public-key blob
   --  @param Signature_Bytes the SSH-wire ecdsa signature blob (mpint r, s)
   --  @param Message_Bytes   the message the signature is claimed to cover
   --  @return Ok when the signature is valid, a non-Ok Status otherwise
   function Verify_Nistp384
     (Public_Key_Blob : Ada.Streams.Stream_Element_Array;
      Signature_Bytes : Ada.Streams.Stream_Element_Array;
      Message_Bytes   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Validate that a P-384 public-key blob is well-formed and on the curve.
   --  @param Public_Key_Blob the SSH-wire ecdsa-sha2-nistp384 public-key blob
   --  @return Ok when the blob is a valid on-curve point, a non-Ok Status
   --          otherwise
   function Validate_Public_Nistp384
     (Public_Key_Blob : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Validate that a P-384 signature blob is well-formed (r and s in range).
   --  @param Signature_Bytes the SSH-wire ecdsa-sha2-nistp384 signature blob
   --  @return Ok when the signature encoding is valid, a non-Ok Status otherwise
   function Validate_Signature_Nistp384
     (Signature_Bytes : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Check that a P-256 public-key blob is the one derived from a private
   --  scalar (guards against a mismatched public/private identity pair).
   --  @param Public_Key_Blob      the SSH-wire ecdsa-sha2-nistp256 public blob
   --  @param Private_Scalar_Mpint the SSH mpint private scalar to derive from
   --  @return Ok when the public key matches the private scalar, a non-Ok
   --          Status otherwise
   function Public_Matches_Private_Nistp256
     (Public_Key_Blob      : Ada.Streams.Stream_Element_Array;
      Private_Scalar_Mpint : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Check that a P-384 public-key blob is the one derived from a private
   --  scalar (guards against a mismatched public/private identity pair).
   --  @param Public_Key_Blob      the SSH-wire ecdsa-sha2-nistp384 public blob
   --  @param Private_Scalar_Mpint the SSH mpint private scalar to derive from
   --  @return Ok when the public key matches the private scalar, a non-Ok
   --          Status otherwise
   function Public_Matches_Private_Nistp384
     (Public_Key_Blob      : Ada.Streams.Stream_Element_Array;
      Private_Scalar_Mpint : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Check that a P-521 public-key blob is the one derived from a private
   --  scalar (guards against a mismatched public/private identity pair).
   --  @param Public_Key_Blob      the SSH-wire ecdsa-sha2-nistp521 public blob
   --  @param Private_Scalar_Mpint the SSH mpint private scalar to derive from
   --  @return Ok when the public key matches the private scalar, a non-Ok
   --          Status otherwise
   function Public_Matches_Private_Nistp521
     (Public_Key_Blob      : Ada.Streams.Stream_Element_Array;
      Private_Scalar_Mpint : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Produce an ecdsa-sha2-nistp256 signature over a message with a private
   --  scalar, emitting the SSH-wire signature blob into Signature_Bytes.
   --  @param Private_Scalar_Mpint the SSH mpint signing private scalar
   --  @param Message_Bytes        the message to sign
   --  @param Signature_Bytes      the produced SSH-wire ecdsa signature blob
   --  @return Ok when signing succeeds, a non-Ok Status otherwise
   function Sign_Nistp256
     (Private_Scalar_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes        : Ada.Streams.Stream_Element_Array;
      Signature_Bytes      : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Produce an ecdsa-sha2-nistp384 signature over a message with a private
   --  scalar, emitting the SSH-wire signature blob into Signature_Bytes.
   --  @param Private_Scalar_Mpint the SSH mpint signing private scalar
   --  @param Message_Bytes        the message to sign
   --  @param Signature_Bytes      the produced SSH-wire ecdsa signature blob
   --  @return Ok when signing succeeds, a non-Ok Status otherwise
   function Sign_Nistp384
     (Private_Scalar_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes        : Ada.Streams.Stream_Element_Array;
      Signature_Bytes      : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Produce an ecdsa-sha2-nistp521 signature over a message with a private
   --  scalar, emitting the SSH-wire signature blob into Signature_Bytes.
   --  @param Private_Scalar_Mpint the SSH mpint signing private scalar
   --  @param Message_Bytes        the message to sign
   --  @param Signature_Bytes      the produced SSH-wire ecdsa signature blob
   --  @return Ok when signing succeeds, a non-Ok Status otherwise
   function Sign_Nistp521
     (Private_Scalar_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes        : Ada.Streams.Stream_Element_Array;
      Signature_Bytes      : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Validate a raw SEC1-encoded P-256 point (curve membership, not identity).
   --  @param Public_Point_Bytes the raw uncompressed SEC1 point octet string
   --  @return Ok when the point is valid and on the curve, a non-Ok Status
   --          otherwise
   function Validate_Raw_Point_Nistp256
     (Public_Point_Bytes : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Validate a raw SEC1-encoded P-384 point (curve membership, not identity).
   --  @param Public_Point_Bytes the raw uncompressed SEC1 point octet string
   --  @return Ok when the point is valid and on the curve, a non-Ok Status
   --          otherwise
   function Validate_Raw_Point_Nistp384
     (Public_Point_Bytes : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Validate a raw SEC1-encoded P-521 point (curve membership, not identity).
   --  @param Public_Point_Bytes the raw uncompressed SEC1 point octet string
   --  @return Ok when the point is valid and on the curve, a non-Ok Status
   --          otherwise
   function Validate_Raw_Point_Nistp521
     (Public_Point_Bytes : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Generate an ephemeral P-256 ECDH key pair from a random source.
   --  @param Source_Item          the random source drawn on for the scalar
   --  @param Private_Scalar_Bytes the generated private scalar octets
   --  @param Public_Point_Bytes   the matching raw SEC1 public point octets
   --  @return Ok when generation succeeds, a non-Ok Status otherwise
   function Generate_ECDH_Nistp256_Keypair
     (Source_Item          : in out CryptoLib.Random.Random_Source;
      Private_Scalar_Bytes : out Ada.Streams.Stream_Element_Array;
      Public_Point_Bytes   : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Validate a P-256 ECDH shared secret (non-zero, expected width).
   --  @param Shared_Secret_Bytes the raw shared-secret X-coordinate octets
   --  @return Ok when the shared secret is valid, a non-Ok Status otherwise
   function Validate_ECDH_Nistp256_Shared_Secret
     (Shared_Secret_Bytes : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Compute the P-256 ECDH shared secret from our scalar and the peer point.
   --  @param Private_Scalar_Bytes our ephemeral private scalar octets
   --  @param Server_Point_Bytes   the peer's raw SEC1 public point octets
   --  @param Shared_Secret_Bytes  the resulting shared X-coordinate octets
   --  @return Ok when computation succeeds, a non-Ok Status otherwise
   function Compute_ECDH_Nistp256_Shared_Secret
     (Private_Scalar_Bytes : Ada.Streams.Stream_Element_Array;
      Server_Point_Bytes   : Ada.Streams.Stream_Element_Array;
      Shared_Secret_Bytes  : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Generate an ephemeral P-384 ECDH key pair from a random source.
   --  @param Source_Item          the random source drawn on for the scalar
   --  @param Private_Scalar_Bytes the generated private scalar octets
   --  @param Public_Point_Bytes   the matching raw SEC1 public point octets
   --  @return Ok when generation succeeds, a non-Ok Status otherwise
   function Generate_ECDH_Nistp384_Keypair
     (Source_Item          : in out CryptoLib.Random.Random_Source;
      Private_Scalar_Bytes : out Ada.Streams.Stream_Element_Array;
      Public_Point_Bytes   : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Validate a P-384 ECDH shared secret (non-zero, expected width).
   --  @param Shared_Secret_Bytes the raw shared-secret X-coordinate octets
   --  @return Ok when the shared secret is valid, a non-Ok Status otherwise
   function Validate_ECDH_Nistp384_Shared_Secret
     (Shared_Secret_Bytes : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Compute the P-384 ECDH shared secret from our scalar and the peer point.
   --  @param Private_Scalar_Bytes our ephemeral private scalar octets
   --  @param Server_Point_Bytes   the peer's raw SEC1 public point octets
   --  @param Shared_Secret_Bytes  the resulting shared X-coordinate octets
   --  @return Ok when computation succeeds, a non-Ok Status otherwise
   function Compute_ECDH_Nistp384_Shared_Secret
     (Private_Scalar_Bytes : Ada.Streams.Stream_Element_Array;
      Server_Point_Bytes   : Ada.Streams.Stream_Element_Array;
      Shared_Secret_Bytes  : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Generate an ephemeral P-521 ECDH key pair from a random source.
   --  @param Source_Item          the random source drawn on for the scalar
   --  @param Private_Scalar_Bytes the generated private scalar octets
   --  @param Public_Point_Bytes   the matching raw SEC1 public point octets
   --  @return Ok when generation succeeds, a non-Ok Status otherwise
   function Generate_ECDH_Nistp521_Keypair
     (Source_Item          : in out CryptoLib.Random.Random_Source;
      Private_Scalar_Bytes : out Ada.Streams.Stream_Element_Array;
      Public_Point_Bytes   : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Validate a P-521 ECDH shared secret (non-zero, expected width).
   --  @param Shared_Secret_Bytes the raw shared-secret X-coordinate octets
   --  @return Ok when the shared secret is valid, a non-Ok Status otherwise
   function Validate_ECDH_Nistp521_Shared_Secret
     (Shared_Secret_Bytes : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Compute the P-521 ECDH shared secret from our scalar and the peer point.
   --  @param Private_Scalar_Bytes our ephemeral private scalar octets
   --  @param Server_Point_Bytes   the peer's raw SEC1 public point octets
   --  @param Shared_Secret_Bytes  the resulting shared X-coordinate octets
   --  @return Ok when computation succeeds, a non-Ok Status otherwise
   function Compute_ECDH_Nistp521_Shared_Secret
     (Private_Scalar_Bytes : Ada.Streams.Stream_Element_Array;
      Server_Point_Bytes   : Ada.Streams.Stream_Element_Array;
      Shared_Secret_Bytes  : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;
end SSH_Lib.ECDSA;
