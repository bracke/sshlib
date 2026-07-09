with Ada.Streams;
with CryptoLib.Errors;
with CryptoLib.Buffers;

--  @summary SSH RSA signature verification and signing (ssh-rsa / rsa-sha2).
--
--  Verifies and produces RSASSA-PKCS1-v1_5 signatures over an SSH message using
--  an ssh-rsa public-key blob, for the legacy SHA-1 ("ssh-rsa") algorithm and
--  the SHA-256/SHA-512 ("rsa-sha2-256"/"rsa-sha2-512") algorithms.  Signing is
--  offered both with a plain private exponent and with the faster CRT form
--  (primes p, q and the CRT exponents/coefficient).
package SSH_Lib.RSA is
   --  Verify a legacy "ssh-rsa" (SHA-1) signature over a message.
   --  @param Public_Key_Blob the ssh-rsa public-key blob (e and n)
   --  @param Signature_Bytes the ssh-rsa signature blob to verify
   --  @param Message_Bytes   the signed message bytes
   --  @return Ok if the signature is valid, else a verification failure status
   function Verify_SHA1
     (Public_Key_Blob : Ada.Streams.Stream_Element_Array;
      Signature_Bytes : Ada.Streams.Stream_Element_Array;
      Message_Bytes   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Verify an "rsa-sha2-256" or "rsa-sha2-512" signature over a message.
   --  @param Algorithm_Name  the signature algorithm ("rsa-sha2-256"/"-512")
   --  @param Public_Key_Blob the ssh-rsa public-key blob (e and n)
   --  @param Signature_Bytes the signature blob to verify
   --  @param Message_Bytes   the signed message bytes
   --  @return Ok if the signature is valid, else a verification failure status
   function Verify_SHA2
     (Algorithm_Name : String;
      Public_Key_Blob : Ada.Streams.Stream_Element_Array;
      Signature_Bytes : Ada.Streams.Stream_Element_Array;
      Message_Bytes   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Check that an ssh-rsa public-key blob is well-formed and usable.
   --  @param Public_Key_Blob the ssh-rsa public-key blob to validate
   --  @return Ok if the blob is a valid ssh-rsa key, else a failure status
   function Validate_Public_Key_Blob
     (Public_Key_Blob : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Produce a legacy "ssh-rsa" (SHA-1) signature over a message.
   --  @param Public_Key_Blob        the ssh-rsa public-key blob (e and n)
   --  @param Private_Exponent_Mpint the RSA private exponent d as an mpint
   --  @param Message_Bytes          the message bytes to sign
   --  @param Signature_Bytes        the produced ssh-rsa signature blob
   --  @return Ok on success, else a signing failure status
   function Sign_SHA1
     (Public_Key_Blob        : Ada.Streams.Stream_Element_Array;
      Private_Exponent_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes          : Ada.Streams.Stream_Element_Array;
      Signature_Bytes        : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Produce an "rsa-sha2-256" signature over a message.
   --  @param Public_Key_Blob        the ssh-rsa public-key blob (e and n)
   --  @param Private_Exponent_Mpint the RSA private exponent d as an mpint
   --  @param Message_Bytes          the message bytes to sign
   --  @param Signature_Bytes        the produced rsa-sha2-256 signature blob
   --  @return Ok on success, else a signing failure status
   function Sign_SHA2_256
     (Public_Key_Blob        : Ada.Streams.Stream_Element_Array;
      Private_Exponent_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes          : Ada.Streams.Stream_Element_Array;
      Signature_Bytes        : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Produce an "rsa-sha2-512" signature over a message.
   --  @param Public_Key_Blob        the ssh-rsa public-key blob (e and n)
   --  @param Private_Exponent_Mpint the RSA private exponent d as an mpint
   --  @param Message_Bytes          the message bytes to sign
   --  @param Signature_Bytes        the produced rsa-sha2-512 signature blob
   --  @return Ok on success, else a signing failure status
   function Sign_SHA2_512
     (Public_Key_Blob        : Ada.Streams.Stream_Element_Array;
      Private_Exponent_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes          : Ada.Streams.Stream_Element_Array;
      Signature_Bytes        : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Produce a legacy "ssh-rsa" (SHA-1) signature using CRT private parameters.
   --  @param Public_Key_Blob        the ssh-rsa public-key blob (e and n)
   --  @param Prime_P_Mpint          the RSA prime p as an mpint
   --  @param Prime_Q_Mpint          the RSA prime q as an mpint
   --  @param Exponent_DMP1_Mpint    the CRT exponent d mod (p-1) as an mpint
   --  @param Exponent_DMQ1_Mpint    the CRT exponent d mod (q-1) as an mpint
   --  @param Coefficient_IQMP_Mpint the CRT coefficient q^-1 mod p as an mpint
   --  @param Message_Bytes          the message bytes to sign
   --  @param Signature_Bytes        the produced ssh-rsa signature blob
   --  @return Ok on success, else a signing failure status
   function Sign_SHA1_CRT
     (Public_Key_Blob       : Ada.Streams.Stream_Element_Array;
      Prime_P_Mpint         : Ada.Streams.Stream_Element_Array;
      Prime_Q_Mpint         : Ada.Streams.Stream_Element_Array;
      Exponent_DMP1_Mpint   : Ada.Streams.Stream_Element_Array;
      Exponent_DMQ1_Mpint   : Ada.Streams.Stream_Element_Array;
      Coefficient_IQMP_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes         : Ada.Streams.Stream_Element_Array;
      Signature_Bytes       : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Produce an "rsa-sha2-256" signature using CRT private parameters.
   --  @param Public_Key_Blob        the ssh-rsa public-key blob (e and n)
   --  @param Prime_P_Mpint          the RSA prime p as an mpint
   --  @param Prime_Q_Mpint          the RSA prime q as an mpint
   --  @param Exponent_DMP1_Mpint    the CRT exponent d mod (p-1) as an mpint
   --  @param Exponent_DMQ1_Mpint    the CRT exponent d mod (q-1) as an mpint
   --  @param Coefficient_IQMP_Mpint the CRT coefficient q^-1 mod p as an mpint
   --  @param Message_Bytes          the message bytes to sign
   --  @param Signature_Bytes        the produced rsa-sha2-256 signature blob
   --  @return Ok on success, else a signing failure status
   function Sign_SHA2_256_CRT
     (Public_Key_Blob       : Ada.Streams.Stream_Element_Array;
      Prime_P_Mpint         : Ada.Streams.Stream_Element_Array;
      Prime_Q_Mpint         : Ada.Streams.Stream_Element_Array;
      Exponent_DMP1_Mpint   : Ada.Streams.Stream_Element_Array;
      Exponent_DMQ1_Mpint   : Ada.Streams.Stream_Element_Array;
      Coefficient_IQMP_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes         : Ada.Streams.Stream_Element_Array;
      Signature_Bytes       : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Produce an "rsa-sha2-512" signature using CRT private parameters.
   --  @param Public_Key_Blob        the ssh-rsa public-key blob (e and n)
   --  @param Prime_P_Mpint          the RSA prime p as an mpint
   --  @param Prime_Q_Mpint          the RSA prime q as an mpint
   --  @param Exponent_DMP1_Mpint    the CRT exponent d mod (p-1) as an mpint
   --  @param Exponent_DMQ1_Mpint    the CRT exponent d mod (q-1) as an mpint
   --  @param Coefficient_IQMP_Mpint the CRT coefficient q^-1 mod p as an mpint
   --  @param Message_Bytes          the message bytes to sign
   --  @param Signature_Bytes        the produced rsa-sha2-512 signature blob
   --  @return Ok on success, else a signing failure status
   function Sign_SHA2_512_CRT
     (Public_Key_Blob       : Ada.Streams.Stream_Element_Array;
      Prime_P_Mpint         : Ada.Streams.Stream_Element_Array;
      Prime_Q_Mpint         : Ada.Streams.Stream_Element_Array;
      Exponent_DMP1_Mpint   : Ada.Streams.Stream_Element_Array;
      Exponent_DMQ1_Mpint   : Ada.Streams.Stream_Element_Array;
      Coefficient_IQMP_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes         : Ada.Streams.Stream_Element_Array;
      Signature_Bytes       : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;
end SSH_Lib.RSA;
