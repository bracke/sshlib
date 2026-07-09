with Ada.Streams;

--  @summary Signing-capability gate exposing a loaded identity key's raw secret and public components.
--
--  This child package is the controlled seam through which the signing code
--  reads the private and public scalars of a parsed Identity_Key (Ed25519, RSA,
--  and ECDSA).  Each accessor returns the corresponding component as a byte
--  array so callers can build SSH signatures without the key record exposing
--  those fields directly.
package SSH_Lib.Identity_Files.Signing_Access is
   --  Return the 32-byte Ed25519 private seed of the identity key.
   --  @param Item the loaded identity key
   --  @return the Ed25519 secret seed bytes
   function Ed25519_Seed
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   --  Return the 32-byte Ed25519 public key of the identity key.
   --  @param Item the loaded identity key
   --  @return the Ed25519 public key bytes
   function Ed25519_Public
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   --  Return the RSA public exponent (e) of the identity key.
   --  @param Item the loaded identity key
   --  @return the big-endian RSA public exponent bytes
   function RSA_Exponent
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   --  Return the RSA modulus (n) of the identity key.
   --  @param Item the loaded identity key
   --  @return the big-endian RSA modulus bytes
   function RSA_Modulus
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   --  Return the RSA private exponent (d) of the identity key.
   --  @param Item the loaded identity key
   --  @return the big-endian RSA private exponent bytes
   function RSA_Private_Exponent
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   --  Return the RSA first prime factor (p) of the identity key.
   --  @param Item the loaded identity key
   --  @return the big-endian RSA prime p bytes
   function RSA_Prime_P
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   --  Return the RSA second prime factor (q) of the identity key.
   --  @param Item the loaded identity key
   --  @return the big-endian RSA prime q bytes
   function RSA_Prime_Q
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   --  Return the RSA CRT exponent d mod (p-1) (dmp1) of the identity key.
   --  @param Item the loaded identity key
   --  @return the big-endian RSA CRT exponent dmp1 bytes
   function RSA_Exponent_DMP1
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   --  Return the RSA CRT exponent d mod (q-1) (dmq1) of the identity key.
   --  @param Item the loaded identity key
   --  @return the big-endian RSA CRT exponent dmq1 bytes
   function RSA_Exponent_DMQ1
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   --  Return the RSA CRT coefficient q^-1 mod p (iqmp) of the identity key.
   --  @param Item the loaded identity key
   --  @return the big-endian RSA CRT coefficient iqmp bytes
   function RSA_Coefficient_IQMP
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   --  Return the ECDSA private scalar of the identity key.
   --  @param Item the loaded identity key
   --  @return the big-endian ECDSA private key bytes
   function ECDSA_Private
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;
end SSH_Lib.Identity_Files.Signing_Access;
