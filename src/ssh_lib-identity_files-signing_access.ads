with Ada.Streams;

package SSH_Lib.Identity_Files.Signing_Access is
   function Ed25519_Seed
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   function Ed25519_Public
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   function RSA_Exponent
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   function RSA_Modulus
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   function RSA_Private_Exponent
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   function RSA_Prime_P
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   function RSA_Prime_Q
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   function RSA_Exponent_DMP1
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   function RSA_Exponent_DMQ1
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   function RSA_Coefficient_IQMP
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   function ECDSA_Private
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;
end SSH_Lib.Identity_Files.Signing_Access;
