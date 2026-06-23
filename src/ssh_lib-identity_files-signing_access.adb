with SSH_Lib.Protocol.Buffers;

package body SSH_Lib.Identity_Files.Signing_Access is
   function Ed25519_Seed
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Item.Ed25519_Seed);
   end Ed25519_Seed;

   function Ed25519_Public
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Item.Ed25519_Public);
   end Ed25519_Public;

   function RSA_Exponent
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Item.RSA_Exponent);
   end RSA_Exponent;

   function RSA_Modulus
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Item.RSA_Modulus);
   end RSA_Modulus;

   function RSA_Private_Exponent
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Item.RSA_Private_Exponent);
   end RSA_Private_Exponent;

   function RSA_Prime_P
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Item.RSA_Prime_P);
   end RSA_Prime_P;

   function RSA_Prime_Q
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Item.RSA_Prime_Q);
   end RSA_Prime_Q;

   function RSA_Exponent_DMP1
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Item.RSA_Exponent_DMP1);
   end RSA_Exponent_DMP1;

   function RSA_Exponent_DMQ1
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Item.RSA_Exponent_DMQ1);
   end RSA_Exponent_DMQ1;

   function RSA_Coefficient_IQMP
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Item.RSA_Coefficient_IQMP);
   end RSA_Coefficient_IQMP;

   function ECDSA_Private
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Item.ECDSA_Private);
   end ECDSA_Private;
end SSH_Lib.Identity_Files.Signing_Access;
