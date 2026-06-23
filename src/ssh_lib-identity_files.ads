with Ada.Streams;
with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Identity_Files is
   Max_Identity_File_Size : constant Natural := 1024 * 1024;
   Max_Identity_Comment_Length : constant Natural := 4096;

   type Key_Kind is (No_Key, Ed25519_Key, RSA_Key, ECDSA_Nistp256_Key, Unsupported_Key);
   type Identity_Key is private;

   procedure Clear (Item : out Identity_Key);

   function Load
     (Path : String;
      Item : out Identity_Key)
      return CryptoLib.Errors.Status;

   function Load
     (Path       : String;
      Passphrase : String;
      Item       : out Identity_Key)
      return CryptoLib.Errors.Status;

   function Attach_Public_Certificate
     (Path : String;
      Item : in out Identity_Key)
      return CryptoLib.Errors.Status;

   function Parse
     (Text : String;
      Item : out Identity_Key)
      return CryptoLib.Errors.Status;

   function Parse
     (Text       : String;
      Passphrase : String;
      Item       : out Identity_Key)
      return CryptoLib.Errors.Status;

   function Kind (Item : Identity_Key) return Key_Kind;

   function Algorithm_Name (Item : Identity_Key) return String;

   function Has_Public_Certificate (Item : Identity_Key) return Boolean;

   function Certificate_Algorithm_Name (Item : Identity_Key) return String;

   function Certificate_Public_Key_Blob
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   function Public_Key_Blob
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

private
   type Identity_Key is record
      Key_Type : Key_Kind := No_Key;
      Algorithm : Ada.Strings.Unbounded.Unbounded_String;
      Public_Blob : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Ed25519_Seed : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Ed25519_Public : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      RSA_Exponent : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      RSA_Modulus : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      RSA_Private_Exponent : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      RSA_Prime_P : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      RSA_Prime_Q : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      RSA_Exponent_DMP1 : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      RSA_Exponent_DMQ1 : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      RSA_Coefficient_IQMP : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      ECDSA_Curve : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      ECDSA_Public : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      ECDSA_Private : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Has_Certificate : Boolean := False;
      Certificate_Algorithm : Ada.Strings.Unbounded.Unbounded_String;
      Certificate_Blob : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;
end SSH_Lib.Identity_Files;
