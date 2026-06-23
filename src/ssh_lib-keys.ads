with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Keys is
   type Public_Key_Algorithm is
     (Unknown,
      Ssh_Rsa,
      Rsa_Sha2_256,
      Rsa_Sha2_512,
      Ssh_Ed25519,
      Ecdsa_Sha2_Nistp256,
      Sk_Ssh_Ed25519,
      Sk_Ecdsa_Sha2_Nistp256);

   type Identity is private;
   type Public_Key is private;
   type Fingerprint is private;

   function Load_Public_Identity
     (Path : String;
      Item : out Identity)
      return CryptoLib.Errors.Status;

   function Algorithm (Item : Identity) return Public_Key_Algorithm;
   function Public_Text (Item : Identity) return String;

   function Algorithm (Item : Public_Key) return String;

   function Is_Valid (Item : Public_Key) return Boolean;

   function SHA256_Fingerprint
     (Item  : Public_Key;
      Value : out Fingerprint)
      return CryptoLib.Errors.Status;

   function Image (Item : Fingerprint) return String;

   function Equal
     (Left_Item  : Fingerprint;
      Right_Item : Fingerprint)
      return Boolean;

private
   type Identity is record
      Kind : Public_Key_Algorithm := Unknown;
      Text : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   type Public_Key is record
      Present        : Boolean := False;
      Algorithm_Text : Ada.Strings.Unbounded.Unbounded_String;
      Blob_Data      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;

   type Fingerprint is record
      Text : Ada.Strings.Unbounded.Unbounded_String;
   end record;
end SSH_Lib.Keys;
