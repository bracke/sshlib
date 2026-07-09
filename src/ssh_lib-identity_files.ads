with Ada.Streams;
with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Loads and parses OpenSSH private-key identity files.
--
--  Reads the OpenSSH new-format ("BEGIN OPENSSH PRIVATE KEY") private key,
--  optionally decrypting a passphrase-protected key, and exposes the parsed
--  Ed25519, RSA or ECDSA material together with its SSH public-key blob and
--  algorithm name.  An optional public certificate (*-cert.pub) can be attached
--  so the identity authenticates with a certificate instead of a bare key.
package SSH_Lib.Identity_Files is
   Max_Identity_File_Size : constant Natural := 1024 * 1024;
   Max_Identity_Comment_Length : constant Natural := 4096;

   type Key_Kind is
     (No_Key,
      Ed25519_Key,
      RSA_Key,
      ECDSA_Nistp256_Key,
      ECDSA_Nistp384_Key,
      ECDSA_Nistp521_Key,
      Unsupported_Key);
   type Identity_Key is private;

   --  Reset an identity key to the empty state, scrubbing any secret material.
   --  @param Item the identity key to clear
   procedure Clear (Item : out Identity_Key);

   --  Load an unencrypted private-key identity file from disk.
   --  @param Path the filesystem path to the private-key file
   --  @param Item the parsed identity key on success
   --  @return Ok on success, or an error status on I/O or parse failure
   function Load
     (Path : String;
      Item : out Identity_Key)
      return CryptoLib.Errors.Status;

   --  Load a private-key identity file, decrypting it with the passphrase.
   --  @param Path the filesystem path to the private-key file
   --  @param Passphrase the passphrase protecting the key
   --  @param Item the parsed identity key on success
   --  @return Ok on success, or an error status on I/O, decrypt or parse failure
   function Load
     (Path       : String;
      Passphrase : String;
      Item       : out Identity_Key)
      return CryptoLib.Errors.Status;

   --  Attach a public certificate (*-cert.pub) read from disk to an identity.
   --  @param Path the filesystem path to the certificate file
   --  @param Item the identity key to attach the certificate to
   --  @return Ok on success, or an error status on I/O or parse failure
   function Attach_Public_Certificate
     (Path : String;
      Item : in out Identity_Key)
      return CryptoLib.Errors.Status;

   --  Parse an unencrypted private key from an in-memory text buffer.
   --  @param Text the identity file contents to parse
   --  @param Item the parsed identity key on success
   --  @return Ok on success, or an error status on parse failure
   function Parse
     (Text : String;
      Item : out Identity_Key)
      return CryptoLib.Errors.Status;

   --  Parse a private key from an in-memory text buffer, decrypting it.
   --  @param Text the identity file contents to parse
   --  @param Passphrase the passphrase protecting the key
   --  @param Item the parsed identity key on success
   --  @return Ok on success, or an error status on decrypt or parse failure
   function Parse
     (Text       : String;
      Passphrase : String;
      Item       : out Identity_Key)
      return CryptoLib.Errors.Status;

   --  Report which key algorithm family the identity holds.
   --  @param Item the identity key to inspect
   --  @return the key kind, or No_Key when the identity is empty
   function Kind (Item : Identity_Key) return Key_Kind;

   --  Return the SSH algorithm name of the key (e.g. "ssh-ed25519").
   --  @param Item the identity key to inspect
   --  @return the SSH public-key algorithm name string
   function Algorithm_Name (Item : Identity_Key) return String;

   --  Report whether a public certificate is attached to the identity.
   --  @param Item the identity key to inspect
   --  @return True when a certificate has been attached, False otherwise
   function Has_Public_Certificate (Item : Identity_Key) return Boolean;

   --  Return the SSH algorithm name of the attached certificate.
   --  @param Item the identity key to inspect
   --  @return the certificate algorithm name string, empty when none attached
   function Certificate_Algorithm_Name (Item : Identity_Key) return String;

   --  Return the wire-format public-key blob of the attached certificate.
   --  @param Item the identity key to inspect
   --  @return the certificate public-key blob, empty when none attached
   function Certificate_Public_Key_Blob
     (Item : Identity_Key)
      return Ada.Streams.Stream_Element_Array;

   --  Return the SSH wire-format public-key blob of the identity's key.
   --  @param Item the identity key to inspect
   --  @return the SSH public-key blob for the key
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
