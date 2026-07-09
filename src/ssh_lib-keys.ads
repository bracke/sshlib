with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary SSH public-key and host-key handling: loading, algorithms, and
--  fingerprints.
--
--  Wraps a parsed public identity or wire-format public key, reports its
--  algorithm and validity, and computes OpenSSH-style key fingerprints
--  (SHA-256, MD5, or a named hash) for display and comparison.
package SSH_Lib.Keys is
   type Public_Key_Algorithm is
     (Unknown,
      Ssh_Rsa,
      Rsa_Sha2_256,
      Rsa_Sha2_512,
      Ssh_Ed25519,
      Ecdsa_Sha2_Nistp256,
      Ecdsa_Sha2_Nistp384,
      Ecdsa_Sha2_Nistp521,
      Sk_Ssh_Ed25519,
      Sk_Ecdsa_Sha2_Nistp256);

   type Identity is private;
   type Public_Key is private;
   type Fingerprint is private;

   --  Load a public identity from an OpenSSH ".pub" file at Path.
   --  @param Path the filesystem path of the public-key file to read
   --  @param Item the parsed identity (algorithm and public-key text)
   --  @return Ok on success, or an error Status if the file is missing or malformed
   function Load_Public_Identity
     (Path : String;
      Item : out Identity)
      return CryptoLib.Errors.Status;

   --  The public-key algorithm of a loaded identity.
   --  @param Item the identity to query
   --  @return the algorithm enumerator, Unknown if unrecognized
   function Algorithm (Item : Identity) return Public_Key_Algorithm;

   --  The raw public-key text of a loaded identity (the OpenSSH ".pub" line).
   --  @param Item the identity to query
   --  @return the public-key text
   function Public_Text (Item : Identity) return String;

   --  The wire algorithm name of a public key (e.g. "ssh-ed25519").
   --  @param Item the public key to query
   --  @return the algorithm name string
   function Algorithm (Item : Public_Key) return String;

   --  Whether a public key holds present, well-formed key material.
   --  @param Item the public key to test
   --  @return True if the key is present and valid
   function Is_Valid (Item : Public_Key) return Boolean;

   --  Compute the OpenSSH SHA-256 (base64) fingerprint of a public key.
   --  @param Item  the public key to fingerprint
   --  @param Value the resulting fingerprint
   --  @return Ok on success, or an error Status on failure
   function SHA256_Fingerprint
     (Item  : Public_Key;
      Value : out Fingerprint)
      return CryptoLib.Errors.Status;

   --  Compute the legacy MD5 (colon-hex) fingerprint of a public key.
   --  @param Item  the public key to fingerprint
   --  @param Value the resulting fingerprint
   --  @return Ok on success, or an error Status on failure
   function MD5_Fingerprint
     (Item  : Public_Key;
      Value : out Fingerprint)
      return CryptoLib.Errors.Status;

   --  Compute a public-key fingerprint using a named hash algorithm.
   --  @param Item      the public key to fingerprint
   --  @param Hash_Name the hash name (e.g. "sha256", "md5")
   --  @param Value     the resulting fingerprint
   --  @return Ok on success, or an error Status if the hash name is unsupported
   function Fingerprint_With_Hash
     (Item      : Public_Key;
      Hash_Name : String;
      Value     : out Fingerprint)
      return CryptoLib.Errors.Status;

   --  The printable text of a fingerprint.
   --  @param Item the fingerprint to render
   --  @return the fingerprint as a displayable string
   function Image (Item : Fingerprint) return String;

   --  Whether two fingerprints are equal.
   --  @param Left_Item  the first fingerprint
   --  @param Right_Item the second fingerprint
   --  @return True if the two fingerprints are identical
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
