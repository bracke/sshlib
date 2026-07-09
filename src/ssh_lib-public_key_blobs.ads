with Ada.Streams;
with Ada.Strings.Unbounded;
with CryptoLib.Errors;

--  @summary Inspection of SSH public-key blobs.
--
--  Reads the leading algorithm-name string from an SSH-encoded public-key blob
--  (validating it as an ASCII protocol name), and recognizes the userauth
--  public-key algorithm names the library offers by default.
package SSH_Lib.Public_Key_Blobs is
   --  Extract the algorithm name (the first SSH string) from a public-key blob,
   --  rejecting empty or non-ASCII-protocol names.
   --  @param Key_Blob the SSH-encoded public-key blob
   --  @param Name     the decoded leading algorithm name
   --  @return Ok on success, an error status on a malformed or invalid name
   function Algorithm_Name
     (Key_Blob : Ada.Streams.Stream_Element_Array;
      Name     : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  True when Name is one of the userauth public-key algorithms enabled by
   --  default (Ed25519, ECDSA, sk-* security keys, RSA-SHA2, ssh-rsa, and their
   --  certificate variants).
   --  @param Name the public-key algorithm name to test
   --  @return True if the algorithm is a default userauth algorithm
   function Is_Default_Userauth_Algorithm
     (Name : String)
      return Boolean;
end SSH_Lib.Public_Key_Blobs;
