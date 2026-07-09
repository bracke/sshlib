with CryptoLib.Errors;

--  @summary Detection and parsing of OpenSSH-armored private key files.
--
--  Recognizes the "-----BEGIN OPENSSH PRIVATE KEY-----" armor and decodes such
--  a key (optionally passphrase-protected) into an Identity_Key, rejecting any
--  text that is not in the OpenSSH format.
package SSH_Lib.Identity_Files.OpenSSH is
   --  Report whether Text contains the OpenSSH private-key armor header.
   --  @param Text the candidate key file contents
   --  @return True if the OpenSSH BEGIN armor line is present, False otherwise
   function Is_OpenSSH_Armor (Text : String) return Boolean;

   --  Parse an unencrypted OpenSSH-armored private key into Item.
   --  @param Text the OpenSSH-armored key file contents
   --  @param Item the decoded identity key on success, cleared on failure
   --  @return Ok on success, Authentication_Failed if Text is not OpenSSH armor
   function Parse
     (Text : String;
      Item : out SSH_Lib.Identity_Files.Identity_Key)
      return CryptoLib.Errors.Status;

   --  Parse a possibly passphrase-protected OpenSSH-armored private key into Item.
   --  @param Text       the OpenSSH-armored key file contents
   --  @param Passphrase the passphrase to decrypt the key, or "" if unencrypted
   --  @param Item       the decoded identity key on success, cleared on failure
   --  @return Ok on success, Authentication_Failed if Text is not OpenSSH armor
   function Parse
     (Text       : String;
      Passphrase : String;
      Item       : out SSH_Lib.Identity_Files.Identity_Key)
      return CryptoLib.Errors.Status;
end SSH_Lib.Identity_Files.OpenSSH;
