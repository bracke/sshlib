with CryptoLib.Errors;

--  @summary Thin entry points for parsing identity-file text into a key.
--
--  Wraps SSH_Lib.Identity_Files.Parse with unencrypted and passphrase-protected
--  overloads that turn the on-disk text of a private key into an Identity_Key.
package SSH_Lib.Identity_Files.Parser is
   --  Parse the text of an unencrypted identity file into a key.
   --  @param Text the full text of the identity file
   --  @param Item the resulting parsed identity key
   --  @return Ok on a successful parse, otherwise the failure status
   function Parse_Text
     (Text : String;
      Item : out SSH_Lib.Identity_Files.Identity_Key)
      return CryptoLib.Errors.Status;

   --  Parse the text of a passphrase-encrypted identity file into a key.
   --  @param Text       the full text of the identity file
   --  @param Passphrase the passphrase used to decrypt the private key
   --  @param Item       the resulting parsed identity key
   --  @return Ok on a successful parse, otherwise the failure status
   function Parse_Text
     (Text       : String;
      Passphrase : String;
      Item       : out SSH_Lib.Identity_Files.Identity_Key)
      return CryptoLib.Errors.Status;
end SSH_Lib.Identity_Files.Parser;
