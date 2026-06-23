with CryptoLib.Errors;

package SSH_Lib.Identity_Files.Parser is
   function Parse_Text
     (Text : String;
      Item : out SSH_Lib.Identity_Files.Identity_Key)
      return CryptoLib.Errors.Status;

   function Parse_Text
     (Text       : String;
      Passphrase : String;
      Item       : out SSH_Lib.Identity_Files.Identity_Key)
      return CryptoLib.Errors.Status;
end SSH_Lib.Identity_Files.Parser;
