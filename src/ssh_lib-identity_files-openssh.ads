with CryptoLib.Errors;

package SSH_Lib.Identity_Files.OpenSSH is
   function Is_OpenSSH_Armor (Text : String) return Boolean;

   function Parse
     (Text : String;
      Item : out SSH_Lib.Identity_Files.Identity_Key)
      return CryptoLib.Errors.Status;

   function Parse
     (Text       : String;
      Passphrase : String;
      Item       : out SSH_Lib.Identity_Files.Identity_Key)
      return CryptoLib.Errors.Status;
end SSH_Lib.Identity_Files.OpenSSH;
