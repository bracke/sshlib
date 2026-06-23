package body SSH_Lib.Identity_Files.Parser is
   function Parse_Text
     (Text : String;
      Item : out SSH_Lib.Identity_Files.Identity_Key)
      return CryptoLib.Errors.Status
   is
   begin
      return SSH_Lib.Identity_Files.Parse (Text, Item);
   end Parse_Text;

   function Parse_Text
     (Text       : String;
      Passphrase : String;
      Item       : out SSH_Lib.Identity_Files.Identity_Key)
      return CryptoLib.Errors.Status
   is
   begin
      return SSH_Lib.Identity_Files.Parse (Text, Passphrase, Item);
   end Parse_Text;
end SSH_Lib.Identity_Files.Parser;
