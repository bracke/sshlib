package SSH_Lib.Identity_Files.PEM is
   function Is_Legacy_PEM_Armor (Text : String) return Boolean;
   function Is_Encrypted_PEM_Armor (Text : String) return Boolean;
end SSH_Lib.Identity_Files.PEM;
