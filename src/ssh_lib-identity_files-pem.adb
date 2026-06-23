package body SSH_Lib.Identity_Files.PEM is
   function Contains
     (Text : String;
      Needle : String)
      return Boolean
   is
   begin
      if Text'Length < Needle'Length then
         return False;
      end if;
      for Index_Value in Text'First .. Text'Last - Needle'Length + 1 loop
         if Text (Index_Value .. Index_Value + Needle'Length - 1) = Needle then
            return True;
         end if;
      end loop;
      return False;
   end Contains;

   function Is_Legacy_PEM_Armor (Text : String) return Boolean is
   begin
      return Contains (Text, "-----BEGIN RSA PRIVATE KEY-----")
        or else Contains (Text, "-----BEGIN EC PRIVATE KEY-----")
        or else Contains (Text, "-----BEGIN PRIVATE KEY-----")
        or else Contains (Text, "-----BEGIN ENCRYPTED PRIVATE KEY-----");
   end Is_Legacy_PEM_Armor;

   function Is_Encrypted_PEM_Armor (Text : String) return Boolean is
   begin
      return Contains (Text, "-----BEGIN ENCRYPTED PRIVATE KEY-----")
        or else Contains (Text, "Proc-Type: 4,ENCRYPTED")
        or else Contains (Text, "DEK-Info:");
   end Is_Encrypted_PEM_Armor;
end SSH_Lib.Identity_Files.PEM;
