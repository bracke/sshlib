package body SSH_Lib.Identity_Files.OpenSSH is
   OpenSSH_Begin : constant String := "-----BEGIN OPENSSH PRIVATE KEY-----";

   function Is_OpenSSH_Armor (Text : String) return Boolean is
   begin
      if Text'Length < OpenSSH_Begin'Length then
         return False;
      end if;
      for Index_Value in Text'First .. Text'Last - OpenSSH_Begin'Length + 1 loop
         if Text (Index_Value .. Index_Value + OpenSSH_Begin'Length - 1) = OpenSSH_Begin then
            return True;
         end if;
      end loop;
      return False;
   end Is_OpenSSH_Armor;

   function Parse
     (Text : String;
      Item : out SSH_Lib.Identity_Files.Identity_Key)
      return CryptoLib.Errors.Status
   is
   begin
      return Parse (Text, "", Item);
   end Parse;

   function Parse
     (Text       : String;
      Passphrase : String;
      Item       : out SSH_Lib.Identity_Files.Identity_Key)
      return CryptoLib.Errors.Status
   is
   begin
      if not Is_OpenSSH_Armor (Text) then
         SSH_Lib.Identity_Files.Clear (Item);
         return CryptoLib.Errors.Authentication_Failed;
      end if;
      return SSH_Lib.Identity_Files.Parse (Text, Passphrase, Item);
   end Parse;
end SSH_Lib.Identity_Files.OpenSSH;
