package SSH_Lib.Tests.Fixtures.Identity_Files is
   function Public_Test_Disclaimer return String;
   function Malformed_OpenSSH_Private_Key return String;
   function Encrypted_OpenSSH_Private_Key return String;
   function Encrypted_OpenSSH_Cipher_Private_Key return String;
   function Encrypted_OpenSSH_BCrypt_Envelope_Private_Key return String;
   function Public_Private_Mismatch_OpenSSH_Private_Key return String;
   function Unsupported_RSA_Private_Key return String;
   function Legacy_PEM_Private_Key return String;
   function RSA_1024_PKCS8_Private_Key return String;
   function Encrypted_Legacy_RSA_AES256_CBC_Private_Key return String;
   function Encrypted_PKCS8_RSA_AES256_CBC_Private_Key return String;
   function Legacy_EC_P256_Private_Key return String;
   function PKCS8_EC_P256_Private_Key return String;
   function PKCS8_V1_EC_P256_Private_Key return String;
   function Encrypted_Legacy_EC_P256_AES256_CBC_Private_Key return String;
   function Contains_Private_Key_Material (Text : String) return Boolean;
end SSH_Lib.Tests.Fixtures.Identity_Files;
