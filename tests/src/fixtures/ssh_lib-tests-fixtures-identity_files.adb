package body SSH_Lib.Tests.Fixtures.Identity_Files is

   function Public_Test_Disclaimer return String is
   begin
      return "PUBLIC TEST FIXTURE ONLY - not a real credential";
   end Public_Test_Disclaimer;

   function Malformed_OpenSSH_Private_Key return String is
   begin
      return
        "-----BEGIN OPENSSH PRIVATE KEY-----" & Character'Val (10) &
        "not-valid-base64-or-openssh-key-data" & Character'Val (10) &
        "-----END OPENSSH PRIVATE KEY-----" & Character'Val (10) &
        Public_Test_Disclaimer;
   end Malformed_OpenSSH_Private_Key;

   function Encrypted_OpenSSH_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "AAAA" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        Public_Test_Disclaimer;
   end Encrypted_OpenSSH_Private_Key;


   function Encrypted_OpenSSH_Cipher_Private_Key return String is
   begin
      return
        "-----BEGIN OPENSSH PRIVATE KEY-----" & Character'Val (10) &
        "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAA2tkZgAAAAEAAA" & Character'Val (10) &
        "AzAAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g" & Character'Val (10) &
        "AAAAlhEiM0QRIjNEAAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFR" & Character'Val (10) &
        "YXGBkaGxwdHh8gAAAAQGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEAQIDBAUG" & Character'Val (10) &
        "BwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAAAAAPaWdub3JlZCBjb21tAQIDBA==" & Character'Val (10) &
        "-----END OPENSSH PRIVATE KEY-----" & Character'Val (10);
   end Encrypted_OpenSSH_Cipher_Private_Key;


   function Encrypted_OpenSSH_BCrypt_Envelope_Private_Key return String is
   begin
      return
        "-----BEGIN OPENSSH PRIVATE KEY-----" & Character'Val (10) &
        "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBzYWx0eX" & Character'Val (10) &
        "NhbHQxMjM0NTY3AAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoL" & Character'Val (10) &
        "DA0ODxAREhMUFRYXGBkaGxwdHh8gAAAAIAABAgMEBQYHCAkKCwwNDg8AAQIDBAUGBwgJCg" & Character'Val (10) &
        "sMDQ4P" & Character'Val (10) &
        "-----END OPENSSH PRIVATE KEY-----" & Character'Val (10);
   end Encrypted_OpenSSH_BCrypt_Envelope_Private_Key;

   function Public_Private_Mismatch_OpenSSH_Private_Key return String is
   begin
      return
        "-----BEGIN OPENSSH PRIVATE KEY-----" & Character'Val (10) &
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUx" & Character'Val (10) &
        "OQAAACABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIAAAAJYRIjNEESIzRAAAAAtzc2gt" & Character'Val (10) &
        "ZWQyNTUxOQAAACABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIAAAAEBlZmdoaWprbG1u" & Character'Val (10) &
        "b3BxcnN0dXZ3eHl6e3x9fn+AgYKDhAkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJAAAA" & Character'Val (10) &
        "D2lnbm9yZWQgY29tbWVudAECAwQ=" & Character'Val (10) &
        "-----END OPENSSH PRIVATE KEY-----" & Character'Val (10);
   end Public_Private_Mismatch_OpenSSH_Private_Key;

   function Unsupported_RSA_Private_Key return String is
   begin
      return
        "-----BEGIN RSA PRIVATE KEY-----" & Character'Val (10) &
        "AAAA" & Character'Val (10) &
        "-----END RSA PRIVATE KEY-----" & Character'Val (10) &
        Public_Test_Disclaimer;
   end Unsupported_RSA_Private_Key;

   function Legacy_PEM_Private_Key return String is
   begin
      return
        "-----BEGIN DSA PRIVATE KEY-----" & Character'Val (10) &
        "AAAA" & Character'Val (10) &
        "-----END DSA PRIVATE KEY-----" & Character'Val (10) &
        Public_Test_Disclaimer;
   end Legacy_PEM_Private_Key;


   function RSA_1024_PKCS8_Private_Key return String is
   begin
      return
        "-----BEGIN PRIVATE KEY-----" & Character'Val (10) &
        "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKOx/pMN19feaPno" & Character'Val (10) &
        "I87XEhA64DtMHfxgMyfyX6yPYZiNDkaXKXT79UIjvKxjHsU/TcVPj/QNPisKSq/7" & Character'Val (10) &
        "ZzmsN6UAQp4jttGT4MHyvpGiNk8x0ymAe5OWi9Ea2zzkuboQxyzGxtpLLsniB/lb" & Character'Val (10) &
        "Lq7IyBVAqcowsMLFXiJ0Don2FoBpAgMBAAECgYAp4eDAv0n6cW1qg3ql8WEtxeKZ" & Character'Val (10) &
        "SWBisjpkfh78h7Lw1SZR6VsyE0UtJvefI707unarhS/PwZOmb3usiyZeGzIhHKyF" & Character'Val (10) &
        "jc/pGznmo65qF/tKUH3ItyASkpMRF3xoC4IPUbU31nSQ4v/Jfk7Y6o2XcYXgyITy" & Character'Val (10) &
        "8ykqwI7phn+v/ji+AQJBAM+AjehlhIb/m+l6tKc9wSgxa4uYhi1CVacTNX+bX3Cs" & Character'Val (10) &
        "5SV3cpF7Yvd3/kELP3PiKgYfn4iRruLUTa8pnyg9+PcCQQDJ9FmZxLzCFeIqKj+R" & Character'Val (10) &
        "2b28UTwr9Xgec+4ZrqGn5UXN9QEZyuVpUveOV+6AJVvNnFtgEg121lDOHbUs0IsU" & Character'Val (10) &
        "jVmfAkAWgiZikCiJEE8US4gvIAbE2l+FG/1qCWkLH41NE0iOC2Mr5kIaP90jZPPC" & Character'Val (10) &
        "kHrIkj7mvSVsBgmHd2oZ1xT5o4dPAkEAv1nWy+utLfiuImWFdhxpulT+PmiHN9OA" & Character'Val (10) &
        "drUQVpTWXx8Vu+qTFAiYpzaJtMGxClBsA8sXFtJaHfHoCF5QaVjE4QJBAK9NRkG4" & Character'Val (10) &
        "hAPmkyZ7szwJxejHYedbxBGl2+y2Nk+mJ7kKCPxw8ttvA4nzEGnbrnh+pFshY5nL" & Character'Val (10) &
        "ExANAsBQ1Lu8u+g=" & Character'Val (10) &
        "-----END PRIVATE KEY-----" & Character'Val (10);
   end RSA_1024_PKCS8_Private_Key;

   function Encrypted_Legacy_RSA_AES256_CBC_Private_Key return String is
   begin
      return
        "-----BEGIN RSA PRIVATE KEY-----" & Character'Val (10) &
        "Proc-Type: 4,ENCRYPTED" & Character'Val (10) &
        "DEK-Info: AES-256-CBC,2C41B6E84DF844CF28E7AD05C21C8FC3" & Character'Val (10) &
        "" & Character'Val (10) &
        "Gj+6V4kR+CiuQ4bqv+CDMW/NHlPP0FqtmlabK894ekoSgUpkH70kBLZvD3TZYd5T" & Character'Val (10) &
        "z0jMKTDTKac1+/QdHsF1hlj3RwO9LGDeafeaytFKHUmE3S4KekfPZsuEXedmh5p3" & Character'Val (10) &
        "vV1jkC8zAGSueQhpDpVyCzMCXtV9ncLg9rS5CTILX66VbrpyfntYZnqH70GEZGMD" & Character'Val (10) &
        "rcXBasuiMH2HLan1kBfE4rrpc2dES8U2X42ExpP4hCgdGnf+PWzOQ23Y/ZuSAW/B" & Character'Val (10) &
        "tZEmjEiKt07+DMkp/EvlpyLYubEkI7oyoHOgab9iOftNRhff7akVG+x0PWGCrv34" & Character'Val (10) &
        "93/KAAsDDRV1OsduRspC0HxiSsESnhPi4zTuK1LpIQDuHCeZWz2v1gk2CftUUIjc" & Character'Val (10) &
        "8UlNa4WgEcJrz/3OT+uS/8ReIxBC1t5no/YWFMMZ/cf7iSyVyIW5bMo0jXF4h/gD" & Character'Val (10) &
        "ZjWLh9GZpopmzawYqrDo8m21MD8ZdASuCBdUK/uXK/ZmF5aob0v9svLmDiM0RpPC" & Character'Val (10) &
        "KkWe1dxUKh6yTTWtpJsyrEQnpj7bpFBwVLD7TKSZ8s8hd2TAbsX2KWlESF5smfxd" & Character'Val (10) &
        "hNZPgUii7ckpA/KdFFEhKSH6Efdxz3ibk0tjhtNdWm/MhjHmG1KaScV5wdhhu9yO" & Character'Val (10) &
        "FCFAcFgD9Q0/qXVRpPpcuAkeBVlPU1syyB5iIqJ2xzk8QvUghMKCIvhU/SqFLXkd" & Character'Val (10) &
        "FfkJitgk67olSLp8ZzGKcDwlUBlcUEddjzlcOrFN2UqBYBOLp+r1N0rKLH4MVHjb" & Character'Val (10) &
        "DIObWEJZAyBbG8FY8c0UOL4kKjsCtAFC6gp1yXByum2neKV5DVVMwNNTsaGNBnL1" & Character'Val (10) &
        "-----END RSA PRIVATE KEY-----";
   end Encrypted_Legacy_RSA_AES256_CBC_Private_Key;

   function Encrypted_PKCS8_RSA_AES256_CBC_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "MIIC3DBWBgkqhkiG9w0BBQ0wSTAoBgkqhkiG9w0BBQwwGwQIdIelzQmwfLACAQEw" & Character'Val (10) &
        "DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEHNq/OITdEXQg+9m3oxl044EggKA" & Character'Val (10) &
        "G0qJAs9uH8X86J+zMBYSUJJ4S2jV+TyXWN+EUQZpiH6kDiHiu8yv+5JlzZTderKh" & Character'Val (10) &
        "mFL43IVf5Qwmoy58Cif/2Eaj2dbSQft+RjitVcv6WUn420fouKxq0EvftIj2AEQf" & Character'Val (10) &
        "K2CNgKcu3GgJdaHGTGgs31HIo25RmAmJ57w7SqynXCKcLU30qNqhGlf+WLesaY42" & Character'Val (10) &
        "75eh42gAD6Y2DaR0IDHLLijX94GYb3daTouyDkKYwKaxaP9r7fecxtodoZ0Gn6tG" & Character'Val (10) &
        "68wWT6RvQ47dWTRDsH/3KVytzIjJG/71O2sa/rJBZwr2gVmjtZB6S0DO4sT2KiL+" & Character'Val (10) &
        "sviGg/Z1rSS/zcd36+Lbz2N7bQyEDhCgnL6ePuMUk5AqBU21UWBcxAqS/gG+L9qa" & Character'Val (10) &
        "P4FAHesyXE3fr7M1vieqml9KEantl0hE9e3tdu42b5p+y8i59AuWU4wrVDcT3v5o" & Character'Val (10) &
        "3EH5aYX1J9a971tpORGIoRe1H2F/hJM21czaPHLtYay3VfGjamabgK0z5dfm58ID" & Character'Val (10) &
        "jBJCUBIrMiRqQBH5RxoJahMYjjcS9wQ1T4SCejXfGV1aSkAL0A2X/xWcR43Dud0T" & Character'Val (10) &
        "uI/TiBfzaNK9GF4VTWsOVcWvqSttLv2vr/maOAW3iPrF9qDt0qrjDyz9WTbGenAo" & Character'Val (10) &
        "bIcFZ61MOAVksc4lZGWPef4+zQGspqBIIgkH29v/e+q5G2j/+oGEJ8jJjaHfLsMv" & Character'Val (10) &
        "F+TqAbfvX9JmQaymccDt7dI2J8lmGeZYRE+6YRChbyxBUUyDPM0SR2rxi6KjYouJ" & Character'Val (10) &
        "xrOvF8zkwvd6Okw5sznaOhQOz37smWYoR4Gi2JHz6k+9E60YYXmoFdBtkud2QZoM" & Character'Val (10) &
        "2swBP0yIzlulfP7Zo8DzLw==" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----";
   end Encrypted_PKCS8_RSA_AES256_CBC_Private_Key;

   function Legacy_EC_P256_Private_Key return String is
   begin
      return
        "-----BEGIN EC PRIVATE KEY-----" & Character'Val (10) &
        "MHcCAQEEIEmok+s8hqBpIHGG3l8YbmOArWEKIT6C7CKpfrXNUeEEoAoGCCqGSM49" & Character'Val (10) &
        "AwEHoUQDQgAEt5XBke3OdQWBgspbpa85BwF40UnzQyRVmQI5+CePB6Vn1x1WNN+t" & Character'Val (10) &
        "hUrg7jU67Ii2XpZi4/2z1PJiNOZ1gQmY3w==" & Character'Val (10) &
        "-----END EC PRIVATE KEY-----";
   end Legacy_EC_P256_Private_Key;

   function PKCS8_EC_P256_Private_Key return String is
   begin
      return
        "-----BEGIN PRIVATE KEY-----" & Character'Val (10) &
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSaiT6zyGoGkgcYbe" & Character'Val (10) &
        "XxhuY4CtYQohPoLsIql+tc1R4QShRANCAAS3lcGR7c51BYGCylulrzkHAXjRSfND" & Character'Val (10) &
        "JFWZAjn4J48HpWfXHVY0362FSuDuNTrsiLZelmLj/bPU8mI05nWBCZjf" & Character'Val (10) &
        "-----END PRIVATE KEY-----";
   end PKCS8_EC_P256_Private_Key;



   function PKCS8_V1_EC_P256_Private_Key return String is
   begin
      return
        "-----BEGIN PRIVATE KEY-----" & Character'Val (10) &
        "MIGOAgEBMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSaiT6zyGoGkgcYbe" & Character'Val (10) &
        "XxhuY4CtYQohPoLsIql+tc1R4QShRANCAAS3lcGR7c51BYGCylulrzkHAXjRSfND" & Character'Val (10) &
        "JFWZAjn4J48HpWfXHVY0362FSuDuNTrsiLZelmLj/bPU8mI05nWBCZjfoQUDAwAB" & Character'Val (10) &
        "Ag==" & Character'Val (10) &
        "-----END PRIVATE KEY-----";
   end PKCS8_V1_EC_P256_Private_Key;

   function Encrypted_Legacy_EC_P256_AES256_CBC_Private_Key return String is
   begin
      return
        "-----BEGIN EC PRIVATE KEY-----" & Character'Val (10) &
        "Proc-Type: 4,ENCRYPTED" & Character'Val (10) &
        "DEK-Info: AES-256-CBC,6914306BBFF4327943642FCB6644CE73" & Character'Val (10) &
        "" & Character'Val (10) &
        "zOtnwLRHbSdOILvpFcVmkMLzDlwb1F1yT527t3L/o63Z8m8ZXW8Py8/JhoVCprr+" & Character'Val (10) &
        "M7HoPV3W4zIOpCXdQjabjGmvuj9ze68b8xiwdllHMuO1NoHTFX4rdbfuCqXjQ3Fv" & Character'Val (10) &
        "Lc3c6qrQ7SNNy1M1HnY+xp6bJd6CbZ/SXA9ff/hpgHc=" & Character'Val (10) &
        "-----END EC PRIVATE KEY-----";
   end Encrypted_Legacy_EC_P256_AES256_CBC_Private_Key;

   function Contains_Private_Key_Material (Text : String) return Boolean is
      Needle : constant String := "PRIVATE KEY";
   begin
      if Text'Length < Needle'Length then
         return False;
      end if;

      for Index in Text'First .. Text'Last - Needle'Length + 1 loop
         if Text (Index .. Index + Needle'Length - 1) = Needle then
            return True;
         end if;
      end loop;
      return False;
   end Contains_Private_Key_Material;
end SSH_Lib.Tests.Fixtures.Identity_Files;
