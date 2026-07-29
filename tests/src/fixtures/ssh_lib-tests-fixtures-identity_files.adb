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
        "DEK-Info: AES-256-CBC,717F91CA8CB0055C757069E279B6A771" & Character'Val (10) &
        "" & Character'Val (10) &
        "UFma2+Y1NtCGxxQkj7itT53a7PjjK/FMEurr5AheqOzgfUtCkyzFxAt4vAxk+FVE" & Character'Val (10) &
        "jUKr9tM8mTOm+iYMcSCAVbpvfwEH3JtIMuMHUX8USxSupfPa4UR7bZgTapD5PR8r" & Character'Val (10) &
        "g3Q9Cx7/d5nfYsuecArhJuuFa6xUb3Eq0Lc6SAoIK5LHwdgbpMQ72ep3NNAXqzhe" & Character'Val (10) &
        "1l7FHnsL7U3EjokXejfeVMvg9eDyylAXHVVbqqXdom+A2rE8ALM9VcNFwZPaRA3G" & Character'Val (10) &
        "DpfQxkajx8fvjey6XRF3MNYk4R3i+evwkgRV3qdOTWJ/8GyjRjUnw2dO2ZKRjTKr" & Character'Val (10) &
        "Vla3H8SusJ1zlV9nPdo/EXctAh02zPGqWnIdgOuJlG+6SKQqBADxPlGP//6bOfe0" & Character'Val (10) &
        "XqfY1ablecRmIWC7XG6rakvFwhpwaN2Ab4tCldFayqHpsjcC3ZK5Xxt5iGlofJOw" & Character'Val (10) &
        "OSWDzNVPFsZBBjvZUDo/I/kQ5eiTmEPFTtbE0GCMqurx6W3y84Shm0Qb0KDkL71O" & Character'Val (10) &
        "vgnVikkET9Va/vA0gy2LM0He23cwZQCcMyGUbpcvW1OEamTKKgtYKsfn8MYFE2jS" & Character'Val (10) &
        "l0CzxnNi1Sm7+qxLV4y1bArI3mxDOni0g6UCKZCqwTwPPr7Bp3Wq0put9LYQw9Cw" & Character'Val (10) &
        "5iOMoM+yMw/njxqhZIQOnPh/rQHV3JGu/7ZzSz2s+aMMNilUJcKxR1YpY8FqlEaH" & Character'Val (10) &
        "BVZjPUvEJBHZV7QJn1AON/r/iAL6jQJhE+P7smhf6yjYHuBTHl8O+dhiSJLPPeQs" & Character'Val (10) &
        "ZZ7bPCKTp/YQ+xoXGckz1eEGQ2hbzfdRLfXBi2Zma9cpkUelAPc4JRPeUCPE2Ffe" & Character'Val (10) &
        "-----END RSA PRIVATE KEY-----";
   end Encrypted_Legacy_RSA_AES256_CBC_Private_Key;

   function Encrypted_Legacy_RSA_AES128_CBC_Private_Key return String is
   begin
      return
        "-----BEGIN RSA PRIVATE KEY-----" & Character'Val (10) &
        "Proc-Type: 4,ENCRYPTED" & Character'Val (10) &
        "DEK-Info: AES-128-CBC,B847A559275370A44FA5D5EBA65226A9" & Character'Val (10) &
        "" & Character'Val (10) &
        "IG06Jw+aql2+9A0UsLTdTewQUpJqfR7S1mWbU0dBNP+8YqHNqX3gayZRccOC3cdD" & Character'Val (10) &
        "QTHbTu3uhSUiq7yQU8H+pSoEoz7wlvXRnpmUpn09WvqZFyYXfdDhWeL7zkvZE3jA" & Character'Val (10) &
        "oWfQA54alXLZ2M+X4B4NZ6tbhWcFbigasLW6u+CKpzAuHEKReyBJWAjb7x4qx1Pr" & Character'Val (10) &
        "0SnUyGzneijyXtxId8MyUoP0hv1rEwDzb3dSIMEUR43x8SPkxaZyKFQhdmvcta6W" & Character'Val (10) &
        "I+9Q7X3lBolBnZ3YxXIqHTJDaAprXnM7XeV3/L8MvCnSUxPSsj78K3MQ6Yl+PGn7" & Character'Val (10) &
        "CHLKhtnu1QOS+/lVdgOX5uxHuNxQ3airOIk/C7h4V29aS0aEIUKtmOMHyTFfrqr4" & Character'Val (10) &
        "Lxeq03XIdIrO0sx+nlc7VFrKaVRauNyE/Qv36vLmxMHFpNkFvW49TdFF9/TLjTPn" & Character'Val (10) &
        "s+57Omf2dxsSh6944yH/DSBIZ5BKqXad+c61qLjntNINbufa7r1Oovikjega8Hn7" & Character'Val (10) &
        "9t9t8wwUmKtxvOnA4sWy1iA5bpzM98U+SHGQedv7U3mK7mlPsP5GF/DNIXxiXLfS" & Character'Val (10) &
        "Cm7zVKl267S7X9oHXkT+BLBkg8OmSZdZbRIt3+Qbjn0IrPBsLsdknCzYK7TNB6MM" & Character'Val (10) &
        "ZPgLqffK0YLXaKwoJWOw7c0J7RnQryRGDAxwGqhpySCvy4cxMPMxRTxFXRcjkL+9" & Character'Val (10) &
        "PwYIi4xB6ud3eCSGKbi4TQ7z/rc2orf27LhkNyarxpVyJPkugabaRXnfaKEjpbr+" & Character'Val (10) &
        "aGDpqGL/Ao/i18lyErwSgjysXWIq5YGpMsIX3luQTgstOAH0pyCAazm/ZHrmM4TN" & Character'Val (10) &
        "-----END RSA PRIVATE KEY-----";
   end Encrypted_Legacy_RSA_AES128_CBC_Private_Key;

   function Encrypted_Legacy_RSA_AES192_CBC_Private_Key return String is
   begin
      return
        "-----BEGIN RSA PRIVATE KEY-----" & Character'Val (10) &
        "Proc-Type: 4,ENCRYPTED" & Character'Val (10) &
        "DEK-Info: AES-192-CBC,C596CAFCB5D91A13A60222E2A15C6BE3" & Character'Val (10) &
        "" & Character'Val (10) &
        "aqtqiTkq8sNvAk1kSlPX6Xi7A34xu5vOsV+MPvuZ5xUqfRmQDMYCfQAngPgi701I" & Character'Val (10) &
        "HY0qOmC4LcVuQQLStBrtJ4qBB7LG03Y9OPWSPTq5u2lOah6vhnLueJ6WNJG8KMhr" & Character'Val (10) &
        "dTdCTzyrZdVt7uwXZWaa2+XTFzRw7+z0pxWPNouDZ4qpbaUhpLv0uCAF1Trl60xG" & Character'Val (10) &
        "/fvOEEHge4mejHcrkFi1Ewj/2UbrPdkrcvxpA/9TugA6VgHh6X0miXNTneRT0l6h" & Character'Val (10) &
        "YRa4VV2nCFR1yzrB0yKhnsBpLOmFWx6zAt1Mxb+/G9xMa09Q4ISinJlOyC183jgm" & Character'Val (10) &
        "YWsKEXSgHUt3/ScIX6yFdfnx8evDSSYYO0AcehHYoGEyh9BydI++KkGsjUBycSLH" & Character'Val (10) &
        "lPo9gNFc6Y41+KEW8rNx9lsUjOWjTghl7BAazscXpzd0D5DW4Gz0K2fl8HCQY//m" & Character'Val (10) &
        "PRmHtMlRypRZv8hJWcyvn9S746ZPbZwIWRlxz36y6fL4qrT6QAODJVNb7ziYWAXq" & Character'Val (10) &
        "+vnknADJjAkRI540Ww7kvSeYbQpFoN77NxmiNcmTO+JvDd8uLj85ofdOxiByNF9L" & Character'Val (10) &
        "ve3NweUolP53InHz1zk0btJbJL2i+OqxYkqlUMz+FpDPWRtpOXAM34HkUA67Rnej" & Character'Val (10) &
        "HIBx1GF6bfvF4DyjOSL5INMHuDpNhrkYQfS+IVbF55r99oXtBQ/zQyJBPPMyhKVi" & Character'Val (10) &
        "Ta3XtD2tIrZEqdc8AdTRzuj0A0wjsYwziMEtkYOoZc5Ym3h1f3qDH9sa+j4SoGyU" & Character'Val (10) &
        "HEhVl0qye5cSNZ2Hnf/sjJRcouP38ANBImY7dDUB8SjGbt3huIdBQ78Z/dXgww9Q" & Character'Val (10) &
        "-----END RSA PRIVATE KEY-----";
   end Encrypted_Legacy_RSA_AES192_CBC_Private_Key;

   function Encrypted_Legacy_RSA_3DES_CBC_Private_Key return String is
   begin
      return
        "-----BEGIN RSA PRIVATE KEY-----" & Character'Val (10) &
        "Proc-Type: 4,ENCRYPTED" & Character'Val (10) &
        "DEK-Info: DES-EDE3-CBC,9BFCE1FBBEBD4CA3" & Character'Val (10) &
        "" & Character'Val (10) &
        "n7rdlz1oSIr9EMtC/zm/T7Ya2B4JtwVCFAeg5u0cc8RW1XhlTaF5QP4O7SOKFqfS" & Character'Val (10) &
        "xley8Yh/0kjMwjcVg8z0DKTZStIHfw/1n+Op3YhG1MyZeBXAF+WzXJuXJZCqutD9" & Character'Val (10) &
        "YIKC26KqzsdvzWf1CB2YyAiAfMY7v/sPKTSC7n90unQO8b2kT3bWKAnxzxXkYbc5" & Character'Val (10) &
        "quavW6ZTYRWQS8/wqtIQhivBA3QgPuacFo7yd3oWKoe6CW/6WXGv0E09BWCYKg9Y" & Character'Val (10) &
        "89N6cb+J4787tl2dkyVznc88NtOFDUJK+6w4k0fjRUbfc8yXG9871JVjLixGpkUD" & Character'Val (10) &
        "gokefmpLFlpzgq7sp/4vKIID1BIMSS0W8QRwxZeiUP96uXbgxBAq+1LxyNIfH3VZ" & Character'Val (10) &
        "r0i6ffvzKb09D/XWomwsApjZ7nzWgFjykbXisDjgmCye+GDy6IDyHCheInk/FjrY" & Character'Val (10) &
        "5GHd8PSnKRdtZUDYuqAPaIdtNGs3hmj5gmJimOHOxPKRSUXXQpK+TM9ma/65N0em" & Character'Val (10) &
        "H4floPhyG9jokCUVQdWCN4L6fy9zU9yR71nYARfGKpp8o/RVH/MZZsxs1ycOSbL0" & Character'Val (10) &
        "CNZPmiB5NOA2MR7pjvUB0zVkrkjFYihA7s19ywyjYcnvV45io6ajgqn6WBDT+/2U" & Character'Val (10) &
        "H4FVrFDiIHTaf+Zv59ycYFkhLN/fbq+Rin3Cqzi2OXZL4eFxe6p5SIL7oM0CTl+p" & Character'Val (10) &
        "UOu6WEOKTbJYmcQj0edCU0fVUnhBNfgboeaxSpI3bs5bEv9RaKhHrBzcRjcPZfZ9" & Character'Val (10) &
        "co/v6nqDn6azasNH417KV8KNqT/fF/JvrFY/vDVqh6sMnHZ2m680Dw==" & Character'Val (10) &
        "-----END RSA PRIVATE KEY-----";
   end Encrypted_Legacy_RSA_3DES_CBC_Private_Key;

   function Encrypted_Legacy_RSA_DES_CBC_Private_Key return String is
   begin
      return
        "-----BEGIN RSA PRIVATE KEY-----" & Character'Val (10) &
        "Proc-Type: 4,ENCRYPTED" & Character'Val (10) &
        "DEK-Info: DES-CBC,298CD5F5B5DDC9DD" & Character'Val (10) &
        "" & Character'Val (10) &
        "HJ87EzM422R1vit4Ktamw0pMw1kmOerUjXF6AAwtuoPfJcHGox+jCN5bcDWGpkwd" & Character'Val (10) &
        "NsBfOaWjtrF1kmXACGT8dxuRnOcGXDeNdC/KGykEzOWGJQoDhMSgfsrrIgrevNZ5" & Character'Val (10) &
        "GgMt/Glsa3tsqmgNQp913Bd/+XGniEc/RFSgbSpN0rxlVhcNPDwVEqf2a0EiOGDP" & Character'Val (10) &
        "aBPqCAB+1OmJweKQ+CPW9lNX/8yvZxy9JG6hgxjqO+VAKIP8/RalgpDRLrGI5yiO" & Character'Val (10) &
        "KlgXKk/47znXPzqTB8b3PgOjGYA1nJuOnVIWe+HRJiooBVjxClACQmaFkSxMp6eZ" & Character'Val (10) &
        "5FWrkcPQ91p7iibANqP4P4t7mrybJA+yg+tPWzAmqg0n9JaKiCCrOs81MWMYcY36" & Character'Val (10) &
        "7AKWOXlVcEteIPc09qEnnjrF5vxugUqDxAIBtpI4tzc68zYdkOSnLMjNszp0zspv" & Character'Val (10) &
        "fJsg9/MjD5lqKsx4J24wvvxXuvx7dsXfBcwl4F6Shr/6IHUO1q3TxecNHPY783Kl" & Character'Val (10) &
        "kVfTEi1wqKjaWRDCYjWqL282abJpTifcr/wvwx4g9y1zcYGtE1kLoUrZ5D2XG1QS" & Character'Val (10) &
        "k5xQG/G6lEdDbqlR7SaBBigB+j7z16WxfbRcNQlEA+ZVFaiVfECuWXrPHCuoP0wD" & Character'Val (10) &
        "Pf/Z7h4jO/+V5Ous9Jr1WvYsN7ZKFtn1BiKcY7XuFne4NRUScQrMYj/etPlZrPfr" & Character'Val (10) &
        "D58X1/e+CvPh+x2BDQSfHCrFReTDTpAtOmMfYb8+5zXvV37g7hH2ClEFLUwkI+6X" & Character'Val (10) &
        "ULNuFavQc3q10BKXF7G1l3nIJwE2lBuXS8vGP85jJj6+cgPxjmr/Aw==" & Character'Val (10) &
        "-----END RSA PRIVATE KEY-----";
   end Encrypted_Legacy_RSA_DES_CBC_Private_Key;

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

   function Encrypted_PKCS8_RSA_AES128_CBC_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "MIIC3TBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIYtlEvYbQmjUCAggA" & Character'Val (10) &
        "MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAECBBCZvgOnv3g69SHNgTpcdjoqBIIC" & Character'Val (10) &
        "gIUEBl0a94e+Br9M3rrFZoPl4WOngImzrUWZi8Zv4eggntU+CigFLmZa+elu/ekN" & Character'Val (10) &
        "jttH0Xj1jm2x0OWXDI5y82qZdCYNdogHPenv1JXD7PjsKSCNv5f4GcSs2wVaXcfu" & Character'Val (10) &
        "i8j0Ya7vD7JG/eIN4gKA81EjOjB65liXYU68S6lkdXnvel2mV01KUGOeRZXyLqAx" & Character'Val (10) &
        "Yjg5WyBShtahTHud+VhvbELKiMO8823yB5htAhdSnfwcvxpti/tn/ahkmPp3Ff6O" & Character'Val (10) &
        "WFkRphM4rlye1WAfQH1PamV5++oBDU6iFPFkXROiKlLRs4HoIugHDb+P0i0WOpOm" & Character'Val (10) &
        "KMzYYrA21cdEe4Q7h8UdXk3K/4tY1xeD9YOCO2x+jIw6SofEa/i0GAEw2bv7JO+H" & Character'Val (10) &
        "5Hh1dgeQNnDPqzUUnD5DaeHRo/bwaJof1LmbDRw+ml0KzmKewMGFLt15Nf7OYu27" & Character'Val (10) &
        "gUqz6/tuVPZ9VN3B4fxQeMAUu4I7FEb4U01NY+6RVPQcugHLiuNy9BGd5BO9WfZb" & Character'Val (10) &
        "RkYAcUY628EKwMVObCwMzKpV+TAl3RkfUU6i2yyNgdhB+QGnkgyDuy4Yp5DRNL21" & Character'Val (10) &
        "XZZBHq7gzBLXLppBpMDZhCIdqz2rAO5Ls3OUxHs3NHuKkzXUrOp5vh66xtXNRaTC" & Character'Val (10) &
        "vzVd3fwR4A5e+DpAxjTrYRFoGdU8JSN8I1Qdh3J8cJTbpzcW3F1AmhYBMgoEFw7g" & Character'Val (10) &
        "V4FNCEhoAqXe+RV7BiZUgKNm9wq2g4fl8zAfmA+o/woC8pf7IJ4r37L6KS7CjXnt" & Character'Val (10) &
        "pnsaPLGxNeUFW7aqF+66XK15BHJLscpiHE4Jy6Funotc5Jx5+r2bGzVxoiqnLUm/" & Character'Val (10) &
        "+seJnWibmdH6+d34tYhcmUE=" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----";
   end Encrypted_PKCS8_RSA_AES128_CBC_Private_Key;

   function Encrypted_PKCS8_RSA_AES192_CBC_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "MIIC3TBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI/jaGRwVwPZ4CAggA" & Character'Val (10) &
        "MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEWBBBBsFOOqINynY9u4B+W8d9UBIIC" & Character'Val (10) &
        "gOeGyu8YFuhsaQhGneDg27Ow6HYqoRBgDUKXdp7KhuEciUy3tiUcbRx0IPNqlQN+" & Character'Val (10) &
        "hA3blLnPXMOKDRhk7rjjy80vhesI7bAam1XKA+LWgNsWnGw4FOR+bGiNTIG3OiAA" & Character'Val (10) &
        "vnb+9zxzZmJM2EKD0FvbcP5h0SWFLgfQZ9Bp6sbJ0m4pA6aneuhsL3SiYk/QF/X3" & Character'Val (10) &
        "sCYuRO+4VxByG0+RjbQ9mb+O/EZHZCQW0NGDTnB6bzRvLUHWJJpGwA5caqWyQXC3" & Character'Val (10) &
        "cdNn5X+QR1TR4Rj3lEi+uvin1wgIRkX0fWE63W38p6H4XUzQhJHyHqgeg5vbqVc0" & Character'Val (10) &
        "JhsGqpdeXKHBVKj6BlrvsZ5RCokIRXn1cAyNsNoIyban2MNpuhoT4fqzOcwYao4p" & Character'Val (10) &
        "308NPu/KVeahTuZhdkn9vC0Wda1rSqhJmsUbuODwwk2WrZPdOX+l4RXk4rUzQlRF" & Character'Val (10) &
        "z9fd7J6wnAW3pz2w+69HQeFQ/35lI1yTgk3Q+3aOO0e+guRFGBIN/2+Plzf3wm9A" & Character'Val (10) &
        "840VYCbaPbbjQd8QM5rlpff47x4adL9blJ1tvt1JvbIeUik/HQbphLxJgYppzQHc" & Character'Val (10) &
        "U8OlP4BgtdZMkGHPf3wecWM40lstH5bE6WW2I+T6OJ5yMsav3UpqVg6iJ48t5Nzh" & Character'Val (10) &
        "E9IMtwOLkJQ5iRSWjYuABYrwzOqHX0mI8RcDm9/9tcSUIU7MdsrZbGKRDdjn7DWZ" & Character'Val (10) &
        "Ix90aUGFmXz3UnO6VdUw75IYjBwYh7RAjEProxwif0PNSrUbi0H8qz3HKWQveM9B" & Character'Val (10) &
        "yNVlrO5f8NV22DIz7+ZRDJk/Erf94cSijE7p5egHiv26bU6MEo6295KX5+ML5ed3" & Character'Val (10) &
        "Q0Ww0GBsVlQcWomoBAPSeuk=" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----";
   end Encrypted_PKCS8_RSA_AES192_CBC_Private_Key;

   function Encrypted_PKCS8_RSA_3DES_CBC_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "MIIC1DBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIorNlhqxj0LYCAggA" & Character'Val (10) &
        "MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECHy8G8Sgw6yBBIICgAbvV9rT2MR/" & Character'Val (10) &
        "p8Uwjz9UtnkfGKm1xDg++cq/LLLR0A17BDacRBHsf71bzuh64c7AQxuaiooKxFIG" & Character'Val (10) &
        "6JKotDRd6UO8zvbqTlg9l0/H7s3/FWtUYjs9EXSA0CltRTHeJtZhdr9Ud+17aqTe" & Character'Val (10) &
        "lzfHbJDdLlvLinXdBMHe7GjWNCILux8G/9dHNR15q148pllioChipvLvbN3q56QP" & Character'Val (10) &
        "3dlc8RAP1WZ14WYd35/GkSienEeQX4vd96FFdHfbYC5qm6hHo4k8fDnr+w8OPdlc" & Character'Val (10) &
        "SPfjNJM+DIlURNUAE6UE+Q2k4KvmivBOwrHJQ8LNMso4gKOsjcPe3hfg248ZXecP" & Character'Val (10) &
        "tIZeI/8DRfTInhcy1A6KMLZjRWhY97PDTpUjp9/g7YB1ZNQHYiWeYS8erBpu9M4c" & Character'Val (10) &
        "WIGwbzj45hDhZQDOYmZLfvm5Xt22e7581GFSiuanhY/b9Dzr4Ja6dLhM90nzptjP" & Character'Val (10) &
        "BYziyMKG2rwIQj96hqsV08J6/G7VPPculMUR+eYUpQQjS+GXiOZnZtohUXLYQnfz" & Character'Val (10) &
        "IDzBn1iPbdgDlPCy9yMIh60oBBasqPwU25Y18pKo0/7JbaJvlS86IulQJmd++baR" & Character'Val (10) &
        "RKnT4nyoPuxHvAC1FFMZaC+yeZELiCsnCs/piClUGD07VPzdagqzwWXVosvY5+uR" & Character'Val (10) &
        "iNMmbTEBcKdThxEmV/FHmjn8xk6stRWAtZyffGRGB9PlUwDnsPJzy3u8JHeHYWsV" & Character'Val (10) &
        "1kV9MrF0BmaWjySUYyyBEEXt44gUVxdxDV2+otdjYLEcP2r9Q3ec+4Q0xkyImK5V" & Character'Val (10) &
        "tg2h2Uo5X0CYuMQKbRD8w9Emu2ZqTwFLbrI5YLNBO82IV+Z6GXDRdhClXu79VY+4" & Character'Val (10) &
        "Kh03TsxBthQ=" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----";
   end Encrypted_PKCS8_RSA_3DES_CBC_Private_Key;

   function Encrypted_PKCS8_RSA_DES_CBC_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "MIIC0TBLBgkqhkiG9w0BBQ0wPjApBgkqhkiG9w0BBQwwHAQIh7fDvR9EWWICAggA" & Character'Val (10) &
        "MAwGCCqGSIb3DQIJBQAwEQYFKw4DAgcECH3LUGV2gQj2BIICgDGsa90Yrxl6q+aL" & Character'Val (10) &
        "26BK9DMxsaMCm4ZUAjpmkqerEUfaeVlUKMdX8riLOVWJ/i25kyshuh+vxN7s1zXO" & Character'Val (10) &
        "nk7YNAcBGQJVP6H/yMPYENms9jtBUTxYomk0PT3ROFdKS/Vm3fipSXyg5dmf5+A0" & Character'Val (10) &
        "FdwXIVHEEdIiRO7RJSVp39b93rmZaqj77M4Ejmkmt++D0x+zbFndNxvH//lG9/R6" & Character'Val (10) &
        "5LwevAdTRK4LQG+OvP/D0Pv7qyeaHd5gOCmAzDRBXyl6JsZTuHVAPMOfBf9FTzgA" & Character'Val (10) &
        "YF6BRVEnaLwEvM0YtTqMIsTTG5LYUd+xVKCzkmu7SdEAxMJop3T9bIFhbHMbPaRH" & Character'Val (10) &
        "I+76KITCYZ4Mi1bY0+eFhNDYhjFNX6QKqHxFN8FkOb4bZEyqaK1+jYiczA6kRvjS" & Character'Val (10) &
        "RHuKrH4btaxcq1LxpmMm1uf1LXoCN0xlOoh9JZyzXapEjcWnO5U0ICrBflgA+xEL" & Character'Val (10) &
        "YYBRMcXR9UXAKa/5z/I/E7NRxdqA6+zS0UHlfY3ivNOgFr8WaRWVYpFRnwbx6VF4" & Character'Val (10) &
        "9Ajv1IwT1zxvEpYC7u0mmbwbcyBCxN1sLk4qMdezRw+x2nyVm0uWWT59Xax7Ik59" & Character'Val (10) &
        "Dx0LfPLFZlhIul7irOZqg1cUxCpT9aSgfxgEZxrVGl5TDgvXqmg3JnkQYLAzFp4p" & Character'Val (10) &
        "SmRkJXrTgdKaAJB07YhljilWu+mrG6jL5Q4vAMqgkgjHuWaPGyn3iTNUVJMSv75e" & Character'Val (10) &
        "as+T1tIHByFcBi/kQD5F4qPJzRqSoQmx/tStjbRAT0vevXklI0+KiJ3V+4lL0ome" & Character'Val (10) &
        "0dbzM0g6IO5KWH+1+dsaVubbNu388XHwvJNHnEh0QK+KGglZjC21h7d4SvkNOJJF" & Character'Val (10) &
        "vuL+tzY=" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----";
   end Encrypted_PKCS8_RSA_DES_CBC_Private_Key;

   function Encrypted_PKCS8_RSA_AES256_CBC_SHA384_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "MIIC3TBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIkADk5bw7ExgCAggA" & Character'Val (10) &
        "MAwGCCqGSIb3DQIKBQAwHQYJYIZIAWUDBAEqBBDBwfkHwHbX/nVMDI8yPvUaBIIC" & Character'Val (10) &
        "gAT248PNd0sZx2UX0hwJ35WtA+szEsSs1uBYLOTyQnUoCnOAf0tzQVuXC7oAPx5A" & Character'Val (10) &
        "TAn/+CEKvwf1on7kcKwgZuy4K5tUcY9uxP+JztmCQFf3fPnUNC32NDm+M378y4ia" & Character'Val (10) &
        "NgmSEoRVFPwoX6MrxukwW89+TDhb8O4P1VqfiLEblHtmDSJUxFIiurvZzF31IpNT" & Character'Val (10) &
        "kmgTWHebmrI06mDqQDIicUC3/P2dkMCIleOyq3+T2VqPrmq88HUlUP3+TsSLA+u7" & Character'Val (10) &
        "cpQC2TpsQYvakuX+R5Y8B8qxL2UIVdqMkapdByHE2T34p+nEJMH7dHJ+Y7eSM2pb" & Character'Val (10) &
        "69rV3gEGC8B5PCXaRmBGFbeqOR8du6YRJtKmyEEbXx10Di8KkdYl9R4ZirQpfeUs" & Character'Val (10) &
        "LsmcAyIxEI7aF4cKQ2WuwiduPWNIt9pq4d47LXBgVcQfQm/K50NZXJ5Vesmc/PJk" & Character'Val (10) &
        "8WAnUaxZNqbxp3EcnypPWd5YUWw4z4Ee4D1GoQcr74fbBbuZZaRGxhnmws+NQPcD" & Character'Val (10) &
        "P9wHIcgEu1cMma6p11Quk5dW5DxzmoRfSDqtCn2OFGcSuqo7chgJYNO42f7Q1bjv" & Character'Val (10) &
        "DtZWezcDsX6V6XOvi90dUjfmNvMXXnpZ6SKcimmbEbrIZ2qXYbsK0q2n/hfAkuVF" & Character'Val (10) &
        "WzEI32QlAA0zHJAAupfJ4RMryW/mPLVVGaG2I2Iu+/GdzTe7ADpl2XX3yGf9FzG1" & Character'Val (10) &
        "csOpwACj9MYBJzPnE194IRpb45ui2q7BbdN4rGLSgLXVzcGONIetRBenJv5VHK1G" & Character'Val (10) &
        "84wIm5TyRZauYAVRtKkZ6l0NhxWN5rNGHEUd8lTdIEUTcVLUkQIwntpadePEo2Jl" & Character'Val (10) &
        "Sb3JLAJWx8/ozbayWTa/oy4=" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----";
   end Encrypted_PKCS8_RSA_AES256_CBC_SHA384_Private_Key;

   function Encrypted_PKCS8_RSA_Scrypt_AES256_CBC_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "MIIC1DBOBgkqhkiG9w0BBQ0wQTAgBgkrBgEEAdpHBAswEwQIk561xFFpFb4CARAC" & Character'Val (10) &
        "AQECAQEwHQYJYIZIAWUDBAEqBBBmAt/TFq0W32pJL7D1dAFqBIICgGGl8KMOE9wW" & Character'Val (10) &
        "rzDx+Ede8VrMhyacWmyIo4HHYxdn4njKIw459Wu83na+WwCAR7Xp15fN8CBQXArm" & Character'Val (10) &
        "t8HE4+DMbgUrkNVL9I8Qzvt5Mr9MkmPwOmPpovwtNtOBGoufllk+tRBnWb9S05cM" & Character'Val (10) &
        "aNbYYt9xsGhzP606tdwoU/6k4WlMHZWAlI2OlUv/miJADC8PS5CdnEn7ZGQ1w72M" & Character'Val (10) &
        "ppwP55jtDc64XfKY6YBlEbb8//Q2bwXfpaLWudN1+mVMdv3ekk9kxUSZFRFwJYUy" & Character'Val (10) &
        "bEkhW9de7vU21i8Y0X+OIwFpWZy6vJKsqfDxj0M7lt+WGtyxMwV2RFAxHRpWT2DL" & Character'Val (10) &
        "5FADVjetCdKFGm4IcojqG6NDx5i34hg1U3DIJU12gSPxUNMT/Np0dKmcR3TZsa9z" & Character'Val (10) &
        "wixU6+qjsBSENPxix73qq/zt6Ed+bOLhTap+Wq7eyX9YnaCe3Dph3TC7181nfIeq" & Character'Val (10) &
        "ZKsVlZYHrsVBMQHD7HBldCxp9PkBcQsuHMchTuss0ee5Oiw9JYS56xN1ZCVC8BTl" & Character'Val (10) &
        "XfbVNt20MFuoPrVGJgaMmOo6fPgfwddZL/H73u0BtLpNp88nZTRk4e9PJrCODF2Y" & Character'Val (10) &
        "Xu0u0cqZfloY+4NxCMp+KRh0X0AQWWfEUGcHT6ALoNIYu1K/o1jZohb7WsMa/+XG" & Character'Val (10) &
        "Nosap8qa7iG9KzYRqSI2jNuVE2JkBEJQAcGbttbKalhJ3emCZkzNXsmh5jPxNEQi" & Character'Val (10) &
        "zibM8IoZxfVjaLS4gykTSLy9WZ6IHNmRmxM4ubeiK0e0tNesV2RtvdFkIxszIrXZ" & Character'Val (10) &
        "w1YQIbNwHBNwVUezqetcDNaR6B5DB0pdC6PvzYIxg7J2zv0y0AtwIrw+EOzTk+Ek" & Character'Val (10) &
        "taczCwWv8R8=" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----";
   end Encrypted_PKCS8_RSA_Scrypt_AES256_CBC_Private_Key;

   function Encrypted_PKCS8_RSA_PBES1_MD5_DES_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "MIICoTAbBgkqhkiG9w0BBQMwDgQIzj3FYel1ErkCAggABIICgBOsnq5m/ESZieQn" & Character'Val (10) &
        "pI4b71X/jH8qoFhQHU1Qzuqg4B/v2KmC+26dW4FG0o9ZhvENfFuIUr88xs4CLmpJ" & Character'Val (10) &
        "jXcv+45yBMYLk5QpXb5SSSRNjLfUb8SPUcw+1R6pIclEDm2bIvXNTlSfEf1iFp+C" & Character'Val (10) &
        "Y1EJtVrFA4ICj9WzWSSPHPqEWUipN3+wIx4BZpmXknay0sirLrE/3kuj7Y3Wt7Ne" & Character'Val (10) &
        "LI9RAG6smVdgQCmUXJIcJjwCkBVtbuz/O6JkfZ96xvvb3jS6g7S9e1S3KkTPKexB" & Character'Val (10) &
        "2Nyu4vYnu3MHqNr3LaKcmau9P4ek/8GOkPaHYLlQjQVo4HRzipUMlooSa/Inrts/" & Character'Val (10) &
        "AmyEPagp5jDWB04inbCHuU8R2dBXckKhdiUNQLuKCXkI14bZhnq/pYTjq3G6KIOu" & Character'Val (10) &
        "tQiUHAfGD2HntFc9smmyUwhxT9oNNhpjijeQ3kHzp2KU8rlslDWpWCv0j9eMJl3E" & Character'Val (10) &
        "DuSQghsCpIMNYKzpiWlYu9H0wd7t9OYrKWGgc7hX9MhOflNQWcdSEqYprzBi93q4" & Character'Val (10) &
        "DUSmYGwQKm02ZeJgmBOGBRyFToqqwPMzu3e+07y8DgA9X1msCTEB76PI6ZSrCY09" & Character'Val (10) &
        "hp8WrpZvOQmud/QXxhQ6y7jjgbr9vMVnGufZDU8Kl5bF4aDJpRlCBOHwbb/9czqT" & Character'Val (10) &
        "bxmpBtnJKRkBYLlc2xUjCJR6MxTHeSnyMSsvtUPg2yeYQsMoq8qSrtsOtc1UNE37" & Character'Val (10) &
        "xdNkyqBKWXnFd/GT1MFuk2/w1g8ckkykBlJStR+nX0w5pPgz1xEtK8mo06ZEJqXl" & Character'Val (10) &
        "BXLSJzKNXGJisC7gIIOLi4U/bwhrLERXr848DszozwNzMMKFBW9nHoc0eQDrwrbr" & Character'Val (10) &
        "NUL8rqA=" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----";
   end Encrypted_PKCS8_RSA_PBES1_MD5_DES_Private_Key;

   function Encrypted_PKCS8_RSA_PBES1_SHA1_DES_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "MIICoTAbBgkqhkiG9w0BBQowDgQILrCVTJxf4L4CAggABIICgBX/ypk8woe47INZ" & Character'Val (10) &
        "3lG13Ks1vAuaRxJfwBC8z1X6mMLtCMuc/bUq5cdCSuop3r7ZD/RZ3NGELeBSviUq" & Character'Val (10) &
        "BC2VzgmOuRDeZ7ccDe4g+0HD6ePOn0hXtMprWQp8ReUwThvCf2UTZGO5c67o4sVf" & Character'Val (10) &
        "AXYnaFHrB7/8EUtggEkD/hIrQ2asM7LpFGU5W+0jPG6mmVFvqM0/MpjWzrG7GNN3" & Character'Val (10) &
        "tLV+P4zJ4lATLnEchi8enWBkJhKNQ/BrL93VAQo6u8X2NzuazBY/vF5SqYTaKbxP" & Character'Val (10) &
        "iKXKnzHcharwykJwwO9SCFqB2wfOATR76QzWx0fN+xypGsKDa8EjJWanrSedkXXp" & Character'Val (10) &
        "w81Y3LSJ+bWMRcg4CxbhAuF/6LUWftXpTlHOyTsMdnShh/dOZ+2vm/8SkP1Ion6r" & Character'Val (10) &
        "nTqgEGdK/flF23So+pTo+ix0GWzP9/sBsJM7Te2+mjoMpWZfthKo6Tk1WynpbuTX" & Character'Val (10) &
        "DfIB2Zs/4TToNrVRouu3Y6GucH8DDx5vrkx7droKpeJ/j0/adZdl3Pr/4vX0YdWn" & Character'Val (10) &
        "qKyHirmMbiOIsa8RjIVG8HYd0rt0UDK+JRxLQxpoCN6EIoVdofxv/UvZn9K/EM3I" & Character'Val (10) &
        "fV+Pkjo2PsJrD+RQjkY17P0FeCHSsRJvFIhPXVAuvNK3HMkoCXR0UlceOgOv93Rk" & Character'Val (10) &
        "HOmYoC4ybFB3lw42rxGZo4j2WPHzHQiVKMXi5idfqnbmoGpOZIO38jTu8n21sds7" & Character'Val (10) &
        "HwCYFuJfxJ2a6Wal+ebnI1hjE3gCqmvTinBejDCJ//n8iYj6SWucQfA38mrwijpX" & Character'Val (10) &
        "HbdtDWzcZSvfDdSp6dvZLxolRuQhuY808+XE4IaKe1QLQB7R5LgDd25Cc+cVyaqh" & Character'Val (10) &
        "eYxRHsM=" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----";
   end Encrypted_PKCS8_RSA_PBES1_SHA1_DES_Private_Key;

   function Encrypted_PKCS8_RSA_PKCS12_SHA1_3DES_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "MIICojAcBgoqhkiG9w0BDAEDMA4ECO5g6XsR/I39AgIIAASCAoDq0TGrlqhY2f8O" & Character'Val (10) &
        "FoMRCey1oVUMIg85eVKawwqts2xTqnjDC8UpA6kD1fi6EoDJgkrxC6MPmzvnz+Y0" & Character'Val (10) &
        "DQtwsvGEsBipT+RYFzhzdVfNbbCldYOgUgnlFu9Mf8AHoncZc+qtR5jlrj/jjarE" & Character'Val (10) &
        "PMcK5xa5SrnnThf4v+b6nCpGPrKoWgmNm/ikncU6F8WEbacG30E0P51Fw9D5sqeJ" & Character'Val (10) &
        "3xAan59TV+LUjK8k8sxtVjy5u6Qsc2W7xiFzL6bdXX9T1iuYotRQhL6BLAfsvwV0" & Character'Val (10) &
        "/6XlxTUPfoOnB/i72nH4UWHpg/GpU8DW3oc469KBM4YIojsXbWhgyfwXIhEFiZ8n" & Character'Val (10) &
        "CgM1Lz6vn7EWN/yGGehsUMuEfibcgRiLOHReycwi2L7gi0nEJX9Dm1Rzu+6vOH5U" & Character'Val (10) &
        "K5SlfhFBc6Loa8Bv6VROHUISEw7ufxDTKc00qjr5s+U5KKxrQCwKQQZ5CF8hSOU2" & Character'Val (10) &
        "XNDVgusfJ+7wg/m4hNcSGAA9MA7kgA4Cq3UGkEsAc78umX27ZHc29qCMMtO1shbc" & Character'Val (10) &
        "DENEOmUT3gAP7rWklMO19vLU0vmOjJCleK9vCqWthHENkEUNsb5GdgGDN6aERWJK" & Character'Val (10) &
        "fLBDOLortnNZiD4QXVABwF2+UMi8edKebZYXKfa5U1DUtTDj+Z0RayBSOdvDu52K" & Character'Val (10) &
        "qGcksFx4TPubvuc38qsfQ9XlFA/fPFK5CoNWJAv+DAMdfFssP0/wZj6poLw5E5aP" & Character'Val (10) &
        "EuyME2Y7Pue7oqLgoBHZSlmAmWKWqi50JO5UUb0IzjdAWCvCfgwQ3wpazFBQ3IqZ" & Character'Val (10) &
        "8NAtxhqZZKjZ3jZ6NvkGl41e28Jx9N3c6iRYAQfQAgeYga2t+8wMZgb5zI1ZrjyT" & Character'Val (10) &
        "iUKeforD" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----";
   end Encrypted_PKCS8_RSA_PKCS12_SHA1_3DES_Private_Key;

   function Encrypted_PKCS8_RSA_PKCS12_SHA1_2DES_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "MIICojAcBgoqhkiG9w0BDAEEMA4ECJ8Me9rgTINaAgIIAASCAoAjsWySKH9JQCH1" & Character'Val (10) &
        "1dG3gSp7JUa5fOWsYYHhdwTpAvah/7t8eruABCWEkX69KwGFouk39jxmdrCcrnYa" & Character'Val (10) &
        "EmOoSlZoCyiHhXCZNjpxhm6ry7v4m/9jQDt+fq+uZWeFCj0TObuwUS/rgeBL3CR2" & Character'Val (10) &
        "vtocJR3l3ihAvc9JuUAhNVHVXvVKB3qASsHxT92UNU9GsoXhvO5SH1EiyUhjaQ7N" & Character'Val (10) &
        "vwg/pPR8GCZwSEuknACBWBlu+zMzVv8hMBGSDU3FYEzmY71l2fsqBdToD1rkCAbw" & Character'Val (10) &
        "Oy6qgBGE8NW2++wO7r9vYm6wtqPj6i19wHuYBEt6alEIrrmHoTWfCcWCZ3VfJxwy" & Character'Val (10) &
        "CrW1l0OARmuewmIay23EAwt0All/HR+Luj3I+DLf6OM/MD+igH9zJTo/l7rGd1qG" & Character'Val (10) &
        "ng/RO7KI3mTpVpMVt24KGd4m/zur8hNewD311fDke166SrqvW4VoI95EAV22jBMC" & Character'Val (10) &
        "yDg+tO3OLHeWC/Ig3ZDJC1xFBk+wexCuPb/Mm/kkjG/JnNuZDlRw0YfAYViU10Lq" & Character'Val (10) &
        "vCWpfsckjAYQWSpnpC6JGkH7U5K5M+5/+Jl+RB5sjfXvgmdUREKhPmqjYeERimpm" & Character'Val (10) &
        "rovVVE6Qm86Wk+NAZ8RPTpljK39Fdtap0bNJafaQxH2L+vscmjXcA/EpzvuLqEHY" & Character'Val (10) &
        "wE7IpDMVeEeiAS2ko1OALqy2t1Bh4m+NgKJ2pPcEcIYMpW2/ltbor7Rv2xLhptb9" & Character'Val (10) &
        "P/kVEo0sr+uHEYzhYPY6gc3eOPuVH7zLPVNOfB4xvBAl5YW5Z8AR0ESUER+ZBvPI" & Character'Val (10) &
        "3tLcs4Om9lm/Xl56aNaVbwP3WaXY97NO4rzXzEb8yNABesJzgX6aWg03sVn3mbII" & Character'Val (10) &
        "CdwrIqCp" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----";
   end Encrypted_PKCS8_RSA_PKCS12_SHA1_2DES_Private_Key;

   function Encrypted_PKCS8_RSA_PKCS12_SHA1_RC2_40_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "MIICojAcBgoqhkiG9w0BDAEGMA4ECGL/CXmQdQc8AgIIAASCAoD2EIFJtAXFlwUp" & Character'Val (10) &
        "ax0iiiY9Mne6ZQtyd1LczQQTjlS3FkxiW7kjZj+hKpgurW6FyhebfMjB5+aydeNm" & Character'Val (10) &
        "nnoOCykfkYf+un/ZV5C0lnVJ/F7ItRDpspEMKA3YhhE3jrnzG/GQ71qQhUpcv5a9" & Character'Val (10) &
        "07pQbyir2146creHWhhMEU3WudgGMzLLBJoNzjwE71TsQE1IiY3Dy+P36Fmi80JQ" & Character'Val (10) &
        "V1Wx3KbtzEuB1y84L7QVGb9dMlivQ/sK/UUX+sgV+Z1TnBzzwgjxTJWyiwMAilcN" & Character'Val (10) &
        "ru5RPQkWOM82dlsAWr0LPpFtC3RjVQNp24QSf8ML7B2IwR7s7Plg4VS1U7PDfJ2h" & Character'Val (10) &
        "WUwQc4Dy78s0loH4VrHwpbRjrUDe5V88Lhuifyi/ZxPTaWCxQF6YdvSzBX8EZnkI" & Character'Val (10) &
        "GFJIkb9jeLL9OZPhW/tbh2GnlyNhVWHmTn/rPZYuIVlryZ0FGSuzNdkDBRpbbEP5" & Character'Val (10) &
        "UwskdZA3XJLk/0piZojdcwQb7eOliDpUOKnh1OJNMr7mo31+O28UdsGLcG/6Roy/" & Character'Val (10) &
        "0776rXQv6lU6Prq9R/T/IRaihJY6Mbr4gvfxIASeHbaos1KXOKAZabmLhPSN1Oi4" & Character'Val (10) &
        "8pCT7iAWlNPOt+788pgh6NL27h7K0qm/Pm605kHaVZTQkfQbWXO2qwvVpsg78z81" & Character'Val (10) &
        "8mSnJdKjLrKiQDMudBNY+Tp3CK7hqn0ZwDvZPMbEJWE+oA2yHOsSqZRV5j7avFhA" & Character'Val (10) &
        "2bKty702jsPmzOeF+cc1zegiW+72XwWKIngcfyPY97o7wApmQByP32YrqF8uy/94" & Character'Val (10) &
        "kLXgV3aySkmza0nGEt+/2bZV+q1L5mk0QKA8vUXEnGlEQBzVSzx+MfOZ5uRzLb/d" & Character'Val (10) &
        "Vl/anovy" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----";
   end Encrypted_PKCS8_RSA_PKCS12_SHA1_RC2_40_Private_Key;

   function Encrypted_PKCS8_RSA_PKCS12_SHA1_RC2_128_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "MIICojAcBgoqhkiG9w0BDAEFMA4ECP63gwlx4rmUAgIIAASCAoD1ZxTYvWR9Ngyt" & Character'Val (10) &
        "rxZMsbjeTBBr2kysz4E6MnHeEWW5vIDCFYRiQtYe/SwHaWhZMZYmwL63A48EYTLr" & Character'Val (10) &
        "tA4vIPsIcyJ6FNlwTnTUJ98L4YA5Q7QGoKD3aq3qmqMxpnfwopnI5ZZKmvFijqpJ" & Character'Val (10) &
        "OHGipHUlDezn3BaHA1Od7YWw/67TuQbSFCU4u0UHieCuyrgsBotcWb0GWerHUxG2" & Character'Val (10) &
        "zTQoXkqFTwKuOaIxlWtkTZ9H3u7bwolx6RGOOqMuC8t9xu01v+HD3g225UOebZPM" & Character'Val (10) &
        "oNcLVrisEOOFjqpfV9Dlvb2C3sUo53J2fHDcAb6UzZfO9y9GJUne5fyBwNfgExD+" & Character'Val (10) &
        "QhOF65XR8fZjZ61Zn9ja1qW0TTGbnviR8rQVDbsbzzqTXEXWl6AtR6b6/M7rDnvg" & Character'Val (10) &
        "nDE3tpxUMiaGCXtlhugX4+qRKC8D3b/NqKVnHICZ31oxJklfVq3VAn/hQwFanWO9" & Character'Val (10) &
        "NbOr7bQ0Lz9NFN2TZ7LzYJOKxWLejkQbhDNOuSA0ECBLw1QQoliym/uvSkJ7Dbei" & Character'Val (10) &
        "L8wxBaKxPT2fm4/3/ExS6wPzmPmd3btc/JnWqtR33KEvIETnixDT8/JcCPp3daCw" & Character'Val (10) &
        "Jsw1ipew09TRi07x9P/MZRS6i4KrMK9fU0fIoFGSe+f4lk4HybsodKk1t2lYTtFd" & Character'Val (10) &
        "lVka51GcuxRLx7M9D5/pmRKuCQA+SavWlv3hAH5OP1qW3jc/IJ39L9SiU/Tyanfx" & Character'Val (10) &
        "+tIbP6+0zttu+Tw53Y6zzgxqBhmFNcwYtk1s1xxTDqO+TlcuQ8ROMqFfiBwuOYOv" & Character'Val (10) &
        "Z3/GtiATqertKdh3mdvBaG5qDJtrx1SsdEqHHOAcfED4Cklt8RyWB2ztHTzZgaJB" & Character'Val (10) &
        "eLx+39Rq" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----";
   end Encrypted_PKCS8_RSA_PKCS12_SHA1_RC2_128_Private_Key;

   function Encrypted_PKCS8_RSA_PBES2_RC2_40_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "MIIC3TBXBgkqhkiG9w0BBQ0wSjAsBgkqhkiG9w0BBQwwHwQIIWwaG+e7F2sCAggA" & Character'Val (10) &
        "AgEFMAwGCCqGSIb3DQIJBQAwGgYIKoZIhvcNAwIwDgICAKAECPADeOplfep4BIIC" & Character'Val (10) &
        "gFJ6kkLfrz+8p2vAWEYKXcZdokbS8d+ad1cOFnen/KkEOQFxszkdJMvpT92sB1en" & Character'Val (10) &
        "flT8fQ2OH4QBv8OtlY3WH0uPc+QVabkKhuF11L1wkXdSU37JYXlhJdExApGlwv7F" & Character'Val (10) &
        "GBmuS9/xgejTYfMsmK2JA4kc9Z1GddeAbkqMUHcgpKNMKrTvVpTesxW5U59bKDg+" & Character'Val (10) &
        "d6CObZfT5qSpwBgYyeHA+aCa3PwTdJlJc+5xOWXIJKFK2RJepVLQSiozrsp/wz3U" & Character'Val (10) &
        "mdy4QlHX1d8e8J+XzBplSmIjrPQeDgTOsjQVlV9jWpMiMjR+OmWjoPrkvsBPbIil" & Character'Val (10) &
        "xrkQ3Tp3H/GVzqbtDuAXg7l93Y/nKBXSaMuRZx/+uZLf3UVdOqZD31pi3yix4acr" & Character'Val (10) &
        "aaAlZBucAUEaLkHcLet8s92nesYzNMb6dU77jmrUGfupRegwSIo4kFyXPt2Ibc3y" & Character'Val (10) &
        "Wdg2ynbDR8ngKgcdjC5mlSNAo9oG88+DNZfPRZRzOrphrbq17eMx9fzWQkGmZ0hC" & Character'Val (10) &
        "IeGakXVdiPWChQl4prvBJRwnx8yypWGFJB6qEp8tzM5J5vDmi2ZIBvsNktflSFqE" & Character'Val (10) &
        "sFFwURh34tp0vvZcXgnA4CKDYwDUjcpiXh7pdqbWd2yZcOQ918fkz7fDjDrGXW2b" & Character'Val (10) &
        "RMrxLM7fyPe40fTkBV8+f4ymf6UwioMWCSuTNNgmLzxlAIc/s6CX2SYRSmcrkjlu" & Character'Val (10) &
        "eOTVBawA5HOvNAXKt1dXR7m+tfmXxg3rh9L451dQC7uHxKWHr1D7cwH3pc0mUIFS" & Character'Val (10) &
        "D14tdrngwkpQsSjXZ7GhBTUrZ3dtyq6NnDkUni8aGQ4k+En9SBlPBzSi4cZ3OIbr" & Character'Val (10) &
        "aCmHbG58wG/R3UwkAw2P9TE=" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----";
   end Encrypted_PKCS8_RSA_PBES2_RC2_40_Private_Key;

   function Encrypted_PKCS8_RSA_PBES2_RC2_64_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "MIIC3DBWBgkqhkiG9w0BBQ0wSTAsBgkqhkiG9w0BBQwwHwQIkzQABwrLrkcCAggA" & Character'Val (10) &
        "AgEIMAwGCCqGSIb3DQIJBQAwGQYIKoZIhvcNAwIwDQIBeAQI0ZL8FFD3I6UEggKA" & Character'Val (10) &
        "LB+IBl0FXvd34zAU84ftPHOK9IZpmtPKoJnn9Ll+qyhyEEwqIrZQzRQJyrM//AnR" & Character'Val (10) &
        "h063jKUyNjVlkyA4EgE9aTBnyIJGlzhP1DUuvmM2QTUIQK3OM0lno/ScOVJ3Qb6g" & Character'Val (10) &
        "HDd6iWgw0mjiiqTE64FdVdh9Rgh0poul/JW4vBWGua8fAtpoEIl+LYVcEoA1YOyg" & Character'Val (10) &
        "fQEY17tpqCfTK6JyIIf95oEz22+9fhVbi/PginL7HG8ne/fmcZ+AdcjVrjGki6Aq" & Character'Val (10) &
        "l1KG8u503NB7fMkaXhNtXjRFu6GI1MaozfIEqLwWpJjrVla+AwIo/b3Ht+5Q2fqc" & Character'Val (10) &
        "7UzeY52DtiN37nXCXdlIZG2+453J2HWVNdoer+oLLMfJqCkN3vengZesqXgQ3Wrb" & Character'Val (10) &
        "+IvKG1h53jIdqaJsZAvMsq4juYSqzATQHTOQ4qSaHdvp+JMkg3zJyFoaKBtlRyGT" & Character'Val (10) &
        "BEqGXKGxALfyhlZdVFzqiA5DHbdLDTfIYHOmuPHRYj3/zNn/bFiZpIZeqcRjNsB+" & Character'Val (10) &
        "2M1UobOyI/g7tgZAelhK01jbj3lFXABjrmdfKpzgI+zWA8DZ0BcGd1lv68FOYVIi" & Character'Val (10) &
        "0CNw4l3VfVSvHdfXSE6nPbDa9rju6HSa+oaAyWrdUk5wubP8ZFnKaNLCHQGYJW0H" & Character'Val (10) &
        "t/Hh/cGzYbLJyWReoXKm/18hiA8wiXYNJ4gJn2cSftI8wwsqcIj0V78UxW88G8Yi" & Character'Val (10) &
        "JZmVrrLj1RgjrvslalkHof50eC32xZulN0yjxZ9mpea5uIAk/UgR/cWBuABi9gAL" & Character'Val (10) &
        "KkpPokwgY8f31KAVYwVjjelsziBwrIsTsk7KLf6nnybWiQlLJreF64Qqsrym7vf4" & Character'Val (10) &
        "6jvzfQbcTYyWGc+og+rvfg==" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----";
   end Encrypted_PKCS8_RSA_PBES2_RC2_64_Private_Key;

   function Encrypted_PKCS8_RSA_PBES2_RC2_128_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "MIIC3DBWBgkqhkiG9w0BBQ0wSTAsBgkqhkiG9w0BBQwwHwQI6Omuzh+EZssCAggA" & Character'Val (10) &
        "AgEQMAwGCCqGSIb3DQIJBQAwGQYIKoZIhvcNAwIwDQIBOgQIaSEkwKsQWEoEggKA" & Character'Val (10) &
        "dN+JKV0mLMEjOtRrf5Z0tai47XC3y/UibDmhiqhQ6l4gk45zNVsMnWTYImK9ICzj" & Character'Val (10) &
        "cB6aGcxxfQBurSlSfkSYigk2ooLO0J8OWZ8gprDVRZEzCL4crlk2Tm4ElB4i0og+" & Character'Val (10) &
        "JGm5hr7tLJmaollKgkd9C50/vC4XMYkAkxJ2HfBxm4u9g7dVuI2pvpYEVorIWILl" & Character'Val (10) &
        "VKstEEVorR3IoSndoNsGiutH/oX5JYIZu6L3mk1yn9k1Y/TpckCqP8IckELXdraU" & Character'Val (10) &
        "jhZSqENscfl8a9Vx9+BNd34HrxW3XtlHLLBumB9KbbUJ672MSJKtI5VeT0ofzdEQ" & Character'Val (10) &
        "eKpzP/0ck1eGHa0X1Xq8bFoMxgDWrzuVvM1dxM14SMVEOmBH87Oq1T9VcaRPIwCH" & Character'Val (10) &
        "tofcKADs8SPFrr16dvEo4pwW58H+fxbyDoBfElJxY1b5NcAzDvbsPRoHPSOo8gQr" & Character'Val (10) &
        "PBKMFDlQl3QgZ/pRP0niC+EvtEvktSLeZ3hHSJLVYG0ZRXclz3lw6KGyP3Fc9ScX" & Character'Val (10) &
        "fkUm+BTvlsfjPYvHXQYUN1W4G/M2xlZCmzL/TPp7bpVMkMdOjrSmlvv3EZX6FuzL" & Character'Val (10) &
        "pNMyy7qvRu0cxXZNx2/zfb5TxCH153xeCUrdFbNTPn3Ob6MpPEgH290fGCbu6X+T" & Character'Val (10) &
        "Uc0C8m3eiJAasTzWkrxH/2hOknzzBbOol8yqUAtcPf1e/4J/5Ye4gvSqv4EMVyZA" & Character'Val (10) &
        "xIF1XL56gsv+5a770qjHxeia2N8fC97lJUedVC0NRzCFVe0Bhhy7QbiQO7hus++J" & Character'Val (10) &
        "0x0EkmUEwIlrqscN+7DhIkWTv+5yXxesDJzXqz0ED6i+uyM1+w+vnq65Ik3oOS1K" & Character'Val (10) &
        "KmDZxiKyZUeIvsLWYRdN2g==" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----";
   end Encrypted_PKCS8_RSA_PBES2_RC2_128_Private_Key;

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

   function Encrypted_PKCS8_EC_P256_AES256_CBC_Private_Key return String is
   begin
      return
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" & Character'Val (10) &
        "MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAi18Cpn/5zklgICCAAw" & Character'Val (10) &
        "DAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEKCQ1Y1QySxbPu1BAW3Ku1sEgZDU" & Character'Val (10) &
        "1zHoT4jp+Gxhyzo0h1s51xsDZkkZ+JZ3nhbizULTumgTn7hRy+M3YyX/FUeXW/6C" & Character'Val (10) &
        "KsPJfrd0X/HrGJDqshLDksH8bIetwA5DV8ryy4NbmJaMX2rgc05z6wWQ3aWC/W9z" & Character'Val (10) &
        "5Yn1rRiHSCxKPNmXUSaRAJjpy17EX563hDWW3IbX7oBrlW67hJNnwrb9L3vBS/E=" & Character'Val (10) &
        "-----END ENCRYPTED PRIVATE KEY-----";
   end Encrypted_PKCS8_EC_P256_AES256_CBC_Private_Key;

   function Encrypted_Legacy_EC_P256_AES256_CBC_Private_Key return String is
   begin
      return
        "-----BEGIN EC PRIVATE KEY-----" & Character'Val (10) &
        "Proc-Type: 4,ENCRYPTED" & Character'Val (10) &
        "DEK-Info: AES-256-CBC,187441279657F0302F07C2F52596821A" & Character'Val (10) &
        "" & Character'Val (10) &
        "Yd/U1oLAhpkd1+DSrlffCWym2M50V3b8pAyQAxFo9g5Ehb4boH6KUAgkYo8KZ5WV" & Character'Val (10) &
        "oRjiGNlu0iAMbCMnZGFoHjfrmHFrcicz1V4Y6iGEboRd46yAHdoEceZOOjE55ViK" & Character'Val (10) &
        "ByYInuyBs9dCESc+ra0SnPgTQI2nlslYLF9t+kmVYpY=" & Character'Val (10) &
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
