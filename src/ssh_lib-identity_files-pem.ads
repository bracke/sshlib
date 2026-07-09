--  @summary Detection of PEM-armored (non-OpenSSH) private-key material.
--
--  Pure textual sniffing of the "-----BEGIN ...-----" banners and PEM headers
--  that mark legacy OpenSSL/PKCS#8 private keys, so a loader can tell them apart
--  from the native OpenSSH key format and detect passphrase-protected files.
package SSH_Lib.Identity_Files.PEM is
   --  True when the text carries a legacy PEM private-key banner (RSA, EC,
   --  PKCS#8 PRIVATE KEY, or ENCRYPTED PRIVATE KEY) rather than OpenSSH armor.
   --  @param Text the candidate identity-file contents to inspect
   --  @return True if any legacy PEM private-key header is present
   function Is_Legacy_PEM_Armor (Text : String) return Boolean;
   --  True when the PEM text denotes an encrypted private key, via a PKCS#8
   --  ENCRYPTED banner or the legacy "Proc-Type: 4,ENCRYPTED" / "DEK-Info:"
   --  headers.
   --  @param Text the candidate identity-file contents to inspect
   --  @return True if the key material is passphrase-protected
   function Is_Encrypted_PEM_Armor (Text : String) return Boolean;
end SSH_Lib.Identity_Files.PEM;
