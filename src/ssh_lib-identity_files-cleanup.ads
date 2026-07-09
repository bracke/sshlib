with CryptoLib.Errors;

--  @summary Zeroization helpers for identity-key parse teardown.
--
--  Scrubs the secret material held in an Identity_Key, both on explicit release
--  and on a failed parse, so partially populated keys never leak.
package SSH_Lib.Identity_Files.Cleanup is
   --  Unconditionally clear the identity key, wiping any loaded secrets.
   --  @param Item the identity key to scrub
   procedure Release
     (Item : out Identity_Key);

   --  Finalize a parse: clear the key on failure and pass the status through.
   --  @param Item         the identity key, scrubbed if the parse failed
   --  @param Status_Value the parse outcome to evaluate and return
   --  @return Status_Value, or Internal_Error if scrubbing raised
   function Finish_Parse
     (Item         : in out Identity_Key;
      Status_Value : CryptoLib.Errors.Status)
      return CryptoLib.Errors.Status;
end SSH_Lib.Identity_Files.Cleanup;
