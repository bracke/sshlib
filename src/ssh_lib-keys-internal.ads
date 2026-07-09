with Ada.Streams;
with CryptoLib.Errors;

--  @summary Internal accessors for the opaque Public_Key representation.
--
--  Lets sibling protocol code read a public key's raw SSH wire blob, reset a
--  key to empty, and populate one from an algorithm name and blob, without
--  exposing the Public_Key internals to clients.
package SSH_Lib.Keys.Internal is
   --  Return the raw SSH public-key blob stored in Item.
   --  @param Item the public key to read
   --  @return the key's wire-format blob as a byte array
   function Raw_Blob
     (Item : Public_Key)
      return Ada.Streams.Stream_Element_Array;

   --  Reset Item to the empty/absent state, clearing its algorithm and blob.
   --  @param Item the public key to clear
   procedure Clear (Item : out Public_Key);

   --  Populate Item from an algorithm name and its raw blob.
   --  @param Item           the public key to fill, cleared on failure
   --  @param Algorithm_Name the SSH algorithm name (e.g. "ssh-ed25519")
   --  @param Blob           the raw wire-format key blob
   --  @return Ok on success, Handshake_Failed if a field is empty, or the
   --          buffer/store error status; Internal_Error on any exception
   function Set_Public_Key
     (Item           : out Public_Key;
      Algorithm_Name : String;
      Blob           : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;
end SSH_Lib.Keys.Internal;
