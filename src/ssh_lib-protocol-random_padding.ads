with Ada.Streams;
with CryptoLib.Errors;

--  @summary CSPRNG byte source for SSH binary-packet padding.
--
--  Supplies cryptographically random bytes used to fill the random-padding
--  field of the SSH binary packet, lazily initializing a production random
--  source on first use.
package SSH_Lib.Protocol.Random_Padding is
   --  Draw the next cryptographically random padding byte.
   --  @param Value the random byte produced, or 0 on failure
   --  @return Ok on success, otherwise the underlying CSPRNG failure status
   function Next_Byte
     (Value : out Ada.Streams.Stream_Element)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Random_Padding;
