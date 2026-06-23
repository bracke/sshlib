with Ada.Streams;
with CryptoLib.Errors;

package SSH_Lib.Protocol.Random_Padding is
   function Next_Byte
     (Value : out Ada.Streams.Stream_Element)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Random_Padding;
