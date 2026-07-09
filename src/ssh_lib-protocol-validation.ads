--  @summary Validation of untrusted SSH protocol strings.
--
--  Small, side-effect-free predicates that reject malformed wire strings before
--  they are used, so decoded names cannot smuggle control or non-ASCII bytes.
package SSH_Lib.Protocol.Validation is
   pragma Pure;

   --  True when Value is a well-formed SSH protocol name: non-empty and composed
   --  only of visible ASCII characters '!' .. '~' (no space, control, or
   --  non-ASCII bytes).
   --  @param Value the candidate protocol/algorithm name to check
   --  @return True if the string is a valid ASCII protocol name
   function Is_ASCII_Protocol_Name (Value : String) return Boolean;
end SSH_Lib.Protocol.Validation;
