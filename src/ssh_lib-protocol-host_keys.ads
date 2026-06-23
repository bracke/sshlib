with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Keys;
with SSH_Lib.Protocol.Encrypted_State;

package SSH_Lib.Protocol.Host_Keys is
   function Parse
     (Blob                 : Ada.Streams.Stream_Element_Array;
      Negotiated_Algorithm : String;
      Item                 : out SSH_Lib.Keys.Public_Key)
      return CryptoLib.Errors.Status;

   function Verify_And_Store
     (Host_Key_Blob        : Ada.Streams.Stream_Element_Array;
      Signature_Blob       : Ada.Streams.Stream_Element_Array;
      Negotiated_Algorithm : String;
      Exchange_Hash        : Ada.Streams.Stream_Element_Array;
      State_Item           : in out SSH_Lib.Protocol.Encrypted_State.Kex_State)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Host_Keys;
