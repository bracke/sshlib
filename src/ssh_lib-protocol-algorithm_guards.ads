with SSH_Lib.Algorithms;
with CryptoLib.Errors;

package SSH_Lib.Protocol.Algorithm_Guards is
   function Selected_Algorithm_Accepted
     (Class_Item        : SSH_Lib.Algorithms.Algorithm_Class;
      Client_Advertised : String;
      Selected_Name     : String)
      return CryptoLib.Errors.Status;

   function Kex_Reply_Consistent
     (Negotiated_Key_Exchange : String;
      Reply_Key_Exchange      : String)
      return CryptoLib.Errors.Status;

   function Compression_Is_None
     (Selected_Name : String)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Algorithm_Guards;
