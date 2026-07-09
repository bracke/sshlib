with SSH_Lib.Algorithms;
with CryptoLib.Errors;

--  @summary Post-negotiation guards validating peer-selected SSH algorithms.
--
--  Enforces that an algorithm a peer claims to have selected was actually
--  advertised by this client, is a valid and supported (non-legacy,
--  implemented) name, that the KEX reply echoes the negotiated key exchange,
--  and that the chosen compression is the "none" method.
package SSH_Lib.Protocol.Algorithm_Guards is
   --  Verify a peer-selected algorithm was advertised, valid, and supported.
   --  @param Class_Item        the algorithm class/direction being negotiated
   --  @param Client_Advertised the comma-separated name list this client offered
   --  @param Selected_Name     the algorithm name the peer claims was selected
   --  @return Ok if accepted; Handshake_Failed if invalid or not advertised;
   --          Unsupported_Feature (or a fail-closed status) if not implemented;
   --          Internal_Error on any exception
   function Selected_Algorithm_Accepted
     (Class_Item        : SSH_Lib.Algorithms.Algorithm_Class;
      Client_Advertised : String;
      Selected_Name     : String)
      return CryptoLib.Errors.Status;

   --  Verify the KEX reply's key exchange matches the negotiated one and is supported.
   --  @param Negotiated_Key_Exchange the key-exchange name agreed during KEXINIT
   --  @param Reply_Key_Exchange      the key-exchange name carried in the reply
   --  @return Ok if consistent and supported; Handshake_Failed if invalid or
   --          mismatched; Unsupported_Feature if unimplemented; Internal_Error
   --          on any exception
   function Kex_Reply_Consistent
     (Negotiated_Key_Exchange : String;
      Reply_Key_Exchange      : String)
      return CryptoLib.Errors.Status;

   --  Verify the selected compression method is the "none" (no-compression) method.
   --  @param Selected_Name the compression algorithm name the peer selected
   --  @return Ok if it is the available "none" method; Handshake_Failed if the
   --          name is invalid; Unsupported_Feature otherwise; Internal_Error on
   --          any exception
   function Compression_Is_None
     (Selected_Name : String)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Algorithm_Guards;
