with Ada.Streams;
with CryptoLib.Errors;
with CryptoLib.Random;
with CryptoLib.Buffers;

package SSH_Lib.ECDSA is

   function Verify_Nistp256
     (Public_Key_Blob : Ada.Streams.Stream_Element_Array;
      Signature_Bytes : Ada.Streams.Stream_Element_Array;
      Message_Bytes   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Validate_Public_Nistp256
     (Public_Key_Blob : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Validate_Signature_Nistp256
     (Signature_Bytes : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Public_Matches_Private_Nistp256
     (Public_Key_Blob      : Ada.Streams.Stream_Element_Array;
      Private_Scalar_Mpint : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Sign_Nistp256
     (Private_Scalar_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes        : Ada.Streams.Stream_Element_Array;
      Signature_Bytes      : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Validate_Raw_Point_Nistp256
     (Public_Point_Bytes : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Generate_ECDH_Nistp256_Keypair
     (Source_Item          : in out CryptoLib.Random.Random_Source;
      Private_Scalar_Bytes : out Ada.Streams.Stream_Element_Array;
      Public_Point_Bytes   : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Validate_ECDH_Nistp256_Shared_Secret
     (Shared_Secret_Bytes : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Compute_ECDH_Nistp256_Shared_Secret
     (Private_Scalar_Bytes : Ada.Streams.Stream_Element_Array;
      Server_Point_Bytes   : Ada.Streams.Stream_Element_Array;
      Shared_Secret_Bytes  : out Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;
end SSH_Lib.ECDSA;
