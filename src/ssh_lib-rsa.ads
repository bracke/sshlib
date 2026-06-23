with Ada.Streams;
with CryptoLib.Errors;
with CryptoLib.Buffers;

package SSH_Lib.RSA is
   function Verify_SHA1
     (Public_Key_Blob : Ada.Streams.Stream_Element_Array;
      Signature_Bytes : Ada.Streams.Stream_Element_Array;
      Message_Bytes   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Verify_SHA2
     (Algorithm_Name : String;
      Public_Key_Blob : Ada.Streams.Stream_Element_Array;
      Signature_Bytes : Ada.Streams.Stream_Element_Array;
      Message_Bytes   : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Validate_Public_Key_Blob
     (Public_Key_Blob : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Sign_SHA1
     (Public_Key_Blob        : Ada.Streams.Stream_Element_Array;
      Private_Exponent_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes          : Ada.Streams.Stream_Element_Array;
      Signature_Bytes        : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Sign_SHA2_256
     (Public_Key_Blob        : Ada.Streams.Stream_Element_Array;
      Private_Exponent_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes          : Ada.Streams.Stream_Element_Array;
      Signature_Bytes        : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Sign_SHA2_512
     (Public_Key_Blob        : Ada.Streams.Stream_Element_Array;
      Private_Exponent_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes          : Ada.Streams.Stream_Element_Array;
      Signature_Bytes        : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Sign_SHA1_CRT
     (Public_Key_Blob       : Ada.Streams.Stream_Element_Array;
      Prime_P_Mpint         : Ada.Streams.Stream_Element_Array;
      Prime_Q_Mpint         : Ada.Streams.Stream_Element_Array;
      Exponent_DMP1_Mpint   : Ada.Streams.Stream_Element_Array;
      Exponent_DMQ1_Mpint   : Ada.Streams.Stream_Element_Array;
      Coefficient_IQMP_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes         : Ada.Streams.Stream_Element_Array;
      Signature_Bytes       : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Sign_SHA2_256_CRT
     (Public_Key_Blob       : Ada.Streams.Stream_Element_Array;
      Prime_P_Mpint         : Ada.Streams.Stream_Element_Array;
      Prime_Q_Mpint         : Ada.Streams.Stream_Element_Array;
      Exponent_DMP1_Mpint   : Ada.Streams.Stream_Element_Array;
      Exponent_DMQ1_Mpint   : Ada.Streams.Stream_Element_Array;
      Coefficient_IQMP_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes         : Ada.Streams.Stream_Element_Array;
      Signature_Bytes       : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Sign_SHA2_512_CRT
     (Public_Key_Blob       : Ada.Streams.Stream_Element_Array;
      Prime_P_Mpint         : Ada.Streams.Stream_Element_Array;
      Prime_Q_Mpint         : Ada.Streams.Stream_Element_Array;
      Exponent_DMP1_Mpint   : Ada.Streams.Stream_Element_Array;
      Exponent_DMQ1_Mpint   : Ada.Streams.Stream_Element_Array;
      Coefficient_IQMP_Mpint : Ada.Streams.Stream_Element_Array;
      Message_Bytes         : Ada.Streams.Stream_Element_Array;
      Signature_Bytes       : out CryptoLib.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;
end SSH_Lib.RSA;
