with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Keys;

package SSH_Lib.Protocol.Certificates is
   function Is_Certificate_Algorithm (Algorithm_Name : String) return Boolean;

   function Raw_Algorithm_For_Certificate
     (Algorithm_Name : String) return String;

   function Parse_Host_Certificate
     (Certificate_Blob      : Ada.Streams.Stream_Element_Array;
      Certificate_Algorithm : String;
      Host_Key              : out SSH_Lib.Keys.Public_Key;
      Signature_Key         : out SSH_Lib.Keys.Public_Key)
      return CryptoLib.Errors.Status;

   function Validate_Host_Certificate
     (Certificate_Blob      : Ada.Streams.Stream_Element_Array;
      Certificate_Algorithm : String;
      Host                  : String;
      Port                  : Natural;
      Authority_Key_Blob    : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Host_Certificate_Signed_By_Public_Key
     (Certificate_Blob      : Ada.Streams.Stream_Element_Array;
      Certificate_Algorithm : String;
      Authority_Key_Blob    : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Host_Principals_Match_For_Test
     (Principals : Ada.Streams.Stream_Element_Array;
      Host       : String;
      Port       : Natural) return Boolean;

   function Validate_Host_Critical_Options_For_Test
     (Options : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Validate_User_Critical_Options_For_Test
     (Options : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Validate_User_Certificate_For_Auth
     (Certificate_Blob      : Ada.Streams.Stream_Element_Array;
      Certificate_Algorithm : String) return CryptoLib.Errors.Status;

   function Certificate_Matches_Signing_Key
     (Certificate_Blob      : Ada.Streams.Stream_Element_Array;
      Certificate_Algorithm : String;
      Signing_Key_Blob      : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Certificates;
