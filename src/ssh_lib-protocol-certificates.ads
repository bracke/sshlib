with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Keys;

--  @summary Parsing and validation of OpenSSH host and user certificates.
--
--  Decodes an OpenSSH "*-cert-v01@openssh.com" certificate blob and checks it
--  against policy: certificate type, principal patterns, validity window,
--  critical options and extensions, and the CA signature over the certified
--  key.
package SSH_Lib.Protocol.Certificates is
   --  Whether an algorithm name is an OpenSSH certificate algorithm.
   --  @param Algorithm_Name the algorithm/key-type name to test
   --  @return True if the name denotes a "*-cert-v01@openssh.com" algorithm
   function Is_Certificate_Algorithm (Algorithm_Name : String) return Boolean;

   --  The underlying raw key algorithm for a certificate algorithm name.
   --  @param Algorithm_Name the certificate algorithm name
   --  @return the corresponding raw key algorithm name (e.g. "ssh-ed25519"),
   --          or the empty string if it is not a certificate algorithm
   function Raw_Algorithm_For_Certificate
     (Algorithm_Name : String) return String;

   --  Parse a host certificate blob, extracting the certified key and the CA
   --  (signature) key without enforcing validity policy.
   --  @param Certificate_Blob      the raw certificate wire blob
   --  @param Certificate_Algorithm the certificate algorithm name
   --  @param Host_Key              the certified host public key
   --  @param Signature_Key         the CA public key that signed the certificate
   --  @return Ok on success, or an error Status if the blob is malformed
   function Parse_Host_Certificate
     (Certificate_Blob      : Ada.Streams.Stream_Element_Array;
      Certificate_Algorithm : String;
      Host_Key              : out SSH_Lib.Keys.Public_Key;
      Signature_Key         : out SSH_Lib.Keys.Public_Key)
      return CryptoLib.Errors.Status;

   --  Fully validate a host certificate: type, critical options, extensions,
   --  principal match against Host/Port, validity window, and CA signature by
   --  the given authority key.
   --  @param Certificate_Blob      the raw certificate wire blob
   --  @param Certificate_Algorithm the certificate algorithm name
   --  @param Host                  the host name being connected to
   --  @param Port                  the port being connected to
   --  @param Authority_Key_Blob    the trusted CA public-key blob
   --  @return Ok if valid, or a specific error Status (e.g. Host_Key_Mismatch)
   function Validate_Host_Certificate
     (Certificate_Blob      : Ada.Streams.Stream_Element_Array;
      Certificate_Algorithm : String;
      Host                  : String;
      Port                  : Natural;
      Authority_Key_Blob    : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Verify only that a host certificate's CA signature was produced by the
   --  given authority key (no principal or validity checks).
   --  @param Certificate_Blob      the raw certificate wire blob
   --  @param Certificate_Algorithm the certificate algorithm name
   --  @param Authority_Key_Blob    the candidate CA public-key blob
   --  @return Ok if the signature verifies, or an error Status otherwise
   function Host_Certificate_Signed_By_Public_Key
     (Certificate_Blob      : Ada.Streams.Stream_Element_Array;
      Certificate_Algorithm : String;
      Authority_Key_Blob    : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Test helper: whether a certificate principal list matches Host/Port.
   --  @param Principals the encoded principal-name list
   --  @param Host       the host name to match
   --  @param Port       the port to match
   --  @return True if a principal pattern matches the host/port
   function Host_Principals_Match_For_Test
     (Principals : Ada.Streams.Stream_Element_Array;
      Host       : String;
      Port       : Natural) return Boolean;

   --  Test helper: validate a host certificate's critical-options map.
   --  @param Options the encoded critical-options map
   --  @return Ok if the options are well-formed and permitted, else an error Status
   function Validate_Host_Critical_Options_For_Test
     (Options : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Test helper: validate a user certificate's critical-options map.
   --  @param Options the encoded critical-options map
   --  @return Ok if the options are well-formed and permitted, else an error Status
   function Validate_User_Critical_Options_For_Test
     (Options : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Validate a user certificate for use in publickey authentication: type,
   --  well-formed principals, and a supported, well-formed certified key shape.
   --  @param Certificate_Blob      the raw certificate wire blob
   --  @param Certificate_Algorithm the certificate algorithm name
   --  @return Ok if usable for auth, else an error Status (e.g. Authentication_Failed)
   function Validate_User_Certificate_For_Auth
     (Certificate_Blob      : Ada.Streams.Stream_Element_Array;
      Certificate_Algorithm : String) return CryptoLib.Errors.Status;

   --  Validate a user certificate and confirm its certified key matches the
   --  given signing key (type, principals, options, validity, key equality).
   --  @param Certificate_Blob      the raw certificate wire blob
   --  @param Certificate_Algorithm the certificate algorithm name
   --  @param Signing_Key_Blob      the public-key blob of the signing identity
   --  @return Ok if valid and matching, else an error Status
   function Certificate_Matches_Signing_Key
     (Certificate_Blob      : Ada.Streams.Stream_Element_Array;
      Certificate_Algorithm : String;
      Signing_Key_Blob      : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Certificates;
