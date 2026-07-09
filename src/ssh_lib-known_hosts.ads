with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Keys;

--  @summary OpenSSH known_hosts host-key trust database.
--
--  Loads and queries an OpenSSH-format known_hosts file to decide whether a
--  server's presented host key is trusted, unknown, or mismatched.  Supports
--  plain and hashed host entries, standard-port omission, SHA-256/named
--  fingerprints, and an opt-in helper to append a newly trusted host key.
--  Unknown hosts fail closed: Sessions.Open never trusts on first use.
package SSH_Lib.Known_Hosts is
   type Verification_Result is
     (Trusted,
      Unknown,
      Mismatch,
      Invalid_Record,
      Unsupported_Entry,
      Unavailable);

   type Host_Key is private;
   type Database is private;

   --  Return the default known_hosts path (~/.ssh/known_hosts).
   --  @return the default known_hosts file path
   function Default_File return Ada.Strings.Unbounded.Unbounded_String;

   --  Load a known_hosts database from a file path (~-expanded, empty means the
   --  default file), retaining the path for later per-host queries.
   --  @param Path the known_hosts file path, or "" for Default_File
   --  @param Item the loaded database
   --  @return Ok on success, else a failure Status
   function Load
     (Path : String;
      Item : out Database)
      return CryptoLib.Errors.Status;

   --  Verify a server's public key against a loaded database for Host/Port.
   --  @param Item the loaded database to consult
   --  @param Host the server host name or address being connected to
   --  @param Port the server port (standard port 22 matches unadorned entries)
   --  @param Key  the host public key presented by the server
   --  @return Ok if trusted, else Host_Key_Unknown, Host_Key_Mismatch, or
   --          another failure Status
   function Check
     (Item : Database;
      Host : String;
      Port : Natural;
      Key  : SSH_Lib.Keys.Public_Key)
      return CryptoLib.Errors.Status;

   --  Build a Host_Key value from an algorithm name and base64-encoded key.
   --  @param Algorithm   the SSH host-key algorithm name (e.g. "ssh-ed25519")
   --  @param Encoded_Key the base64-encoded key blob
   --  @return the constructed Host_Key
   function Create_Host_Key
     (Algorithm   : String;
      Encoded_Key : String)
      return Host_Key;

   --  Return the algorithm name of a host key.
   --  @param Item the host key
   --  @return the SSH host-key algorithm name
   function Algorithm (Item : Host_Key) return String;
   --  Return the base64-encoded key blob of a host key.
   --  @param Item the host key
   --  @return the base64-encoded key text
   function Encoded (Item : Host_Key) return String;

   --  Report whether a host key is well formed (supported algorithm and valid
   --  base64 blob).
   --  @param Item the host key to check
   --  @return True if the host key is valid
   function Is_Valid (Item : Host_Key) return Boolean;

   --  Compare two host keys for equal algorithm and key material.
   --  @param Left_Item  the first host key
   --  @param Right_Item the second host key
   --  @return True if both keys are equal
   function Equal
     (Left_Item  : Host_Key;
      Right_Item : Host_Key)
      return Boolean;

   --  Convert a presented SSH public key into a Host_Key record.
   --  @param Presented_Key the public key presented by the server
   --  @param Item          the resulting Host_Key
   --  @return Ok on success, else a failure Status
   function From_Public_Key
     (Presented_Key : SSH_Lib.Keys.Public_Key;
      Item          : out Host_Key)
      return CryptoLib.Errors.Status;

   --  Compute the SHA-256 fingerprint of a host key.
   --  @param Item  the host key to fingerprint
   --  @param Value the resulting SHA-256 fingerprint
   --  @return Ok on success, else a failure Status
   function SHA256_Fingerprint
     (Item  : Host_Key;
      Value : out SSH_Lib.Keys.Fingerprint)
      return CryptoLib.Errors.Status;

   --  Compute a host-key fingerprint using a named hash (e.g. "sha256", "md5").
   --  @param Item      the host key to fingerprint
   --  @param Hash_Name the hash algorithm name
   --  @param Value     the resulting fingerprint
   --  @return Ok on success, else a failure Status
   function Fingerprint_With_Hash
     (Item      : Host_Key;
      Hash_Name : String;
      Value     : out SSH_Lib.Keys.Fingerprint)
      return CryptoLib.Errors.Status;

   --  Verify a presented host key against a known_hosts file for Host/Port,
   --  returning the fine-grained verification outcome.
   --  @param Known_Hosts_File the known_hosts file path (~-expanded, "" means
   --                          the default file)
   --  @param Host             the server host name or address
   --  @param Port             the server port (22 matches unadorned entries)
   --  @param Presented_Key    the host key presented by the server
   --  @return the verification result (Trusted, Unknown, Mismatch, ...)
   function Verify
     (Known_Hosts_File : String;
      Host             : String;
      Port             : Natural;
      Presented_Key    : Host_Key)
      return Verification_Result;

   --  Explicitly append a trusted host key to a known_hosts file.
   --  This is an opt-in workflow helper only; Sessions.Open never calls it
   --  automatically, so unknown hosts still fail closed by default.
   --  @param Known_Hosts_File the known_hosts file to append to (created/
   --                          extended; ~-expanded, "" means the default file)
   --  @param Host             the server host name or address to record
   --  @param Port             the server port (22 written without adornment)
   --  @param Presented_Key    the host key to trust and record
   --  @param Hash_Host        when True, write a hashed (HashKnownHosts) entry
   --  @return Ok on success, else a failure Status
   function Append_Trusted_Host
     (Known_Hosts_File : String;
      Host             : String;
      Port             : Natural;
      Presented_Key    : Host_Key;
      Hash_Host        : Boolean := False)
      return CryptoLib.Errors.Status;

   --  Map a Verification_Result to the corresponding CryptoLib error Status.
   --  @param Value the verification result to translate
   --  @return Ok for Trusted, else the matching failure Status
   function To_Status
     (Value : Verification_Result)
      return CryptoLib.Errors.Status;

private
   type Host_Key is record
      Algorithm_Text : Ada.Strings.Unbounded.Unbounded_String;
      Encoded_Text   : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   type Database is record
      Path_Text : Ada.Strings.Unbounded.Unbounded_String;
      Loaded    : Boolean := False;
   end record;
end SSH_Lib.Known_Hosts;
