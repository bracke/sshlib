with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Keys;

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

   function Default_File return Ada.Strings.Unbounded.Unbounded_String;

   function Load
     (Path : String;
      Item : out Database)
      return CryptoLib.Errors.Status;

   function Check
     (Item : Database;
      Host : String;
      Port : Natural;
      Key  : SSH_Lib.Keys.Public_Key)
      return CryptoLib.Errors.Status;

   function Create_Host_Key
     (Algorithm   : String;
      Encoded_Key : String)
      return Host_Key;

   function Algorithm (Item : Host_Key) return String;
   function Encoded (Item : Host_Key) return String;

   function Is_Valid (Item : Host_Key) return Boolean;

   function Equal
     (Left_Item  : Host_Key;
      Right_Item : Host_Key)
      return Boolean;

   function From_Public_Key
     (Presented_Key : SSH_Lib.Keys.Public_Key;
      Item          : out Host_Key)
      return CryptoLib.Errors.Status;

   function SHA256_Fingerprint
     (Item  : Host_Key;
      Value : out SSH_Lib.Keys.Fingerprint)
      return CryptoLib.Errors.Status;

   function Verify
     (Known_Hosts_File : String;
      Host             : String;
      Port             : Natural;
      Presented_Key    : Host_Key)
      return Verification_Result;

   --  Explicitly append a trusted host key to a known_hosts file.
   --  This is an opt-in workflow helper only; Sessions.Open never calls it
   --  automatically, so unknown hosts still fail closed by default.
   function Append_Trusted_Host
     (Known_Hosts_File : String;
      Host             : String;
      Port             : Natural;
      Presented_Key    : Host_Key)
      return CryptoLib.Errors.Status;

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
