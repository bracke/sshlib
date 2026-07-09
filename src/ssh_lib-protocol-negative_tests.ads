with Ada.Streams;
with CryptoLib.Errors;

--  @summary Catalogue of negative/hostile-input test cases for the SSH
--  protocol, mapping each case to its expected Status, category, and invariant.
--
--  Enumerates the adversarial and edge-case scenarios (bad host keys,
--  unsupported algorithms, tampered packets, malformed config/identity input,
--  resource-bound violations, and byte-preservation checks) that the SSH
--  implementation must reject or handle deterministically.  The query
--  functions give tests the reference expectation for each case so behaviour
--  can be asserted uniformly.
package SSH_Lib.Protocol.Negative_Tests is
   type Negative_Category is
     (Host_Key_Category,
      Algorithm_Category,
      Packet_Protection_Category,
      Authentication_Category,
      Command_Quoting_Category,
      Remote_Config_Category,
      Binary_Stream_Category,
      Timeout_Dirty_Category,
      Resource_Bound_Category,
      Exception_Mapping_Category);

   type Negative_Invariant is
     (Rejects_Untrusted_Server_Identity,
      Rejects_Unsupported_Algorithms,
      Requires_Encrypted_Packet_Protection,
      Requires_Authenticated_Ordering,
      Preserves_Shell_Safe_Remote_Command,
      Parses_Config_As_Data_Only,
      Preserves_Opaque_Binary_Bytes,
      Enforces_Timeout_And_Dirty_State,
      Enforces_Resource_Bounds,
      Contains_Ordinary_Exceptions);

   type Negative_Case is
     (Host_Absent_From_Known_Hosts,
      Host_Key_Mismatch,
      Invalid_Host_Key_Signature,
      Unsupported_Known_Host_Key_Type,
      Malformed_Known_Hosts_Line,
      Hashed_Known_Hosts_Entry,
      Wildcard_Known_Hosts_Entry,
      Nonstandard_Port_Not_Trusted_By_Bare_Host,
      Host_Port_Mismatch,
      Known_Hosts_Check_After_Invalid_Signature,
      Host_Key_Verification_Disabled_Bypass,
      No_Supported_Kex,
      No_Supported_Host_Key,
      No_Supported_Cipher,
      No_Supported_Mac,
      Compression_Not_None,
      Unexpected_Algorithm,
      Inconsistent_Kex_Reply,
      Legacy_Ssh_Rsa_Sha1,
      Weak_Algorithm_Offered,
      Weak_Algorithm_Not_Selected,
      Unsupported_Selected_Algorithm,
      Bad_Mac,
      Wrong_Sequence_Mac,
      Truncated_Encrypted_Packet,
      Oversized_Packet,
      Invalid_Padding_Length,
      Packet_After_Dirty_State,
      Sequence_Number_Not_Incremented_Once,
      Packet_Length_Before_Allocation,
      Padding_Length_Exceeds_Packet,
      Mac_Failure_Dirties_Session,
      Service_Request_Before_Encryption,
      Service_Accept_Before_Encryption,
      Userauth_Before_Host_Trust,
      Userauth_Partial_Success,
      Userauth_Banner,
      Cipher_Not_Active_Before_Userauth,
      Agent_Signature_Wrong_Payload,
      Identity_Signature_Wrong_Payload,
      Session_Id_Not_First_Exchange_Hash,
      Missing_Agent,
      Agent_Connection_Failure,
      Oversized_Agent_Response,
      Malformed_Agent_Identity_List,
      Malformed_Agent_Response,
      Wrong_Agent_Signature_Algorithm,
      Missing_Identity_File,
      Unreadable_Identity_File,
      Malformed_Identity_File,
      Encrypted_Identity_File,
      Unsupported_Private_Key_Algorithm,
      Public_Private_Key_Mismatch,
      Legacy_Pem_Identity_File,
      Repository_Path_Lf,
      Repository_Path_Cr,
      Repository_Path_Nul,
      Empty_Repository_Path,
      Oversized_Repository_Path,
      Shell_Metacharacters_Quoted,
      Single_Quote_Escaped,
      Subprocess_Fallback_Disallowed,
      Invalid_Remote_Host,
      Invalid_Remote_Port,
      Invalid_Remote_User,
      Config_Proxy_Command,
      Config_Proxy_Jump,
      Config_Negated_Host_Pattern,
      Config_Wildcard_Unsupported,
      Config_IdentityFile_Not_Shell_Expanded,
      Config_Cannot_Disable_Verify_Known_Host,
      Config_Cannot_Disable_Strict_Host_Key,
      Config_HostName_Cannot_Alter_Repository_Path,
      Remote_User_Overrides_Config_User,
      Remote_Port_Overrides_Config_Port,
      Binary_Nul_Preserved,
      Binary_Cr_Lf_Preserved,
      Binary_High_Bytes_Preserved,
      Binary_Write_Exact,
      Git_Protocol_Text_Conversion_Disallowed,
      Queued_Data_Before_Eof,
      Stderr_Not_Returned_As_Stdout,
      Timeout_Identification,
      Timeout_Kex,
      Timeout_Auth,
      Timeout_Channel_Open,
      Timeout_Channel_Read,
      Timeout_Window_Write,
      Partial_Write_Socket_Failure,
      Partial_Write_Dirties_Channel,
      Dirty_Session_Cannot_Open_Channel,
      Dirty_Channel_Cannot_Write,
      Close_After_Dirty_State,
      Partial_Write_Timeout,
      Retry_After_Dirty_Write,
      Timeout_Does_Not_Reset_Per_Byte,
      Partial_Write_No_Ok,
      Failed_Open_Leaves_Session_Closed,
      Oversized_Local_File,
      Oversized_Config_Line,
      Oversized_Known_Hosts_Line,
      Oversized_Stderr_Buffer,
      Too_Many_Open_Channels,
      Maximum_Identities_Exceeded,
      Maximum_Command_Length_Exceeded,
      Max_Agent_Message_Bound,
      Max_Identity_File_Bound,
      Max_Known_Hosts_Line_Bound,
      Max_Config_Line_Bound,
      Max_Stdout_Pending_Bound,
      Max_Repo_Path_Bound,
      Socket_Exception,
      Packet_Parse_Exception,
      Crypto_Verification_Exception,
      Known_Hosts_Read_Exception,
      Config_Read_Exception,
      Identity_Read_Exception,
      Agent_Transport_Exception,
      Channel_Dispatch_Exception);

   --  Return the Status a given negative case is expected to produce.
   --  @param Case_Item the negative case to look up
   --  @return the reference Status the implementation must return for the case
   function Expected_Status
     (Case_Item : Negative_Case)
      return CryptoLib.Errors.Status;

   --  Return a human-readable label identifying a negative case.
   --  @param Case_Item the negative case to name
   --  @return the display label for the case
   function Case_Label (Case_Item : Negative_Case) return String;

   --  Return the category that groups a given negative case.
   --  @param Case_Item the negative case to classify
   --  @return the Negative_Category the case belongs to
   function Case_Category
     (Case_Item : Negative_Case)
      return Negative_Category;

   --  Return a human-readable label identifying a negative category.
   --  @param Category_Item the category to name
   --  @return the display label for the category
   function Category_Label
     (Category_Item : Negative_Category)
      return String;

   --  Return the security invariant that a given negative case exercises.
   --  @param Case_Item the negative case to map
   --  @return the Negative_Invariant asserted by the case
   function Case_Invariant
     (Case_Item : Negative_Case)
      return Negative_Invariant;

   --  Return a human-readable label identifying a negative invariant.
   --  @param Invariant_Item the invariant to name
   --  @return the display label for the invariant
   function Invariant_Label
     (Invariant_Item : Negative_Invariant)
      return String;

   --  Return True when the case asserts that valid data is preserved verbatim
   --  (rather than that a hostile input is rejected).
   --  @param Case_Item the negative case to test
   --  @return True for a preservation case, False for a hostile-rejection case
   function Is_Preservation_Case
     (Case_Item : Negative_Case)
      return Boolean;

   --  Return True when the case asserts that a hostile input is rejected
   --  (the complement of Is_Preservation_Case).
   --  @param Case_Item the negative case to test
   --  @return True for a hostile-rejection case, False for a preservation case
   function Is_Hostile_Case
     (Case_Item : Negative_Case)
      return Boolean;

   --  Return the fixed six-byte edge-case set (00, 0A, 0D, 7F, 80, FF) used to
   --  exercise binary/byte-preservation cases.
   --  @return the six-element boundary byte array
   function Byte_Set return Ada.Streams.Stream_Element_Array;
end SSH_Lib.Protocol.Negative_Tests;
