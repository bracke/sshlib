with CryptoLib.Errors;

--  @summary Runtime security self-audit checks (e.g. the no-subprocess
--  guarantee and related invariants) surfaced through Status results.
package SSH_Lib.Security_Audit is
   type Review_Area is
     (Host_Key_Verification,
      Algorithm_Negotiation,
      Packet_Protection,
      Authentication_Order,
      Git_Command_Quoting,
      Remote_Config_Parsing,
      Binary_Stream_Safety,
      Timeout_Dirty_State,
      Resource_Bounds,
      Exception_Containment);

   type Status_Matrix_Case is
     (Invalid_Remote_Host_Case,
      Invalid_Remote_Port_Case,
      Missing_Resolved_User_Case,
      Unsafe_Repository_Command_Case,
      DNS_Failure_Case,
      Connection_Refused_Case,
      Operation_Timeout_Case,
      Malformed_Identification_Case,
      Unsupported_Algorithm_Set_Case,
      Invalid_Host_Key_Signature_Case,
      Unknown_Host_Key_Case,
      Changed_Host_Key_Case,
      Auth_Rejected_Case,
      Channel_Open_Rejected_Case,
      Exec_Rejected_Case,
      Malformed_Channel_Data_Case,
      Ambiguous_Partial_Write_Case,
      Remote_Exit_Status_Nonzero_Case,
      Cancelled_Operation_Case,
      Unexpected_Internal_Invariant_Case);

   type Review_Result is
     (Satisfied,
      Needs_Test_Coverage,
      Unsafe);

   --  Report the secure default for host-key verification.
   --  @return True, since host-key verification is on by default
   function Default_Host_Key_Verification return Boolean;

   --  Report the secure default for strict host-key checking.
   --  @return True, since strict host-key checking is on by default
   function Default_Strict_Host_Key return Boolean;

   --  Report the secure default for using the ssh-agent.
   --  @return True, since agent use is on by default
   function Default_Use_Agent return Boolean;

   --  Return the stable machine-readable label for a review area.
   --  @param Area_Item the review area to label
   --  @return the hyphenated area label (e.g. "host-key-verification")
   function Area_Label (Area_Item : Review_Area) return String;

   --  Return the error status a review area must be able to produce on failure.
   --  @param Area_Item the review area to query
   --  @return the required failure status for that area
   function Required_Status
     (Area_Item : Review_Area)
      return CryptoLib.Errors.Status;

   --  Report whether a status counts as a security-relevant failure.
   --  @param Value the status to classify
   --  @return True for every failure status, False for Ok/End_Of_Stream
   function Is_Security_Failure_Status
     (Value : CryptoLib.Errors.Status)
      return Boolean;

   --  Return the human-readable label for a status-matrix case.
   --  @param Case_Item the status-matrix case to label
   --  @return the descriptive case label (e.g. "unknown host key")
   function Status_Matrix_Label
     (Case_Item : Status_Matrix_Case)
      return String;

   --  Return the error status expected for a status-matrix case.
   --  @param Case_Item the status-matrix case to query
   --  @return the status that case must map to
   function Status_Matrix_Status
     (Case_Item : Status_Matrix_Case)
      return CryptoLib.Errors.Status;

   --  Map a free-text case label to its expected failure status.
   --  @param Case_Label the case label text to match (case-insensitive substring)
   --  @return the matched failure status, or Internal_Error if none matches
   function Failure_Status_For
     (Case_Label : String)
      return CryptoLib.Errors.Status;
end SSH_Lib.Security_Audit;
