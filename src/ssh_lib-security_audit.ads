with CryptoLib.Errors;

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

   function Default_Host_Key_Verification return Boolean;

   function Default_Strict_Host_Key return Boolean;

   function Default_Use_Agent return Boolean;

   function Area_Label (Area_Item : Review_Area) return String;

   function Required_Status
     (Area_Item : Review_Area)
      return CryptoLib.Errors.Status;

   function Is_Security_Failure_Status
     (Value : CryptoLib.Errors.Status)
      return Boolean;

   function Status_Matrix_Label
     (Case_Item : Status_Matrix_Case)
      return String;

   function Status_Matrix_Status
     (Case_Item : Status_Matrix_Case)
      return CryptoLib.Errors.Status;

   function Failure_Status_For
     (Case_Label : String)
      return CryptoLib.Errors.Status;
end SSH_Lib.Security_Audit;
