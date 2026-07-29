package body SSH_Lib.Protocol.Negative_Tests is
   function Expected_Status
     (Case_Item : Negative_Case)
      return CryptoLib.Errors.Status
   is
   begin
      case Case_Item is
         when Host_Absent_From_Known_Hosts
            | Hashed_Known_Hosts_Entry
            | Wildcard_Known_Hosts_Entry
            | Nonstandard_Port_Not_Trusted_By_Bare_Host
            | Host_Port_Mismatch =>
            return CryptoLib.Errors.Host_Key_Unknown;
         when Host_Key_Mismatch =>
            return CryptoLib.Errors.Host_Key_Mismatch;
         when Host_Key_Verification_Disabled_Bypass =>
            return CryptoLib.Errors.Ok;
         when Invalid_Host_Key_Signature
            | Known_Hosts_Check_After_Invalid_Signature
            | Unexpected_Algorithm
            | Inconsistent_Kex_Reply
            | Legacy_Ssh_Rsa_Sha1
            | Bad_Mac
            | Wrong_Sequence_Mac
            | Truncated_Encrypted_Packet
            | Oversized_Packet
            | Invalid_Padding_Length
            | Packet_After_Dirty_State
            | Service_Request_Before_Encryption
            | Service_Accept_Before_Encryption
            | Malformed_Known_Hosts_Line
            | Unsupported_Known_Host_Key_Type
            | Packet_Parse_Exception
            | Crypto_Verification_Exception
            | Unsupported_Selected_Algorithm
            | Sequence_Number_Not_Incremented_Once
            | Packet_Length_Before_Allocation
            | Padding_Length_Exceeds_Packet
            | Mac_Failure_Dirties_Session
            | Cipher_Not_Active_Before_Userauth
            | Session_Id_Not_First_Exchange_Hash =>
            return CryptoLib.Errors.Handshake_Failed;
         when No_Supported_Kex
            | No_Supported_Host_Key
            | No_Supported_Cipher
            | No_Supported_Mac
            | Compression_Not_None
            | Encrypted_Identity_File
            | Unsupported_Private_Key_Algorithm
            | Legacy_Pem_Identity_File
            | Oversized_Local_File
            | Maximum_Identities_Exceeded
            | Weak_Algorithm_Offered
            | Max_Agent_Message_Bound
            | Max_Identity_File_Bound
            | Max_Known_Hosts_Line_Bound
            | Max_Config_Line_Bound
            | Max_Stdout_Pending_Bound
            | Max_Repo_Path_Bound =>
            return CryptoLib.Errors.Unsupported_Feature;
         when Userauth_Before_Host_Trust =>
            return CryptoLib.Errors.Host_Key_Unknown;
         when Userauth_Partial_Success
            | Agent_Signature_Wrong_Payload
            | Identity_Signature_Wrong_Payload
            | Missing_Agent
            | Agent_Connection_Failure
            | Oversized_Agent_Response
            | Malformed_Agent_Identity_List
            | Malformed_Agent_Response
            | Wrong_Agent_Signature_Algorithm
            | Missing_Identity_File
            | Unreadable_Identity_File
            | Malformed_Identity_File
            | Public_Private_Key_Mismatch
            | Agent_Transport_Exception =>
            return CryptoLib.Errors.Authentication_Failed;
         when Userauth_Banner =>
            return CryptoLib.Errors.Ok;
         when Repository_Path_Lf
            | Repository_Path_Cr
            | Repository_Path_Nul
            | Empty_Repository_Path
            | Oversized_Repository_Path
            | Maximum_Command_Length_Exceeded =>
            return CryptoLib.Errors.Invalid_Command;
         when Shell_Metacharacters_Quoted
            | Single_Quote_Escaped =>
            return CryptoLib.Errors.Ok;
         when Subprocess_Fallback_Disallowed =>
            return CryptoLib.Errors.Unsupported_Feature;
         when Invalid_Remote_Host
            | Config_Negated_Host_Pattern
            | Config_Wildcard_Unsupported =>
            return CryptoLib.Errors.Invalid_Host;
         when Invalid_Remote_Port =>
            return CryptoLib.Errors.Invalid_Port;
         when Invalid_Remote_User =>
            return CryptoLib.Errors.Invalid_User;
         when Config_Proxy_Command =>
            return CryptoLib.Errors.Unsupported_Feature;
         when Config_Proxy_Jump =>
            return CryptoLib.Errors.Ok;
         when Config_IdentityFile_Not_Shell_Expanded
            | Config_Cannot_Disable_Verify_Known_Host
            | Config_Cannot_Disable_Strict_Host_Key
            | Config_HostName_Cannot_Alter_Repository_Path
            | Remote_User_Overrides_Config_User
            | Remote_Port_Overrides_Config_Port =>
            return CryptoLib.Errors.Ok;
         when Binary_Nul_Preserved
            | Binary_Cr_Lf_Preserved
            | Binary_High_Bytes_Preserved
            | Binary_Write_Exact
            | Git_Protocol_Text_Conversion_Disallowed
            | Queued_Data_Before_Eof
            | Stderr_Not_Returned_As_Stdout =>
            return CryptoLib.Errors.Ok;
         when Timeout_Identification
            | Timeout_Kex
            | Timeout_Auth
            | Timeout_Channel_Open
            | Timeout_Channel_Read
            | Timeout_Window_Write
            | Partial_Write_Timeout
            | Timeout_Does_Not_Reset_Per_Byte =>
            return CryptoLib.Errors.Timeout;
         when Partial_Write_Socket_Failure
            | Partial_Write_Dirties_Channel
            | Dirty_Channel_Cannot_Write
            | Retry_After_Dirty_Write
            | Partial_Write_No_Ok =>
            return CryptoLib.Errors.Write_Failed;
         when Dirty_Session_Cannot_Open_Channel =>
            return CryptoLib.Errors.Channel_Open_Failed;
         when Close_After_Dirty_State
            | Failed_Open_Leaves_Session_Closed
            | Weak_Algorithm_Not_Selected =>
            return CryptoLib.Errors.Ok;
         when Oversized_Config_Line
            | Oversized_Known_Hosts_Line =>
            return CryptoLib.Errors.Unsupported_Feature;
         when Oversized_Stderr_Buffer =>
            return CryptoLib.Errors.Ok;
         when Too_Many_Open_Channels =>
            return CryptoLib.Errors.Channel_Open_Failed;
         when Socket_Exception
            | Known_Hosts_Read_Exception
            | Config_Read_Exception
            | Identity_Read_Exception
            | Channel_Dispatch_Exception =>
            return CryptoLib.Errors.Internal_Error;
      end case;
   end Expected_Status;

   function Case_Label (Case_Item : Negative_Case) return String is
      Image_Text : constant String := Negative_Case'Image (Case_Item);
      Result     : String (Image_Text'Range);
   begin
      for Index_Value in Image_Text'Range loop
         if Image_Text (Index_Value) = '_' then
            Result (Index_Value) := '-';
         elsif Image_Text (Index_Value) in 'A' .. 'Z' then
            Result (Index_Value) := Character'Val
              (Character'Pos (Image_Text (Index_Value))
               - Character'Pos ('A') + Character'Pos ('a'));
         else
            Result (Index_Value) := Image_Text (Index_Value);
         end if;
      end loop;
      return Result;
   end Case_Label;

   function Category_Label
     (Category_Item : Negative_Category)
      return String
   is
      Image_Text : constant String := Negative_Category'Image (Category_Item);
      Result     : String (Image_Text'Range);
   begin
      for Index_Value in Image_Text'Range loop
         if Image_Text (Index_Value) = '_' then
            Result (Index_Value) := '-';
         elsif Image_Text (Index_Value) in 'A' .. 'Z' then
            Result (Index_Value) := Character'Val
              (Character'Pos (Image_Text (Index_Value))
               - Character'Pos ('A') + Character'Pos ('a'));
         else
            Result (Index_Value) := Image_Text (Index_Value);
         end if;
      end loop;
      return Result;
   end Category_Label;

   function Invariant_Label
     (Invariant_Item : Negative_Invariant)
      return String
   is
      Image_Text : constant String := Negative_Invariant'Image (Invariant_Item);
      Result     : String (Image_Text'Range);
   begin
      for Index_Value in Image_Text'Range loop
         if Image_Text (Index_Value) = '_' then
            Result (Index_Value) := '-';
         elsif Image_Text (Index_Value) in 'A' .. 'Z' then
            Result (Index_Value) := Character'Val
              (Character'Pos (Image_Text (Index_Value))
               - Character'Pos ('A') + Character'Pos ('a'));
         else
            Result (Index_Value) := Image_Text (Index_Value);
         end if;
      end loop;
      return Result;
   end Invariant_Label;

   function Case_Invariant
     (Case_Item : Negative_Case)
      return Negative_Invariant
   is
   begin
      case Case_Category (Case_Item) is
         when Host_Key_Category =>
            return Rejects_Untrusted_Server_Identity;
         when Algorithm_Category =>
            return Rejects_Unsupported_Algorithms;
         when Packet_Protection_Category =>
            return Requires_Encrypted_Packet_Protection;
         when Authentication_Category =>
            return Requires_Authenticated_Ordering;
         when Command_Quoting_Category =>
            return Preserves_Shell_Safe_Remote_Command;
         when Remote_Config_Category =>
            return Parses_Config_As_Data_Only;
         when Binary_Stream_Category =>
            return Preserves_Opaque_Binary_Bytes;
         when Timeout_Dirty_Category =>
            return Enforces_Timeout_And_Dirty_State;
         when Resource_Bound_Category =>
            return Enforces_Resource_Bounds;
         when Exception_Mapping_Category =>
            return Contains_Ordinary_Exceptions;
      end case;
   end Case_Invariant;

   function Case_Category
     (Case_Item : Negative_Case)
      return Negative_Category
   is
   begin
      case Case_Item is
         when Host_Absent_From_Known_Hosts
            | Host_Key_Mismatch
            | Invalid_Host_Key_Signature
            | Unsupported_Known_Host_Key_Type
            | Malformed_Known_Hosts_Line
            | Hashed_Known_Hosts_Entry
            | Wildcard_Known_Hosts_Entry
            | Nonstandard_Port_Not_Trusted_By_Bare_Host
            | Host_Port_Mismatch
            | Known_Hosts_Check_After_Invalid_Signature
            | Host_Key_Verification_Disabled_Bypass =>
            return Host_Key_Category;
         when No_Supported_Kex
            | No_Supported_Host_Key
            | No_Supported_Cipher
            | No_Supported_Mac
            | Compression_Not_None
            | Unexpected_Algorithm
            | Inconsistent_Kex_Reply
            | Legacy_Ssh_Rsa_Sha1
            | Weak_Algorithm_Offered
            | Weak_Algorithm_Not_Selected
            | Unsupported_Selected_Algorithm =>
            return Algorithm_Category;
         when Bad_Mac
            | Wrong_Sequence_Mac
            | Truncated_Encrypted_Packet
            | Oversized_Packet
            | Invalid_Padding_Length
            | Packet_After_Dirty_State
            | Sequence_Number_Not_Incremented_Once
            | Packet_Length_Before_Allocation
            | Padding_Length_Exceeds_Packet
            | Mac_Failure_Dirties_Session =>
            return Packet_Protection_Category;
         when Service_Request_Before_Encryption
            | Service_Accept_Before_Encryption
            | Userauth_Before_Host_Trust
            | Userauth_Partial_Success
            | Userauth_Banner
            | Cipher_Not_Active_Before_Userauth
            | Agent_Signature_Wrong_Payload
            | Identity_Signature_Wrong_Payload
            | Session_Id_Not_First_Exchange_Hash
            | Missing_Agent
            | Agent_Connection_Failure
            | Oversized_Agent_Response
            | Malformed_Agent_Identity_List
            | Malformed_Agent_Response
            | Wrong_Agent_Signature_Algorithm
            | Missing_Identity_File
            | Unreadable_Identity_File
            | Malformed_Identity_File
            | Encrypted_Identity_File
            | Unsupported_Private_Key_Algorithm
            | Public_Private_Key_Mismatch
            | Legacy_Pem_Identity_File =>
            return Authentication_Category;
         when Repository_Path_Lf
            | Repository_Path_Cr
            | Repository_Path_Nul
            | Empty_Repository_Path
            | Oversized_Repository_Path
            | Shell_Metacharacters_Quoted
            | Single_Quote_Escaped
            | Subprocess_Fallback_Disallowed =>
            return Command_Quoting_Category;
         when Invalid_Remote_Host
            | Invalid_Remote_Port
            | Invalid_Remote_User
            | Config_Proxy_Command
            | Config_Proxy_Jump
            | Config_Negated_Host_Pattern
            | Config_Wildcard_Unsupported
            | Config_IdentityFile_Not_Shell_Expanded
            | Config_Cannot_Disable_Verify_Known_Host
            | Config_Cannot_Disable_Strict_Host_Key
            | Config_HostName_Cannot_Alter_Repository_Path
            | Remote_User_Overrides_Config_User
            | Remote_Port_Overrides_Config_Port =>
            return Remote_Config_Category;
         when Binary_Nul_Preserved
            | Binary_Cr_Lf_Preserved
            | Binary_High_Bytes_Preserved
            | Binary_Write_Exact
            | Git_Protocol_Text_Conversion_Disallowed
            | Queued_Data_Before_Eof
            | Stderr_Not_Returned_As_Stdout =>
            return Binary_Stream_Category;
         when Timeout_Identification
            | Timeout_Kex
            | Timeout_Auth
            | Timeout_Channel_Open
            | Timeout_Channel_Read
            | Timeout_Window_Write
            | Partial_Write_Socket_Failure
            | Partial_Write_Dirties_Channel
            | Dirty_Session_Cannot_Open_Channel
            | Dirty_Channel_Cannot_Write
            | Close_After_Dirty_State
            | Partial_Write_Timeout
            | Retry_After_Dirty_Write
            | Timeout_Does_Not_Reset_Per_Byte
            | Partial_Write_No_Ok
            | Failed_Open_Leaves_Session_Closed =>
            return Timeout_Dirty_Category;
         when Oversized_Local_File
            | Oversized_Config_Line
            | Oversized_Known_Hosts_Line
            | Oversized_Stderr_Buffer
            | Too_Many_Open_Channels
            | Maximum_Identities_Exceeded
            | Maximum_Command_Length_Exceeded
            | Max_Agent_Message_Bound
            | Max_Identity_File_Bound
            | Max_Known_Hosts_Line_Bound
            | Max_Config_Line_Bound
            | Max_Stdout_Pending_Bound
            | Max_Repo_Path_Bound =>
            return Resource_Bound_Category;
         when Socket_Exception
            | Packet_Parse_Exception
            | Crypto_Verification_Exception
            | Known_Hosts_Read_Exception
            | Config_Read_Exception
            | Identity_Read_Exception
            | Agent_Transport_Exception
            | Channel_Dispatch_Exception =>
            return Exception_Mapping_Category;
      end case;
   end Case_Category;

   function Is_Preservation_Case
     (Case_Item : Negative_Case)
      return Boolean
   is
   begin
      case Case_Item is
         when Host_Key_Verification_Disabled_Bypass
            | Userauth_Banner
            | Weak_Algorithm_Not_Selected
            | Config_Proxy_Jump
            | Shell_Metacharacters_Quoted
            | Single_Quote_Escaped
            | Config_IdentityFile_Not_Shell_Expanded
            | Config_Cannot_Disable_Verify_Known_Host
            | Config_Cannot_Disable_Strict_Host_Key
            | Config_HostName_Cannot_Alter_Repository_Path
            | Remote_User_Overrides_Config_User
            | Remote_Port_Overrides_Config_Port
            | Binary_Nul_Preserved
            | Binary_Cr_Lf_Preserved
            | Binary_High_Bytes_Preserved
            | Binary_Write_Exact
            | Git_Protocol_Text_Conversion_Disallowed
            | Queued_Data_Before_Eof
            | Stderr_Not_Returned_As_Stdout
            | Close_After_Dirty_State
            | Failed_Open_Leaves_Session_Closed
            | Oversized_Stderr_Buffer =>
            return True;
         when others =>
            return False;
      end case;
   end Is_Preservation_Case;

   function Is_Hostile_Case
     (Case_Item : Negative_Case)
      return Boolean
   is
   begin
      return not Is_Preservation_Case (Case_Item);
   end Is_Hostile_Case;

   function Byte_Set return Ada.Streams.Stream_Element_Array is
      Data : constant Ada.Streams.Stream_Element_Array
        (Ada.Streams.Stream_Element_Offset'(1) ..
         Ada.Streams.Stream_Element_Offset'(6)) :=
        [Ada.Streams.Stream_Element_Offset'(1) => 16#00#,
         Ada.Streams.Stream_Element_Offset'(2) => 16#0A#,
         Ada.Streams.Stream_Element_Offset'(3) => 16#0D#,
         Ada.Streams.Stream_Element_Offset'(4) => 16#7F#,
         Ada.Streams.Stream_Element_Offset'(5) => 16#80#,
         Ada.Streams.Stream_Element_Offset'(6) => 16#FF#];
   begin
      return Data;
   end Byte_Set;
end SSH_Lib.Protocol.Negative_Tests;
