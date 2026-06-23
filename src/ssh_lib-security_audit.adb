with Ada.Characters.Handling;
with Ada.Strings.Fixed;

package body SSH_Lib.Security_Audit is
   function Default_Host_Key_Verification return Boolean is
   begin
      return True;
   end Default_Host_Key_Verification;

   function Default_Strict_Host_Key return Boolean is
   begin
      return True;
   end Default_Strict_Host_Key;

   function Default_Use_Agent return Boolean is
   begin
      return True;
   end Default_Use_Agent;

   function Area_Label (Area_Item : Review_Area) return String is
   begin
      case Area_Item is
         when Host_Key_Verification =>
            return "host-key-verification";
         when Algorithm_Negotiation =>
            return "algorithm-negotiation";
         when Packet_Protection =>
            return "packet-protection";
         when Authentication_Order =>
            return "authentication-order";
         when Git_Command_Quoting =>
            return "git-command-quoting";
         when Remote_Config_Parsing =>
            return "remote-config-parsing";
         when Binary_Stream_Safety =>
            return "binary-stream-safety";
         when Timeout_Dirty_State =>
            return "timeout-dirty-state";
         when Resource_Bounds =>
            return "resource-bounds";
         when Exception_Containment =>
            return "exception-containment";
      end case;
   end Area_Label;

   function Required_Status
     (Area_Item : Review_Area)
      return CryptoLib.Errors.Status
   is
   begin
      case Area_Item is
         when Host_Key_Verification =>
            return CryptoLib.Errors.Host_Key_Unknown;
         when Algorithm_Negotiation =>
            return CryptoLib.Errors.Unsupported_Feature;
         when Packet_Protection =>
            return CryptoLib.Errors.Handshake_Failed;
         when Authentication_Order =>
            return CryptoLib.Errors.Authentication_Failed;
         when Git_Command_Quoting =>
            return CryptoLib.Errors.Invalid_Command;
         when Remote_Config_Parsing =>
            return CryptoLib.Errors.Invalid_Host;
         when Binary_Stream_Safety =>
            return CryptoLib.Errors.Ok;
         when Timeout_Dirty_State =>
            return CryptoLib.Errors.Timeout;
         when Resource_Bounds =>
            return CryptoLib.Errors.Unsupported_Feature;
         when Exception_Containment =>
            return CryptoLib.Errors.Internal_Error;
      end case;
   end Required_Status;

   function Is_Security_Failure_Status
     (Value : CryptoLib.Errors.Status)
      return Boolean
   is
   begin
      case Value is
         when CryptoLib.Errors.Invalid_Host
            | CryptoLib.Errors.Invalid_Port
            | CryptoLib.Errors.Invalid_User
            | CryptoLib.Errors.Invalid_Command
            | CryptoLib.Errors.DNS_Failed
            | CryptoLib.Errors.Connection_Failed
            | CryptoLib.Errors.Timeout
            | CryptoLib.Errors.Handshake_Failed
            | CryptoLib.Errors.Host_Key_Unknown
            | CryptoLib.Errors.Host_Key_Mismatch
            | CryptoLib.Errors.Authentication_Failed
            | CryptoLib.Errors.Channel_Open_Failed
            | CryptoLib.Errors.Channel_Request_Failed
            | CryptoLib.Errors.Read_Failed
            | CryptoLib.Errors.Write_Failed
            | CryptoLib.Errors.No_Such_File
            | CryptoLib.Errors.Permission_Denied
            | CryptoLib.Errors.Remote_Failure
            | CryptoLib.Errors.Remote_Exit_Nonzero
            | CryptoLib.Errors.Cancelled
            | CryptoLib.Errors.Unsupported_Feature
            | CryptoLib.Errors.Internal_Error =>
            return True;
         when CryptoLib.Errors.Ok | CryptoLib.Errors.End_Of_Stream =>
            return False;
      end case;
   end Is_Security_Failure_Status;

   function Status_Matrix_Label
     (Case_Item : Status_Matrix_Case)
      return String
   is
   begin
      case Case_Item is
         when Invalid_Remote_Host_Case =>
            return "invalid remote host";
         when Invalid_Remote_Port_Case =>
            return "invalid remote port";
         when Missing_Resolved_User_Case =>
            return "missing resolved user";
         when Unsafe_Repository_Command_Case =>
            return "unsafe repository command";
         when DNS_Failure_Case =>
            return "dns failure";
         when Connection_Refused_Case =>
            return "connection refused";
         when Operation_Timeout_Case =>
            return "operation timeout";
         when Malformed_Identification_Case =>
            return "malformed identification";
         when Unsupported_Algorithm_Set_Case =>
            return "unsupported algorithm set";
         when Invalid_Host_Key_Signature_Case =>
            return "invalid host-key signature";
         when Unknown_Host_Key_Case =>
            return "unknown host key";
         when Changed_Host_Key_Case =>
            return "changed host key";
         when Auth_Rejected_Case =>
            return "auth rejected";
         when Channel_Open_Rejected_Case =>
            return "channel open rejected";
         when Exec_Rejected_Case =>
            return "exec rejected";
         when Malformed_Channel_Data_Case =>
            return "malformed channel data";
         when Ambiguous_Partial_Write_Case =>
            return "ambiguous partial write";
         when Remote_Exit_Status_Nonzero_Case =>
            return "remote exit status nonzero";
         when Cancelled_Operation_Case =>
            return "cancelled operation";
         when Unexpected_Internal_Invariant_Case =>
            return "unexpected internal invariant";
      end case;
   end Status_Matrix_Label;

   function Status_Matrix_Status
     (Case_Item : Status_Matrix_Case)
      return CryptoLib.Errors.Status
   is
   begin
      case Case_Item is
         when Invalid_Remote_Host_Case =>
            return CryptoLib.Errors.Invalid_Host;
         when Invalid_Remote_Port_Case =>
            return CryptoLib.Errors.Invalid_Port;
         when Missing_Resolved_User_Case =>
            return CryptoLib.Errors.Invalid_User;
         when Unsafe_Repository_Command_Case =>
            return CryptoLib.Errors.Invalid_Command;
         when DNS_Failure_Case =>
            return CryptoLib.Errors.DNS_Failed;
         when Connection_Refused_Case =>
            return CryptoLib.Errors.Connection_Failed;
         when Operation_Timeout_Case =>
            return CryptoLib.Errors.Timeout;
         when Malformed_Identification_Case =>
            return CryptoLib.Errors.Handshake_Failed;
         when Unsupported_Algorithm_Set_Case =>
            return CryptoLib.Errors.Unsupported_Feature;
         when Invalid_Host_Key_Signature_Case =>
            return CryptoLib.Errors.Handshake_Failed;
         when Unknown_Host_Key_Case =>
            return CryptoLib.Errors.Host_Key_Unknown;
         when Changed_Host_Key_Case =>
            return CryptoLib.Errors.Host_Key_Mismatch;
         when Auth_Rejected_Case =>
            return CryptoLib.Errors.Authentication_Failed;
         when Channel_Open_Rejected_Case =>
            return CryptoLib.Errors.Channel_Open_Failed;
         when Exec_Rejected_Case =>
            return CryptoLib.Errors.Channel_Request_Failed;
         when Malformed_Channel_Data_Case =>
            return CryptoLib.Errors.Read_Failed;
         when Ambiguous_Partial_Write_Case =>
            return CryptoLib.Errors.Write_Failed;
         when Remote_Exit_Status_Nonzero_Case =>
            return CryptoLib.Errors.Remote_Exit_Nonzero;
         when Cancelled_Operation_Case =>
            return CryptoLib.Errors.Cancelled;
         when Unexpected_Internal_Invariant_Case =>
            return CryptoLib.Errors.Internal_Error;
      end case;
   end Status_Matrix_Status;

   function Failure_Status_For
     (Case_Label : String)
      return CryptoLib.Errors.Status
   is
      Lower_Label : constant String :=
        Ada.Characters.Handling.To_Lower (Case_Label);
   begin
      for Case_Item in Status_Matrix_Case loop
         if Ada.Strings.Fixed.Index
              (Lower_Label, Status_Matrix_Label (Case_Item)) /= 0
         then
            return Status_Matrix_Status (Case_Item);
         end if;
      end loop;

      if Ada.Strings.Fixed.Index (Lower_Label, "invalid remote host") /= 0 then
         return CryptoLib.Errors.Invalid_Host;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "invalid remote port") /= 0 then
         return CryptoLib.Errors.Invalid_Port;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "missing resolved user") /= 0 then
         return CryptoLib.Errors.Invalid_User;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "unsafe repository command") /= 0 then
         return CryptoLib.Errors.Invalid_Command;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "dns failure") /= 0 then
         return CryptoLib.Errors.DNS_Failed;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "connection refused") /= 0 then
         return CryptoLib.Errors.Connection_Failed;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "operation timeout") /= 0 then
         return CryptoLib.Errors.Timeout;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "malformed identification") /= 0 then
         return CryptoLib.Errors.Handshake_Failed;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "unsupported algorithm") /= 0 then
         return CryptoLib.Errors.Unsupported_Feature;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "invalid host-key signature") /= 0 then
         return CryptoLib.Errors.Handshake_Failed;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "unknown host key") /= 0 then
         return CryptoLib.Errors.Host_Key_Unknown;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "changed host key") /= 0 then
         return CryptoLib.Errors.Host_Key_Mismatch;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "auth rejected") /= 0 then
         return CryptoLib.Errors.Authentication_Failed;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "channel open rejected") /= 0 then
         return CryptoLib.Errors.Channel_Open_Failed;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "exec rejected") /= 0 then
         return CryptoLib.Errors.Channel_Request_Failed;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "malformed channel data") /= 0 then
         return CryptoLib.Errors.Read_Failed;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "ambiguous partial write") /= 0 then
         return CryptoLib.Errors.Write_Failed;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "remote exit status nonzero") /= 0 then
         return CryptoLib.Errors.Remote_Exit_Nonzero;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "cancelled operation") /= 0 then
         return CryptoLib.Errors.Cancelled;
      elsif Ada.Strings.Fixed.Index (Lower_Label, "unexpected internal invariant") /= 0 then
         return CryptoLib.Errors.Internal_Error;
      else
         return CryptoLib.Errors.Internal_Error;
      end if;
   end Failure_Status_For;
end SSH_Lib.Security_Audit;
