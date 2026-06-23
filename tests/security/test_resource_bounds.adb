with Ada.Text_IO;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Negative_Tests;
with SSH_Lib.Tests.Fixtures.Resource_Bounds;

procedure Test_Resource_Bounds is
   use type CryptoLib.Errors.Status;
   type Case_Array is array (Positive range <>) of SSH_Lib.Protocol.Negative_Tests.Negative_Case;

   Cases : constant Case_Array :=
     [SSH_Lib.Protocol.Negative_Tests.Oversized_Packet,
      SSH_Lib.Protocol.Negative_Tests.Oversized_Local_File,
      SSH_Lib.Protocol.Negative_Tests.Oversized_Config_Line,
      SSH_Lib.Protocol.Negative_Tests.Oversized_Known_Hosts_Line,
      SSH_Lib.Protocol.Negative_Tests.Oversized_Stderr_Buffer,
      SSH_Lib.Protocol.Negative_Tests.Too_Many_Open_Channels,
      SSH_Lib.Protocol.Negative_Tests.Maximum_Identities_Exceeded,
      SSH_Lib.Protocol.Negative_Tests.Maximum_Command_Length_Exceeded,
      SSH_Lib.Protocol.Negative_Tests.Max_Agent_Message_Bound,
      SSH_Lib.Protocol.Negative_Tests.Max_Identity_File_Bound,
      SSH_Lib.Protocol.Negative_Tests.Max_Known_Hosts_Line_Bound,
      SSH_Lib.Protocol.Negative_Tests.Max_Config_Line_Bound,
      SSH_Lib.Protocol.Negative_Tests.Max_Stdout_Pending_Bound,
      SSH_Lib.Protocol.Negative_Tests.Max_Repo_Path_Bound];

   procedure Check_Case
     (Case_Item : SSH_Lib.Protocol.Negative_Tests.Negative_Case)
   is
      Actual : constant CryptoLib.Errors.Status :=
        SSH_Lib.Protocol.Negative_Tests.Expected_Status (Case_Item);
   begin
      if SSH_Lib.Protocol.Negative_Tests.Is_Preservation_Case (Case_Item) then
         if Actual /= CryptoLib.Errors.Ok then
            Ada.Text_IO.Put_Line
              ("FAILED preservation: "
               & SSH_Lib.Protocol.Negative_Tests.Case_Label (Case_Item));
            raise Program_Error;
         end if;
      elsif Actual = CryptoLib.Errors.Ok
        or else Actual = CryptoLib.Errors.End_Of_Stream
        or else Actual = CryptoLib.Errors.Cancelled
        or else Actual = CryptoLib.Errors.Remote_Exit_Nonzero
      then
         Ada.Text_IO.Put_Line
           ("FAILED failure mapping: "
            & SSH_Lib.Protocol.Negative_Tests.Case_Label (Case_Item));
         raise Program_Error;
      end if;
   end Check_Case;
begin
   for Case_Item of Cases loop
      Check_Case (Case_Item);
   end loop;
   SSH_Lib.Tests.Fixtures.Resource_Bounds.Assert_All_Production_Bounds_Reject_Oversized_Input;
   Ada.Text_IO.Put_Line ("test_resource_bounds passed");
end Test_Resource_Bounds;
