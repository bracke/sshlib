with Ada.Text_IO;
with CryptoLib.Errors;
with SSH_Lib.Security_Audit;

procedure Test_Status_Mapping_Matrix is
   use type CryptoLib.Errors.Status;
begin
   for Case_Item in SSH_Lib.Security_Audit.Status_Matrix_Case loop
      if SSH_Lib.Security_Audit.Status_Matrix_Label (Case_Item)'Length = 0 then
         Ada.Text_IO.Put_Line ("FAILED empty status matrix label");
         raise Program_Error;
      end if;

      if SSH_Lib.Security_Audit.Failure_Status_For
           (SSH_Lib.Security_Audit.Status_Matrix_Label (Case_Item)) /=
         SSH_Lib.Security_Audit.Status_Matrix_Status (Case_Item)
      then
         Ada.Text_IO.Put_Line
           ("FAILED status matrix mapping: "
            & SSH_Lib.Security_Audit.Status_Matrix_Label (Case_Item));
         raise Program_Error;
      end if;
   end loop;

   Ada.Text_IO.Put_Line ("test_status_mapping_matrix passed");
end Test_Status_Mapping_Matrix;
