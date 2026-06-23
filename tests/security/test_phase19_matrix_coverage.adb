with Ada.Text_IO;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Negative_Tests;

procedure Test_Phase19_Matrix_Coverage is
   use type CryptoLib.Errors.Status;
   use type SSH_Lib.Protocol.Negative_Tests.Negative_Category;

   function Is_Failure (Value : CryptoLib.Errors.Status) return Boolean is
   begin
      case Value is
         when CryptoLib.Errors.Ok | CryptoLib.Errors.End_Of_Stream =>
            return False;
         when others =>
            return True;
      end case;
   end Is_Failure;
begin
   for Category_Item in SSH_Lib.Protocol.Negative_Tests.Negative_Category loop
      declare
         Covered : Boolean := False;
      begin
         for Case_Item in SSH_Lib.Protocol.Negative_Tests.Negative_Case loop
            if SSH_Lib.Protocol.Negative_Tests.Case_Category (Case_Item) = Category_Item then
               Covered := True;
            end if;
         end loop;

         if not Covered then
            Ada.Text_IO.Put_Line
              ("FAILED empty category: "
               & SSH_Lib.Protocol.Negative_Tests.Category_Label (Category_Item));
            raise Program_Error;
         end if;
      end;
   end loop;

   for Case_Item in SSH_Lib.Protocol.Negative_Tests.Negative_Case loop
      declare
         Expected : constant CryptoLib.Errors.Status :=
           SSH_Lib.Protocol.Negative_Tests.Expected_Status (Case_Item);
      begin
         if SSH_Lib.Protocol.Negative_Tests.Case_Label (Case_Item)'Length = 0 then
            Ada.Text_IO.Put_Line ("FAILED empty case label");
            raise Program_Error;
         end if;

         if SSH_Lib.Protocol.Negative_Tests.Category_Label
              (SSH_Lib.Protocol.Negative_Tests.Case_Category (Case_Item))'Length = 0
         then
            Ada.Text_IO.Put_Line
              ("FAILED empty category label for "
               & SSH_Lib.Protocol.Negative_Tests.Case_Label (Case_Item));
            raise Program_Error;
         end if;

         if SSH_Lib.Protocol.Negative_Tests.Is_Preservation_Case (Case_Item) then
            if Expected /= CryptoLib.Errors.Ok then
               Ada.Text_IO.Put_Line
                 ("FAILED preservation status: "
                  & SSH_Lib.Protocol.Negative_Tests.Case_Label (Case_Item));
               raise Program_Error;
            end if;
         elsif not Is_Failure (Expected) then
            Ada.Text_IO.Put_Line
              ("FAILED hostile case status: "
               & SSH_Lib.Protocol.Negative_Tests.Case_Label (Case_Item));
            raise Program_Error;
         end if;
      end;
   end loop;

   Ada.Text_IO.Put_Line ("test_phase19_matrix_coverage passed");
end Test_Phase19_Matrix_Coverage;
