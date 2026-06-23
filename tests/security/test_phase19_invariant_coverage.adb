with Ada.Text_IO;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Negative_Tests;

procedure Test_Phase19_Invariant_Coverage is
   use type CryptoLib.Errors.Status;
   use type SSH_Lib.Protocol.Negative_Tests.Negative_Invariant;

   function Is_Failure (Value : CryptoLib.Errors.Status) return Boolean is
   begin
      case Value is
         when CryptoLib.Errors.Ok | CryptoLib.Errors.End_Of_Stream =>
            return False;
         when others =>
            return True;
      end case;
   end Is_Failure;

   procedure Check (Condition : Boolean; Message_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Message_Text);
         raise Program_Error;
      end if;
   end Check;
begin
   for Invariant_Item in SSH_Lib.Protocol.Negative_Tests.Negative_Invariant loop
      declare
         Covered : Boolean := False;
      begin
         Check
           (SSH_Lib.Protocol.Negative_Tests.Invariant_Label (Invariant_Item)'Length > 0,
            "empty invariant label");

         for Case_Item in SSH_Lib.Protocol.Negative_Tests.Negative_Case loop
            if SSH_Lib.Protocol.Negative_Tests.Case_Invariant (Case_Item) =
              Invariant_Item
            then
               Covered := True;
            end if;
         end loop;

         Check
           (Covered,
            "uncovered security invariant: "
            & SSH_Lib.Protocol.Negative_Tests.Invariant_Label (Invariant_Item));
      end;
   end loop;

   for Case_Item in SSH_Lib.Protocol.Negative_Tests.Negative_Case loop
      declare
         Expected : constant CryptoLib.Errors.Status :=
           SSH_Lib.Protocol.Negative_Tests.Expected_Status (Case_Item);
      begin
         Check
           (SSH_Lib.Protocol.Negative_Tests.Invariant_Label
              (SSH_Lib.Protocol.Negative_Tests.Case_Invariant (Case_Item))'Length > 0,
            "case has a stable invariant mapping");

         if SSH_Lib.Protocol.Negative_Tests.Is_Hostile_Case (Case_Item) then
            Check
              (not SSH_Lib.Protocol.Negative_Tests.Is_Preservation_Case (Case_Item),
               "hostile/preservation classifiers are mutually exclusive");
            Check
              (Is_Failure (Expected),
               "hostile case must map to deterministic failure: "
               & SSH_Lib.Protocol.Negative_Tests.Case_Label (Case_Item));
         else
            Check
              (SSH_Lib.Protocol.Negative_Tests.Is_Preservation_Case (Case_Item),
               "non-hostile case must be preservation case");
            Check
              (Expected = CryptoLib.Errors.Ok,
               "preservation case must map to Ok: "
               & SSH_Lib.Protocol.Negative_Tests.Case_Label (Case_Item));
         end if;
      end;
   end loop;

   Ada.Text_IO.Put_Line ("test_phase19_invariant_coverage passed");
end Test_Phase19_Invariant_Coverage;
