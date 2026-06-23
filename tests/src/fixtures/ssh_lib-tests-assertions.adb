with Ada.Text_IO;
with SSH_Lib.Tests.Fixtures.Binary_Data;

package body SSH_Lib.Tests.Assertions is
   use type CryptoLib.Errors.Status;

   procedure Assert (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Assert;

   procedure Check (Condition : Boolean; Label_Text : String) renames Assert;

   procedure Check_Status
     (Actual_Status   : CryptoLib.Errors.Status;
      Expected_Status : CryptoLib.Errors.Status;
      Operation       : String;
      Scenario        : String := "") is
   begin
      if Actual_Status /= Expected_Status then
         Ada.Text_IO.Put_Line
           ("FAILED: " & Operation & " scenario=" & Scenario &
            " expected=" & CryptoLib.Errors.Status'Image (Expected_Status) &
            " actual=" & CryptoLib.Errors.Status'Image (Actual_Status));
         raise Program_Error;
      end if;
   end Check_Status;

   procedure Check_Bytes
     (Actual_Data   : Ada.Streams.Stream_Element_Array;
      Expected_Data : Ada.Streams.Stream_Element_Array;
      Operation     : String;
      Scenario      : String := "") is
   begin
      if not SSH_Lib.Tests.Fixtures.Binary_Data.Same_Bytes
        (Actual_Data, Expected_Data)
      then
         Ada.Text_IO.Put_Line
           ("FAILED: " & Operation & " scenario=" & Scenario &
            " first-mismatch=" & Natural'Image
              (SSH_Lib.Tests.Fixtures.Binary_Data.First_Mismatch
                 (Actual_Data, Expected_Data)));
         raise Program_Error;
      end if;
   end Check_Bytes;
end SSH_Lib.Tests.Assertions;
