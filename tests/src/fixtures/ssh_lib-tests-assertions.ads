with Ada.Streams;
with CryptoLib.Errors;

package SSH_Lib.Tests.Assertions is
   procedure Assert (Condition : Boolean; Label_Text : String);
   procedure Check (Condition : Boolean; Label_Text : String);

   procedure Check_Status
     (Actual_Status   : CryptoLib.Errors.Status;
      Expected_Status : CryptoLib.Errors.Status;
      Operation       : String;
      Scenario        : String := "");

   procedure Check_Bytes
     (Actual_Data   : Ada.Streams.Stream_Element_Array;
      Expected_Data : Ada.Streams.Stream_Element_Array;
      Operation     : String;
      Scenario      : String := "");
end SSH_Lib.Tests.Assertions;
