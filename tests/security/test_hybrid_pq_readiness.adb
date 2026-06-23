with Ada.Text_IO;
with Ada.Command_Line;
with CryptoLib.Hybrid_PQ_Kex;
with CryptoLib.Errors;

procedure Test_Hybrid_PQ_Readiness is
   use CryptoLib.Hybrid_PQ_Kex;
   use type CryptoLib.Errors.Status;

   Failure_Count : Natural := 0;

   procedure Check (Condition : Boolean; Message_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
         Failure_Count := Failure_Count + 1;
      end if;
   end Check;

   procedure Check_Gated
     (Name_Text      : String;
      Expected_State : Hybrid_PQ_Readiness;
      Expected_Image : String)
   is
   begin
      Check (Is_OpenSSH_Hybrid_PQ_Kex_Name (Name_Text), Name_Text & " is recognized");
      Check (Readiness_Of (Name_Text) = Expected_State,
             Name_Text & " reports expected readiness state");
      Check (Readiness_Image (Readiness_Of (Name_Text)) = Expected_Image,
             Name_Text & " readiness image is stable");
      Check (Is_Implemented (Name_Text), Name_Text & " is advertised after conformance gates pass");
      Check (Fail_Closed_Status (Name_Text) = CryptoLib.Errors.Ok,
             Name_Text & " no longer fails closed after conformance gates pass");
   end Check_Gated;

begin
   Check_Gated ("mlkem768x25519-sha256",
                Advertised_And_Selectable,
                "advertised-and-selectable");
   Check_Gated ("mlkem768x25519-sha512",
                Advertised_And_Selectable,
                "advertised-and-selectable");
   Check_Gated ("sntrup761x25519-sha512@openssh.com",
                Advertised_And_Selectable,
                "advertised-and-selectable");
   Check_Gated ("sntrup761x25519-sha512",
                Advertised_And_Selectable,
                "advertised-and-selectable");

   Check (Readiness_Of ("curve25519-sha256") = Unknown_Algorithm,
          "non-hybrid algorithm has unknown readiness");
   Check (Readiness_Image (Unknown_Algorithm) = "unknown-algorithm",
          "unknown readiness image is stable");

   if Failure_Count /= 0 then
      Ada.Text_IO.Put_Line
        ("test_hybrid_pq_readiness failed with" & Natural'Image (Failure_Count) & " issue(s)");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   else
      Ada.Text_IO.Put_Line ("test_hybrid_pq_readiness passed");
   end if;
end Test_Hybrid_PQ_Readiness;
