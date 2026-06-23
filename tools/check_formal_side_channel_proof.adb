with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Text_IO;

procedure Check_Formal_Side_Channel_Proof is
   use Ada.Strings.Fixed;

   Failure_Count : Natural := 0;

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   function File_Contains (Path : String; Needle : String) return Boolean is
      File_Item : Ada.Text_IO.File_Type;
   begin
      if not Ada.Directories.Exists (Path) then
         return False;
      end if;

      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
         begin
            if Index (Line_Text, Needle) /= 0 then
               Ada.Text_IO.Close (File_Item);
               return True;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
      return False;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return False;
   end File_Contains;

   procedure Require_File (Path : String) is
   begin
      if not Ada.Directories.Exists (Path) then
         Fail ("missing formal proof file: " & Path);
      end if;
   end Require_File;

   procedure Require_Text (Path : String; Needle : String) is
   begin
      if not File_Contains (Path, Needle) then
         Fail ("missing formal proof token in " & Path & ": " & Needle);
      end if;
   end Require_Text;

   procedure Forbid_Text (Path : String; Needle : String) is
   begin
      if File_Contains (Path, Needle) then
         Fail ("forbidden side-channel proof regression token in " & Path & ": " & Needle);
      end if;
   end Forbid_Text;

begin
   Require_File ("../cryptolib/src/cryptolib-constant_time_proof.ads");
   Require_File ("../cryptolib/src/cryptolib-constant_time_proof.adb");
   Require_File ("tests/vectors/security/SIDE_CHANNEL_FORMAL_PROOF_MANIFEST.txt");
   Require_File ("docs/security/FORMAL_SIDE_CHANNEL_PROOF.md");
   Require_File ("tests/security/test_side_channel_assurance.adb");

   Require_Text ("../cryptolib/src/cryptolib-constant_time_proof.ads", "type Proof_Obligation");
   Require_Text ("../cryptolib/src/cryptolib-constant_time_proof.ads", "No_Secret_Dependent_Branches");
   Require_Text ("../cryptolib/src/cryptolib-constant_time_proof.ads", "All_Source_Obligations_Discharged");
   Require_Text ("../cryptolib/src/cryptolib-constant_time_proof.adb", "External_Evidence_Required");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-side_channel_assurance.adb", "All_Source_Obligations_Discharged");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-side_channel_assurance.adb", "External_Proof_Remains_Required");
   Require_Text ("tests/vectors/security/SIDE_CHANNEL_FORMAL_PROOF_MANIFEST.txt", "source-obligations-discharged-external-proof-required");
   Require_Text ("docs/security/FORMAL_SIDE_CHANNEL_PROOF.md", "source-level proof obligations");
   Require_Text ("tools/tools.gpr", "check_formal_side_channel_proof.adb");

   --  Guard against common proof-invalidating source regressions.
   Forbid_Text ("../cryptolib/src/cryptolib-diffie_hellman.adb", "Lowest_Useful_Bit");
   Forbid_Text ("../cryptolib/src/cryptolib-diffie_hellman.adb", "Stop_Bit");
   Forbid_Text ("../cryptolib/src/cryptolib-ed25519.adb", "while Compare (Item, P_Value) >= 0 loop");
   Forbid_Text ("../cryptolib/src/cryptolib-curve25519.adb", "return True;");
   Forbid_Text ("../cryptolib/src/cryptolib-mlkem768.adb", "if Ciphertext =");
   Forbid_Text ("../cryptolib/src/cryptolib-sntrup761.adb", "if Ciphertext =");

   if Failure_Count /= 0 then
      Ada.Text_IO.Put_Line
        ("check_formal_side_channel_proof failed with" & Natural'Image (Failure_Count) & " issue(s)");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   else
      Ada.Text_IO.Put_Line ("check_formal_side_channel_proof passed");
   end if;
end Check_Formal_Side_Channel_Proof;
