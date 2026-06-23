with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Text_IO;

procedure Check_Side_Channel_Assurance is
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
         Fail ("missing assurance file: " & Path);
      end if;
   end Require_File;

   procedure Require_Text (Path : String; Needle : String) is
   begin
      if not File_Contains (Path, Needle) then
         Fail ("missing assurance token in " & Path & ": " & Needle);
      end if;
   end Require_Text;

   procedure Forbid_Text (Path : String; Needle : String) is
   begin
      if File_Contains (Path, Needle) then
         Fail ("forbidden side-channel regression token in " & Path & ": " & Needle);
      end if;
   end Forbid_Text;

begin
   Require_File ("../cryptolib/src/cryptolib-constant_time_assurance.ads");
   Require_File ("../cryptolib/src/cryptolib-constant_time_assurance.adb");
   Require_File ("tests/security/test_side_channel_assurance.adb");
   Require_File ("tests/vectors/security/SIDE_CHANNEL_ASSURANCE_MANIFEST.txt");
   Require_File ("docs/security/SIDE_CHANNEL_ASSURANCE.md");
   Require_File ("../cryptolib/src/cryptolib-constant_time_proof.ads");
   Require_File ("tests/vectors/security/SIDE_CHANNEL_FORMAL_PROOF_MANIFEST.txt");

   Require_Text ("../cryptolib/src/cryptolib-constant_time_assurance.ads", "type Crypto_Primitive");
   Require_Text ("../cryptolib/src/cryptolib-constant_time_assurance.ads", "Source_Gated_Formal_Assurance");
   Require_Text ("../cryptolib/src/cryptolib-constant_time_assurance.ads", "External_Proof_Required");
   Require_Text ("../cryptolib/src/cryptolib-constant_time_assurance.adb", "All_Primitives_Assessed");
   Require_Text ("tests/security/security_tests.gpr", "test_side_channel_assurance.adb");
   Require_Text ("tests/vectors/security/SIDE_CHANNEL_ASSURANCE_MANIFEST.txt", "version: side-channel-assurance-v1");
   Require_Text ("tests/vectors/security/SIDE_CHANNEL_ASSURANCE_MANIFEST.txt", "external_review_required: true");
   Require_Text ("docs/security/SIDE_CHANNEL_ASSURANCE.md", "not an independent mathematical proof");
   Require_Text ("../cryptolib/src/cryptolib-constant_time_proof.ads", "type Proof_Obligation");
   Require_Text ("tests/vectors/security/SIDE_CHANNEL_FORMAL_PROOF_MANIFEST.txt", "side-channel-formal-proof-v1");

   --  Guard against the specific side-channel regression patterns removed in
   --  previous hardening passes.  This is intentionally conservative and must
   --  remain source-level: it catches accidental reintroduction before release.
   Forbid_Text ("../cryptolib/src/cryptolib-diffie_hellman.adb", "Lowest_Useful_Bit");
   Forbid_Text ("../cryptolib/src/cryptolib-diffie_hellman.adb", "Stop_Bit");
   Forbid_Text ("../cryptolib/src/cryptolib-ed25519.adb", "while Compare (Item, P_Value) >= 0 loop");
   Forbid_Text ("../cryptolib/src/cryptolib-curve25519.adb", "return True;");

   if Failure_Count /= 0 then
      Ada.Text_IO.Put_Line
        ("check_side_channel_assurance failed with" & Natural'Image (Failure_Count) & " issue(s)");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   else
      Ada.Text_IO.Put_Line ("check_side_channel_assurance passed");
   end if;
end Check_Side_Channel_Assurance;
