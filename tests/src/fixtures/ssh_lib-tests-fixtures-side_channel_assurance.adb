with Ada.Text_IO;
with CryptoLib.Constant_Time_Assurance;
with CryptoLib.Constant_Time_Proof;

package body SSH_Lib.Tests.Fixtures.Side_Channel_Assurance is

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   procedure Assert_Side_Channel_Assurance is
      use CryptoLib.Constant_Time_Assurance;
      use CryptoLib.Constant_Time_Proof;
   begin
      Check (Manifest_Version = "side-channel-assurance-v1",
             "side-channel assurance manifest version");
      Check (All_Primitives_Assessed,
             "all side-channel-sensitive primitives are assessed");
      Check (Formal_Proof_Manifest_Version = "side-channel-formal-proof-v1",
             "formal side-channel proof manifest version");
      Check (All_Source_Obligations_Discharged,
             "all source-level formal proof obligations are discharged");

      for Item in Crypto_Primitive loop
         Check (Primitive_Label (Item)'Length > 0,
                "primitive has assurance label");
         Check (Level (Item) /= Not_Assessed,
                "primitive is not unassessed");
         Check (Is_Assurance_Gated (Item),
                "primitive is assurance gated");
         Check (Requires_External_Review (Item),
                "primitive keeps external review requirement");
         Check (Source_Obligations_Discharged (Item),
                "primitive has source-level proof obligations discharged");
         Check (External_Proof_Remains_Required (Item),
                "primitive keeps external proof evidence requirement");
      end loop;

      Check (Level (RSA_Private_Exponentiation) = Source_Gated_Formal_Assurance,
             "RSA private exponentiation source gate");
      Check (Level (X25519_Scalar_Multiplication) = Source_Gated_Formal_Assurance,
             "X25519 scalar multiplication source gate");
      Check (Level (MLKEM768_Decapsulation) = Fixed_Iteration_Audited,
             "ML-KEM decapsulation fixed iteration audit");
      Check (Level (SNTRUP761_Decapsulation) = Fixed_Iteration_Audited,
             "SNTRUP decapsulation fixed iteration audit");
   end Assert_Side_Channel_Assurance;
end SSH_Lib.Tests.Fixtures.Side_Channel_Assurance;
