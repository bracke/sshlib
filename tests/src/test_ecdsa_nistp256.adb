with Ada.Streams;
with Ada.Text_IO;
with SSH_Lib.ECDSA;
with SSH_Lib.Signatures;
with SSH_Lib.Protocol.Buffers;
with CryptoLib.Errors;

procedure Test_ECDSA_Nistp256 is
   use Ada.Streams;
   use type CryptoLib.Errors.Status;

   ECDSA_Public_Blob : constant Stream_Element_Array (1 .. 104) :=
     [
      1 => 16#00#, 2 => 16#00#, 3 => 16#00#, 4 => 16#13#,
      5 => 16#65#, 6 => 16#63#, 7 => 16#64#, 8 => 16#73#,
      9 => 16#61#, 10 => 16#2D#, 11 => 16#73#, 12 => 16#68#,
      13 => 16#61#, 14 => 16#32#, 15 => 16#2D#, 16 => 16#6E#,
      17 => 16#69#, 18 => 16#73#, 19 => 16#74#, 20 => 16#70#,
      21 => 16#32#, 22 => 16#35#, 23 => 16#36#, 24 => 16#00#,
      25 => 16#00#, 26 => 16#00#, 27 => 16#08#, 28 => 16#6E#,
      29 => 16#69#, 30 => 16#73#, 31 => 16#74#, 32 => 16#70#,
      33 => 16#32#, 34 => 16#35#, 35 => 16#36#, 36 => 16#00#,
      37 => 16#00#, 38 => 16#00#, 39 => 16#41#, 40 => 16#04#,
      41 => 16#67#, 42 => 16#AC#, 43 => 16#AD#, 44 => 16#2D#,
      45 => 16#10#, 46 => 16#08#, 47 => 16#83#, 48 => 16#67#,
      49 => 16#76#, 50 => 16#CE#, 51 => 16#44#, 52 => 16#72#,
      53 => 16#0E#, 54 => 16#8A#, 55 => 16#C9#, 56 => 16#FA#,
      57 => 16#5A#, 58 => 16#50#, 59 => 16#10#, 60 => 16#74#,
      61 => 16#2C#, 62 => 16#15#, 63 => 16#6B#, 64 => 16#D2#,
      65 => 16#B8#, 66 => 16#5D#, 67 => 16#8B#, 68 => 16#31#,
      69 => 16#68#, 70 => 16#34#, 71 => 16#74#, 72 => 16#A2#,
      73 => 16#8D#, 74 => 16#E9#, 75 => 16#88#, 76 => 16#24#,
      77 => 16#F7#, 78 => 16#26#, 79 => 16#C9#, 80 => 16#F4#,
      81 => 16#B0#, 82 => 16#F5#, 83 => 16#88#, 84 => 16#A7#,
      85 => 16#41#, 86 => 16#9D#, 87 => 16#D9#, 88 => 16#E4#,
      89 => 16#A1#, 90 => 16#8D#, 91 => 16#F6#, 92 => 16#B8#,
      93 => 16#2A#, 94 => 16#DC#, 95 => 16#B7#, 96 => 16#0D#,
      97 => 16#0F#, 98 => 16#6D#, 99 => 16#D4#, 100 => 16#AB#,
      101 => 16#31#, 102 => 16#CA#, 103 => 16#CE#, 104 => 16#9D#];

   ECDSA_Signature : constant Stream_Element_Array (1 .. 73) :=
     [
      1 => 16#00#, 2 => 16#00#, 3 => 16#00#, 4 => 16#21#,
      5 => 16#00#, 6 => 16#EA#, 7 => 16#3A#, 8 => 16#EB#,
      9 => 16#32#, 10 => 16#2E#, 11 => 16#3D#, 12 => 16#09#,
      13 => 16#4C#, 14 => 16#7F#, 15 => 16#13#, 16 => 16#AA#,
      17 => 16#5F#, 18 => 16#D8#, 19 => 16#D2#, 20 => 16#3F#,
      21 => 16#F7#, 22 => 16#D4#, 23 => 16#59#, 24 => 16#68#,
      25 => 16#CC#, 26 => 16#C2#, 27 => 16#7A#, 28 => 16#DF#,
      29 => 16#1F#, 30 => 16#65#, 31 => 16#70#, 32 => 16#C3#,
      33 => 16#E3#, 34 => 16#8A#, 35 => 16#69#, 36 => 16#36#,
      37 => 16#1B#, 38 => 16#00#, 39 => 16#00#, 40 => 16#00#,
      41 => 16#20#, 42 => 16#5F#, 43 => 16#B9#, 44 => 16#5B#,
      45 => 16#B4#, 46 => 16#77#, 47 => 16#CF#, 48 => 16#81#,
      49 => 16#7E#, 50 => 16#A2#, 51 => 16#A6#, 52 => 16#E9#,
      53 => 16#2F#, 54 => 16#CF#, 55 => 16#B2#, 56 => 16#53#,
      57 => 16#E8#, 58 => 16#C8#, 59 => 16#94#, 60 => 16#01#,
      61 => 16#5E#, 62 => 16#09#, 63 => 16#1E#, 64 => 16#7F#,
      65 => 16#F4#, 66 => 16#5A#, 67 => 16#E0#, 68 => 16#BC#,
      69 => 16#06#, 70 => 16#EB#, 71 => 16#E7#, 72 => 16#14#,
      73 => 16#8B#];

   ECDSA_Message : constant Stream_Element_Array (1 .. 38) :=
     [
      1 => 16#00#, 2 => 16#0A#, 3 => 16#0D#, 4 => 16#7F#,
      5 => 16#80#, 6 => 16#FF#, 7 => 16#41#, 8 => 16#64#,
      9 => 16#61#, 10 => 16#5F#, 11 => 16#53#, 12 => 16#53#,
      13 => 16#48#, 14 => 16#20#, 15 => 16#45#, 16 => 16#43#,
      17 => 16#44#, 18 => 16#53#, 19 => 16#41#, 20 => 16#20#,
      21 => 16#50#, 22 => 16#2D#, 23 => 16#32#, 24 => 16#35#,
      25 => 16#36#, 26 => 16#20#, 27 => 16#76#, 28 => 16#65#,
      29 => 16#72#, 30 => 16#69#, 31 => 16#66#, 32 => 16#69#,
      33 => 16#63#, 34 => 16#61#, 35 => 16#74#, 36 => 16#69#,
      37 => 16#6F#, 38 => 16#6E#];


   ECDSA_Private_Scalar_Mpint : constant Stream_Element_Array (1 .. 31) :=
     [
      1 => 16#1F#, 2 => 16#1E#, 3 => 16#1D#, 4 => 16#1C#,
      5 => 16#1B#, 6 => 16#1A#, 7 => 16#19#, 8 => 16#18#,
      9 => 16#17#, 10 => 16#16#, 11 => 16#15#, 12 => 16#14#,
      13 => 16#13#, 14 => 16#12#, 15 => 16#11#, 16 => 16#10#,
      17 => 16#0F#, 18 => 16#0E#, 19 => 16#0D#, 20 => 16#0C#,
      21 => 16#0B#, 22 => 16#0A#, 23 => 16#09#, 24 => 16#08#,
      25 => 16#07#, 26 => 16#06#, 27 => 16#05#, 28 => 16#04#,
      29 => 16#03#, 30 => 16#02#, 31 => 16#01#];

   procedure Check_Status
     (Actual : CryptoLib.Errors.Status;
      Expected : CryptoLib.Errors.Status;
      Label_Text : String) is
   begin
      if Actual /= Expected then
         Ada.Text_IO.Put_Line
           ("FAILED: " & Label_Text & " expected " & Expected'Image & " got " & Actual'Image);
         raise Program_Error;
      end if;
   end Check_Status;

   Mutated_Signature : Stream_Element_Array := ECDSA_Signature;
   Mutated_Message   : Stream_Element_Array := ECDSA_Message;
   Generated_Signature : SSH_Lib.Protocol.Buffers.Packet_Buffer;
begin
   Check_Status
     (SSH_Lib.ECDSA.Validate_Public_Nistp256 (ECDSA_Public_Blob),
      CryptoLib.Errors.Ok,
      "ECDSA P-256 public key blob validates");
   Check_Status
     (SSH_Lib.ECDSA.Validate_Signature_Nistp256 (ECDSA_Signature),
      CryptoLib.Errors.Ok,
      "ECDSA P-256 signature blob validates");
   Check_Status
     (SSH_Lib.Signatures.Verify
        ("ecdsa-sha2-nistp256", ECDSA_Public_Blob, ECDSA_Signature, ECDSA_Message),
      CryptoLib.Errors.Ok,
      "ECDSA P-256 signature verifies");

   Mutated_Signature (Mutated_Signature'Last) :=
     Mutated_Signature (Mutated_Signature'Last) xor 16#01#;
   Check_Status
     (SSH_Lib.Signatures.Verify
        ("ecdsa-sha2-nistp256", ECDSA_Public_Blob, Mutated_Signature, ECDSA_Message),
      CryptoLib.Errors.Handshake_Failed,
      "mutated ECDSA P-256 signature is rejected");

   Mutated_Message (Mutated_Message'First) :=
     Mutated_Message (Mutated_Message'First) xor 16#01#;
   Check_Status
     (SSH_Lib.Signatures.Verify
        ("ecdsa-sha2-nistp256", ECDSA_Public_Blob, ECDSA_Signature, Mutated_Message),
      CryptoLib.Errors.Handshake_Failed,
      "mutated ECDSA P-256 message is rejected");

   Check_Status
     (SSH_Lib.ECDSA.Public_Matches_Private_Nistp256
        (ECDSA_Public_Blob, ECDSA_Private_Scalar_Mpint),
      CryptoLib.Errors.Ok,
      "ECDSA P-256 public key matches private scalar");

   Check_Status
     (SSH_Lib.ECDSA.Sign_Nistp256
        (ECDSA_Private_Scalar_Mpint, ECDSA_Message, Generated_Signature),
      CryptoLib.Errors.Ok,
      "ECDSA P-256 private scalar signs");

   Check_Status
     (SSH_Lib.ECDSA.Verify_Nistp256
        (ECDSA_Public_Blob,
         SSH_Lib.Protocol.Buffers.To_Array (Generated_Signature),
         ECDSA_Message),
      CryptoLib.Errors.Ok,
      "generated ECDSA P-256 signature verifies");

   Ada.Text_IO.Put_Line ("test_ecdsa_nistp256 passed");
end Test_ECDSA_Nistp256;
