with Ada.Streams;
with Ada.Text_IO;
with CryptoLib.Buffers;
with CryptoLib.Ciphers;
with CryptoLib.Curve25519;
with CryptoLib.Diffie_Hellman;
with SSH_Lib.ECDSA;
with CryptoLib.Ed25519;
with SSH_Lib.RSA;
with CryptoLib.Random;
with CryptoLib.MLKEM768;
with CryptoLib.MLKEM768_Core;
with CryptoLib.SNTRUP761;
with SSH_Lib.Signatures;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Tests.Assertions;

package body SSH_Lib.Tests.Fixtures.Crypto_Primitives is
   use Ada.Streams;
   use type CryptoLib.Errors.Status;
   use type CryptoLib.Curve25519.Public_Key;

   RSA_Public_Blob : constant Stream_Element_Array (1 .. 151) :=
     [
      1 => 16#00#, 2 => 16#00#, 3 => 16#00#, 4 => 16#07#,
      5 => 16#73#, 6 => 16#73#, 7 => 16#68#, 8 => 16#2D#,
      9 => 16#72#, 10 => 16#73#, 11 => 16#61#, 12 => 16#00#,
      13 => 16#00#, 14 => 16#00#, 15 => 16#03#, 16 => 16#01#,
      17 => 16#00#, 18 => 16#01#, 19 => 16#00#, 20 => 16#00#,
      21 => 16#00#, 22 => 16#81#, 23 => 16#00#, 24 => 16#CB#,
      25 => 16#00#, 26 => 16#1A#, 27 => 16#1C#, 28 => 16#E1#,
      29 => 16#4F#, 30 => 16#30#, 31 => 16#67#, 32 => 16#6D#,
      33 => 16#F1#, 34 => 16#59#, 35 => 16#8E#, 36 => 16#23#,
      37 => 16#FE#, 38 => 16#50#, 39 => 16#FA#, 40 => 16#7E#,
      41 => 16#35#, 42 => 16#F9#, 43 => 16#65#, 44 => 16#75#,
      45 => 16#9A#, 46 => 16#60#, 47 => 16#5A#, 48 => 16#4B#,
      49 => 16#19#, 50 => 16#E4#, 51 => 16#AB#, 52 => 16#80#,
      53 => 16#78#, 54 => 16#7C#, 55 => 16#C5#, 56 => 16#E4#,
      57 => 16#5B#, 58 => 16#3E#, 59 => 16#DA#, 60 => 16#5B#,
      61 => 16#FB#, 62 => 16#98#, 63 => 16#2D#, 64 => 16#F1#,
      65 => 16#03#, 66 => 16#B6#, 67 => 16#C9#, 68 => 16#B3#,
      69 => 16#D1#, 70 => 16#CC#, 71 => 16#D0#, 72 => 16#25#,
      73 => 16#71#, 74 => 16#39#, 75 => 16#13#, 76 => 16#E8#,
      77 => 16#0C#, 78 => 16#D6#, 79 => 16#DB#, 80 => 16#3D#,
      81 => 16#B0#, 82 => 16#8A#, 83 => 16#89#, 84 => 16#F9#,
      85 => 16#9D#, 86 => 16#E0#, 87 => 16#9A#, 88 => 16#B8#,
      89 => 16#28#, 90 => 16#E1#, 91 => 16#FF#, 92 => 16#0A#,
      93 => 16#B2#, 94 => 16#66#, 95 => 16#93#, 96 => 16#32#,
      97 => 16#07#, 98 => 16#39#, 99 => 16#54#, 100 => 16#89#,
      101 => 16#23#, 102 => 16#75#, 103 => 16#97#, 104 => 16#24#,
      105 => 16#CD#, 106 => 16#00#, 107 => 16#26#, 108 => 16#62#,
      109 => 16#4A#, 110 => 16#5D#, 111 => 16#30#, 112 => 16#5C#,
      113 => 16#1B#, 114 => 16#C6#, 115 => 16#55#, 116 => 16#0C#,
      117 => 16#CA#, 118 => 16#BE#, 119 => 16#6B#, 120 => 16#A3#,
      121 => 16#C7#, 122 => 16#47#, 123 => 16#47#, 124 => 16#1F#,
      125 => 16#B1#, 126 => 16#CC#, 127 => 16#C5#, 128 => 16#F0#,
      129 => 16#A4#, 130 => 16#D9#, 131 => 16#82#, 132 => 16#65#,
      133 => 16#6B#, 134 => 16#50#, 135 => 16#07#, 136 => 16#94#,
      137 => 16#70#, 138 => 16#9E#, 139 => 16#32#, 140 => 16#A1#,
      141 => 16#98#, 142 => 16#FD#, 143 => 16#D5#, 144 => 16#83#,
      145 => 16#F4#, 146 => 16#8D#, 147 => 16#5D#, 148 => 16#72#,
      149 => 16#9C#, 150 => 16#23#, 151 => 16#9F#];

   RSA_Signature : constant Stream_Element_Array (1 .. 128) :=
     [
      1 => 16#7F#, 2 => 16#87#, 3 => 16#AB#, 4 => 16#76#,
      5 => 16#3A#, 6 => 16#59#, 7 => 16#8D#, 8 => 16#2D#,
      9 => 16#77#, 10 => 16#B9#, 11 => 16#46#, 12 => 16#C2#,
      13 => 16#28#, 14 => 16#B8#, 15 => 16#94#, 16 => 16#04#,
      17 => 16#C4#, 18 => 16#7C#, 19 => 16#E6#, 20 => 16#A1#,
      21 => 16#14#, 22 => 16#DB#, 23 => 16#DD#, 24 => 16#A8#,
      25 => 16#26#, 26 => 16#78#, 27 => 16#A9#, 28 => 16#6F#,
      29 => 16#6D#, 30 => 16#6A#, 31 => 16#70#, 32 => 16#08#,
      33 => 16#78#, 34 => 16#F1#, 35 => 16#66#, 36 => 16#10#,
      37 => 16#CF#, 38 => 16#EB#, 39 => 16#E4#, 40 => 16#83#,
      41 => 16#66#, 42 => 16#3F#, 43 => 16#E9#, 44 => 16#F9#,
      45 => 16#30#, 46 => 16#0B#, 47 => 16#4F#, 48 => 16#45#,
      49 => 16#75#, 50 => 16#56#, 51 => 16#27#, 52 => 16#4F#,
      53 => 16#DB#, 54 => 16#95#, 55 => 16#87#, 56 => 16#7A#,
      57 => 16#9D#, 58 => 16#5D#, 59 => 16#4F#, 60 => 16#2D#,
      61 => 16#E1#, 62 => 16#87#, 63 => 16#C4#, 64 => 16#38#,
      65 => 16#B4#, 66 => 16#81#, 67 => 16#0C#, 68 => 16#FC#,
      69 => 16#24#, 70 => 16#D9#, 71 => 16#44#, 72 => 16#CB#,
      73 => 16#F7#, 74 => 16#3A#, 75 => 16#5A#, 76 => 16#9F#,
      77 => 16#70#, 78 => 16#FE#, 79 => 16#85#, 80 => 16#00#,
      81 => 16#94#, 82 => 16#D3#, 83 => 16#3E#, 84 => 16#BC#,
      85 => 16#D1#, 86 => 16#00#, 87 => 16#BF#, 88 => 16#D8#,
      89 => 16#8C#, 90 => 16#D2#, 91 => 16#65#, 92 => 16#1D#,
      93 => 16#BF#, 94 => 16#26#, 95 => 16#59#, 96 => 16#6F#,
      97 => 16#73#, 98 => 16#9A#, 99 => 16#45#, 100 => 16#1A#,
      101 => 16#7A#, 102 => 16#D1#, 103 => 16#73#, 104 => 16#17#,
      105 => 16#AC#, 106 => 16#02#, 107 => 16#BD#, 108 => 16#23#,
      109 => 16#7A#, 110 => 16#3F#, 111 => 16#A0#, 112 => 16#84#,
      113 => 16#18#, 114 => 16#59#, 115 => 16#23#, 116 => 16#3A#,
      117 => 16#02#, 118 => 16#27#, 119 => 16#0C#, 120 => 16#72#,
      121 => 16#1B#, 122 => 16#FC#, 123 => 16#FD#, 124 => 16#19#,
      125 => 16#77#, 126 => 16#48#, 127 => 16#BF#, 128 => 16#69#];

   RSA_Message : constant Stream_Element_Array (1 .. 37) :=
     [
      1 => 16#00#, 2 => 16#0A#, 3 => 16#0D#, 4 => 16#7F#,
      5 => 16#80#, 6 => 16#FF#, 7 => 16#41#, 8 => 16#64#,
      9 => 16#61#, 10 => 16#5F#, 11 => 16#53#, 12 => 16#53#,
      13 => 16#48#, 14 => 16#20#, 15 => 16#52#, 16 => 16#53#,
      17 => 16#41#, 18 => 16#20#, 19 => 16#53#, 20 => 16#48#,
      21 => 16#41#, 22 => 16#32#, 23 => 16#35#, 24 => 16#36#,
      25 => 16#20#, 26 => 16#76#, 27 => 16#65#, 28 => 16#72#,
      29 => 16#69#, 30 => 16#66#, 31 => 16#69#, 32 => 16#63#,
      33 => 16#61#, 34 => 16#74#, 35 => 16#69#, 36 => 16#6F#,
      37 => 16#6E#];

   Ed25519_Seed : constant Stream_Element_Array (1 .. 32) :=
     [
      1 => 16#4C#, 2 => 16#CD#, 3 => 16#08#, 4 => 16#9B#,
      5 => 16#28#, 6 => 16#FF#, 7 => 16#96#, 8 => 16#DA#,
      9 => 16#9D#, 10 => 16#B6#, 11 => 16#C3#, 12 => 16#46#,
      13 => 16#EC#, 14 => 16#11#, 15 => 16#4E#, 16 => 16#0F#,
      17 => 16#5B#, 18 => 16#8A#, 19 => 16#31#, 20 => 16#9F#,
      21 => 16#35#, 22 => 16#AB#, 23 => 16#A6#, 24 => 16#24#,
      25 => 16#DA#, 26 => 16#8C#, 27 => 16#F6#, 28 => 16#ED#,
      29 => 16#4F#, 30 => 16#B8#, 31 => 16#A6#, 32 => 16#FB#];

   Ed25519_Public_Key : constant Stream_Element_Array (1 .. 32) :=
     [
      1 => 16#3D#, 2 => 16#40#, 3 => 16#17#, 4 => 16#C3#,
      5 => 16#E8#, 6 => 16#43#, 7 => 16#89#, 8 => 16#5A#,
      9 => 16#92#, 10 => 16#B7#, 11 => 16#0A#, 12 => 16#A7#,
      13 => 16#4D#, 14 => 16#1B#, 15 => 16#7E#, 16 => 16#BC#,
      17 => 16#9C#, 18 => 16#98#, 19 => 16#2C#, 20 => 16#CF#,
      21 => 16#2E#, 22 => 16#C4#, 23 => 16#96#, 24 => 16#8C#,
      25 => 16#C0#, 26 => 16#CD#, 27 => 16#55#, 28 => 16#F1#,
      29 => 16#2A#, 30 => 16#F4#, 31 => 16#66#, 32 => 16#0C#];

   Ed25519_Public_Blob : constant Stream_Element_Array (1 .. 51) :=
     [
      1 => 16#00#, 2 => 16#00#, 3 => 16#00#, 4 => 16#0B#,
      5 => 16#73#, 6 => 16#73#, 7 => 16#68#, 8 => 16#2D#,
      9 => 16#65#, 10 => 16#64#, 11 => 16#32#, 12 => 16#35#,
      13 => 16#35#, 14 => 16#31#, 15 => 16#39#, 16 => 16#00#,
      17 => 16#00#, 18 => 16#00#, 19 => 16#20#, 20 => 16#3D#,
      21 => 16#40#, 22 => 16#17#, 23 => 16#C3#, 24 => 16#E8#,
      25 => 16#43#, 26 => 16#89#, 27 => 16#5A#, 28 => 16#92#,
      29 => 16#B7#, 30 => 16#0A#, 31 => 16#A7#, 32 => 16#4D#,
      33 => 16#1B#, 34 => 16#7E#, 35 => 16#BC#, 36 => 16#9C#,
      37 => 16#98#, 38 => 16#2C#, 39 => 16#CF#, 40 => 16#2E#,
      41 => 16#C4#, 42 => 16#96#, 43 => 16#8C#, 44 => 16#C0#,
      45 => 16#CD#, 46 => 16#55#, 47 => 16#F1#, 48 => 16#2A#,
      49 => 16#F4#, 50 => 16#66#, 51 => 16#0C#];

   Ed25519_Signature : constant Stream_Element_Array (1 .. 64) :=
     [
      1 => 16#92#, 2 => 16#A0#, 3 => 16#09#, 4 => 16#A9#,
      5 => 16#F0#, 6 => 16#D4#, 7 => 16#CA#, 8 => 16#B8#,
      9 => 16#72#, 10 => 16#0E#, 11 => 16#82#, 12 => 16#0B#,
      13 => 16#5F#, 14 => 16#64#, 15 => 16#25#, 16 => 16#40#,
      17 => 16#A2#, 18 => 16#B2#, 19 => 16#7B#, 20 => 16#54#,
      21 => 16#16#, 22 => 16#50#, 23 => 16#3F#, 24 => 16#8F#,
      25 => 16#B3#, 26 => 16#76#, 27 => 16#22#, 28 => 16#23#,
      29 => 16#EB#, 30 => 16#DB#, 31 => 16#69#, 32 => 16#DA#,
      33 => 16#08#, 34 => 16#5A#, 35 => 16#C1#, 36 => 16#E4#,
      37 => 16#3E#, 38 => 16#15#, 39 => 16#99#, 40 => 16#6E#,
      41 => 16#45#, 42 => 16#8F#, 43 => 16#36#, 44 => 16#13#,
      45 => 16#D0#, 46 => 16#F1#, 47 => 16#1D#, 48 => 16#8C#,
      49 => 16#38#, 50 => 16#7B#, 51 => 16#2E#, 52 => 16#AE#,
      53 => 16#B4#, 54 => 16#30#, 55 => 16#2A#, 56 => 16#EE#,
      57 => 16#B0#, 58 => 16#0D#, 59 => 16#29#, 60 => 16#16#,
      61 => 16#12#, 62 => 16#BB#, 63 => 16#0C#, 64 => 16#00#];

   Ed25519_Message : constant Stream_Element_Array (1 .. 1) :=
     [1 => 16#72#];





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

   RSA_SHA512_Public_Blob : constant Stream_Element_Array (1 .. 151) :=
     [1 => 16#00#, 2 => 16#00#, 3 => 16#00#, 4 => 16#07#,
      5 => 16#73#, 6 => 16#73#, 7 => 16#68#, 8 => 16#2D#,
      9 => 16#72#, 10 => 16#73#, 11 => 16#61#, 12 => 16#00#,
      13 => 16#00#, 14 => 16#00#, 15 => 16#03#, 16 => 16#01#,
      17 => 16#00#, 18 => 16#01#, 19 => 16#00#, 20 => 16#00#,
      21 => 16#00#, 22 => 16#81#, 23 => 16#00#, 24 => 16#E9#,
      25 => 16#F0#, 26 => 16#E4#, 27 => 16#0D#, 28 => 16#B1#,
      29 => 16#F2#, 30 => 16#3A#, 31 => 16#2F#, 32 => 16#02#,
      33 => 16#AF#, 34 => 16#6E#, 35 => 16#8D#, 36 => 16#B4#,
      37 => 16#80#, 38 => 16#92#, 39 => 16#41#, 40 => 16#FF#,
      41 => 16#79#, 42 => 16#D5#, 43 => 16#75#, 44 => 16#AF#,
      45 => 16#D9#, 46 => 16#C0#, 47 => 16#39#, 48 => 16#0F#,
      49 => 16#28#, 50 => 16#78#, 51 => 16#A6#, 52 => 16#F4#,
      53 => 16#44#, 54 => 16#5C#, 55 => 16#66#, 56 => 16#16#,
      57 => 16#A2#, 58 => 16#0C#, 59 => 16#38#, 60 => 16#B8#,
      61 => 16#E1#, 62 => 16#A3#, 63 => 16#A3#, 64 => 16#B5#,
      65 => 16#D6#, 66 => 16#0E#, 67 => 16#76#, 68 => 16#72#,
      69 => 16#35#, 70 => 16#51#, 71 => 16#F4#, 72 => 16#D1#,
      73 => 16#84#, 74 => 16#FF#, 75 => 16#DD#, 76 => 16#A5#,
      77 => 16#1A#, 78 => 16#58#, 79 => 16#4A#, 80 => 16#E0#,
      81 => 16#4F#, 82 => 16#07#, 83 => 16#FA#, 84 => 16#5B#,
      85 => 16#2B#, 86 => 16#3F#, 87 => 16#8F#, 88 => 16#71#,
      89 => 16#94#, 90 => 16#D7#, 91 => 16#0A#, 92 => 16#C0#,
      93 => 16#07#, 94 => 16#84#, 95 => 16#F3#, 96 => 16#33#,
      97 => 16#5D#, 98 => 16#73#, 99 => 16#72#, 100 => 16#32#,
      101 => 16#E8#, 102 => 16#D0#, 103 => 16#2E#, 104 => 16#28#,
      105 => 16#B1#, 106 => 16#D0#, 107 => 16#00#, 108 => 16#DA#,
      109 => 16#4F#, 110 => 16#1F#, 111 => 16#CD#, 112 => 16#CF#,
      113 => 16#C1#, 114 => 16#5F#, 115 => 16#E0#, 116 => 16#C9#,
      117 => 16#F6#, 118 => 16#27#, 119 => 16#24#, 120 => 16#F6#,
      121 => 16#22#, 122 => 16#C3#, 123 => 16#05#, 124 => 16#C0#,
      125 => 16#53#, 126 => 16#98#, 127 => 16#2E#, 128 => 16#32#,
      129 => 16#50#, 130 => 16#A2#, 131 => 16#F6#, 132 => 16#72#,
      133 => 16#AA#, 134 => 16#30#, 135 => 16#D3#, 136 => 16#C1#,
      137 => 16#1D#, 138 => 16#1E#, 139 => 16#49#, 140 => 16#A7#,
      141 => 16#49#, 142 => 16#F8#, 143 => 16#CE#, 144 => 16#A2#,
      145 => 16#2C#, 146 => 16#C2#, 147 => 16#E2#, 148 => 16#C0#,
      149 => 16#9B#, 150 => 16#AB#, 151 => 16#71#];

   RSA_SHA512_Signature : constant Stream_Element_Array (1 .. 128) :=
     [1 => 16#03#, 2 => 16#34#, 3 => 16#D2#, 4 => 16#53#,
      5 => 16#01#, 6 => 16#D8#, 7 => 16#0C#, 8 => 16#F1#,
      9 => 16#A2#, 10 => 16#A5#, 11 => 16#1D#, 12 => 16#F8#,
      13 => 16#D7#, 14 => 16#F7#, 15 => 16#14#, 16 => 16#36#,
      17 => 16#EA#, 18 => 16#54#, 19 => 16#96#, 20 => 16#A6#,
      21 => 16#53#, 22 => 16#C6#, 23 => 16#DE#, 24 => 16#E6#,
      25 => 16#1A#, 26 => 16#4A#, 27 => 16#E0#, 28 => 16#AE#,
      29 => 16#9D#, 30 => 16#2D#, 31 => 16#2F#, 32 => 16#D4#,
      33 => 16#02#, 34 => 16#BF#, 35 => 16#08#, 36 => 16#F3#,
      37 => 16#21#, 38 => 16#59#, 39 => 16#78#, 40 => 16#0F#,
      41 => 16#90#, 42 => 16#DB#, 43 => 16#90#, 44 => 16#DC#,
      45 => 16#BC#, 46 => 16#E8#, 47 => 16#D1#, 48 => 16#FE#,
      49 => 16#AB#, 50 => 16#BF#, 51 => 16#8A#, 52 => 16#9C#,
      53 => 16#62#, 54 => 16#26#, 55 => 16#A8#, 56 => 16#00#,
      57 => 16#F8#, 58 => 16#77#, 59 => 16#9B#, 60 => 16#C1#,
      61 => 16#0E#, 62 => 16#FB#, 63 => 16#DC#, 64 => 16#D0#,
      65 => 16#DD#, 66 => 16#B6#, 67 => 16#B9#, 68 => 16#82#,
      69 => 16#02#, 70 => 16#CB#, 71 => 16#A6#, 72 => 16#D0#,
      73 => 16#4D#, 74 => 16#1C#, 75 => 16#B2#, 76 => 16#08#,
      77 => 16#63#, 78 => 16#77#, 79 => 16#22#, 80 => 16#91#,
      81 => 16#67#, 82 => 16#C2#, 83 => 16#49#, 84 => 16#27#,
      85 => 16#AC#, 86 => 16#42#, 87 => 16#B7#, 88 => 16#93#,
      89 => 16#83#, 90 => 16#0F#, 91 => 16#44#, 92 => 16#94#,
      93 => 16#8A#, 94 => 16#F4#, 95 => 16#1C#, 96 => 16#1D#,
      97 => 16#AE#, 98 => 16#EA#, 99 => 16#36#, 100 => 16#50#,
      101 => 16#AD#, 102 => 16#EF#, 103 => 16#58#, 104 => 16#5F#,
      105 => 16#94#, 106 => 16#61#, 107 => 16#D6#, 108 => 16#82#,
      109 => 16#3C#, 110 => 16#39#, 111 => 16#50#, 112 => 16#4B#,
      113 => 16#71#, 114 => 16#30#, 115 => 16#CB#, 116 => 16#70#,
      117 => 16#CD#, 118 => 16#A5#, 119 => 16#8E#, 120 => 16#0C#,
      121 => 16#EA#, 122 => 16#0A#, 123 => 16#88#, 124 => 16#44#,
      125 => 16#65#, 126 => 16#8C#, 127 => 16#C8#, 128 => 16#A2#];

   RSA_SHA512_Message : constant Stream_Element_Array (1 .. 45) :=
     [1 => 16#00#, 2 => 16#0A#, 3 => 16#0D#, 4 => 16#7F#,
      5 => 16#80#, 6 => 16#FF#, 7 => 16#41#, 8 => 16#64#,
      9 => 16#61#, 10 => 16#5F#, 11 => 16#53#, 12 => 16#53#,
      13 => 16#48#, 14 => 16#20#, 15 => 16#50#, 16 => 16#68#,
      17 => 16#61#, 18 => 16#73#, 19 => 16#65#, 20 => 16#31#,
      21 => 16#39#, 22 => 16#20#, 23 => 16#52#, 24 => 16#53#,
      25 => 16#41#, 26 => 16#20#, 27 => 16#53#, 28 => 16#48#,
      29 => 16#41#, 30 => 16#35#, 31 => 16#31#, 32 => 16#32#,
      33 => 16#20#, 34 => 16#76#, 35 => 16#65#, 36 => 16#72#,
      37 => 16#69#, 38 => 16#66#, 39 => 16#69#, 40 => 16#63#,
      41 => 16#61#, 42 => 16#74#, 43 => 16#69#, 44 => 16#6F#,
      45 => 16#6E#];

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   function Hex_Nibble (Ch : Character) return Natural is
   begin
      if Ch in '0' .. '9' then
         return Character'Pos (Ch) - Character'Pos ('0');
      elsif Ch in 'A' .. 'F' then
         return Character'Pos (Ch) - Character'Pos ('A') + 10;
      elsif Ch in 'a' .. 'f' then
         return Character'Pos (Ch) - Character'Pos ('a') + 10;
      end if;
      raise Program_Error;
   end Hex_Nibble;

   function Hex_To_Bytes (Text : String) return Stream_Element_Array is
      Result_Value : Stream_Element_Array (1 .. Text'Length / 2);
      Cursor       : Natural := Text'First;
   begin
      Check (Text'Length mod 2 = 0, "hex fixture has complete bytes");
      for Index_Value in Result_Value'Range loop
         Result_Value (Index_Value) :=
           Stream_Element
             (Hex_Nibble (Text (Cursor)) * 16
              + Hex_Nibble (Text (Cursor + 1)));
         Cursor := Cursor + 2;
      end loop;
      return Result_Value;
   end Hex_To_Bytes;

   procedure Assert_Curve25519_RFC7748_Vectors is
      Alice_Private : constant CryptoLib.Curve25519.Public_Key :=
        [1  => 16#77#, 2  => 16#07#, 3  => 16#6D#, 4  => 16#0A#,
         5  => 16#73#, 6  => 16#18#, 7  => 16#A5#, 8  => 16#7D#,
         9  => 16#3C#, 10 => 16#16#, 11 => 16#C1#, 12 => 16#72#,
         13 => 16#51#, 14 => 16#B2#, 15 => 16#66#, 16 => 16#45#,
         17 => 16#DF#, 18 => 16#4C#, 19 => 16#2F#, 20 => 16#87#,
         21 => 16#EB#, 22 => 16#C0#, 23 => 16#99#, 24 => 16#2A#,
         25 => 16#B1#, 26 => 16#77#, 27 => 16#FB#, 28 => 16#A5#,
         29 => 16#1D#, 30 => 16#B9#, 31 => 16#2C#, 32 => 16#2A#];
      Alice_Public : constant CryptoLib.Curve25519.Public_Key :=
        [1  => 16#85#, 2  => 16#20#, 3  => 16#F0#, 4  => 16#09#,
         5  => 16#89#, 6  => 16#30#, 7  => 16#A7#, 8  => 16#54#,
         9  => 16#74#, 10 => 16#8B#, 11 => 16#7D#, 12 => 16#DC#,
         13 => 16#B4#, 14 => 16#3E#, 15 => 16#F7#, 16 => 16#5A#,
         17 => 16#0D#, 18 => 16#BF#, 19 => 16#3A#, 20 => 16#0D#,
         21 => 16#26#, 22 => 16#38#, 23 => 16#1A#, 24 => 16#F4#,
         25 => 16#EB#, 26 => 16#A4#, 27 => 16#A9#, 28 => 16#8E#,
         29 => 16#AA#, 30 => 16#9B#, 31 => 16#4E#, 32 => 16#6A#];
      Bob_Public : constant CryptoLib.Curve25519.Public_Key :=
        [1  => 16#DE#, 2  => 16#9E#, 3  => 16#DB#, 4  => 16#7D#,
         5  => 16#7B#, 6  => 16#7D#, 7  => 16#C1#, 8  => 16#B4#,
         9  => 16#D3#, 10 => 16#5B#, 11 => 16#61#, 12 => 16#C2#,
         13 => 16#EC#, 14 => 16#E4#, 15 => 16#35#, 16 => 16#37#,
         17 => 16#3F#, 18 => 16#83#, 19 => 16#43#, 20 => 16#C8#,
         21 => 16#5B#, 22 => 16#78#, 23 => 16#67#, 24 => 16#4D#,
         25 => 16#AD#, 26 => 16#FC#, 27 => 16#7E#, 28 => 16#14#,
         29 => 16#6F#, 30 => 16#88#, 31 => 16#2B#, 32 => 16#4F#];
      Shared_Vector : constant CryptoLib.Curve25519.Public_Key :=
        [1  => 16#4A#, 2  => 16#5D#, 3  => 16#9D#, 4  => 16#5B#,
         5  => 16#A4#, 6  => 16#CE#, 7  => 16#2D#, 8  => 16#E1#,
         9  => 16#72#, 10 => 16#8E#, 11 => 16#3B#, 12 => 16#F4#,
         13 => 16#80#, 14 => 16#35#, 15 => 16#0F#, 16 => 16#25#,
         17 => 16#E0#, 18 => 16#7E#, 19 => 16#21#, 20 => 16#C9#,
         21 => 16#47#, 22 => 16#D1#, 23 => 16#9E#, 24 => 16#33#,
         25 => 16#76#, 26 => 16#F0#, 27 => 16#9B#, 28 => 16#3C#,
         29 => 16#1E#, 30 => 16#16#, 31 => 16#17#, 32 => 16#42#];
      Base_Point : constant CryptoLib.Curve25519.Public_Key :=
        [1 => 9, others => 0];
      Bob_Public_High_Bit : CryptoLib.Curve25519.Public_Key := Bob_Public;
      Raw_Result : CryptoLib.Curve25519.Public_Key := [others => 0];
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := CryptoLib.Curve25519.Compute_Raw
        (Alice_Private, Base_Point, Raw_Result);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "RFC 7748 X25519 public key computes");
      Check (Raw_Result = Alice_Public,
             "RFC 7748 X25519 public key keeps little-endian byte order");

      Status_Value := CryptoLib.Curve25519.Compute_Raw
        (Alice_Private, Bob_Public, Raw_Result);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "RFC 7748 X25519 shared secret computes");
      Check (Raw_Result = Shared_Vector,
             "RFC 7748 X25519 shared secret keeps little-endian byte order");

      Bob_Public_High_Bit (32) :=
        Bob_Public_High_Bit (32) or Stream_Element'(16#80#);
      Status_Value := CryptoLib.Curve25519.Compute_Raw
        (Alice_Private, Bob_Public_High_Bit, Raw_Result);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "RFC 7748 X25519 high-bit peer key computes");
      Check (Raw_Result = Shared_Vector,
             "RFC 7748 X25519 masks peer u-coordinate high bit");

      Status_Value := CryptoLib.Curve25519.Compute_Raw
        (Alice_Private, [others => 0], Raw_Result);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "crypto primitives", "X25519 all-zero peer key fails closed");
      Check (Raw_Result = [Raw_Result'Range => 0],
             "X25519 failed raw compute clears shared-secret output");
   end Assert_Curve25519_RFC7748_Vectors;


   procedure Assert_Group14_Diffie_Hellman is
      Source_A : CryptoLib.Random.Random_Source;
      Source_B : CryptoLib.Random.Random_Source;
      Private_A : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Private_B : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Public_A  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Public_B  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Shared_AB : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Shared_BA : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Group1_Private : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Group1_Public  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Group1_Shared  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
      Pattern_A : constant Stream_Element_Array (1 .. 8) :=
        [16#11#, 16#23#, 16#35#, 16#47#, 16#59#, 16#6B#, 16#7D#, 16#8F#];
      Pattern_B : constant Stream_Element_Array (1 .. 8) :=
        [16#A1#, 16#B2#, 16#C3#, 16#D4#, 16#E5#, 16#F6#, 16#07#, 16#18#];
   begin
      CryptoLib.Random.Initialize_Deterministic (Source_A, Pattern_A);
      CryptoLib.Random.Initialize_Deterministic (Source_B, Pattern_B);

      Status_Value := CryptoLib.Diffie_Hellman.Generate_Group14_Keypair
        (Source_A, Private_A, Public_A);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "group14 DH key generation succeeds");
      Check (SSH_Lib.Protocol.Buffers.Length (Private_A) = 256
             and then SSH_Lib.Protocol.Buffers.Length (Public_A) > 0,
             "group14 key generation emits private scalar and public mpint");

      Status_Value := CryptoLib.Diffie_Hellman.Generate_Group14_Keypair
        (Source_B, Private_B, Public_B);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "group14 second DH key generation succeeds");

      Status_Value := CryptoLib.Diffie_Hellman.Compute_Group14_Shared_Secret
        (SSH_Lib.Protocol.Buffers.To_Array (Private_A),
         SSH_Lib.Protocol.Buffers.To_Array (Public_B),
         Shared_AB);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "group14 shared secret computes");
      Check (SSH_Lib.Protocol.Buffers.Length (Shared_AB) > 0,
             "group14 shared secret emits mpint output");

      Status_Value := CryptoLib.Diffie_Hellman.Compute_Group14_Shared_Secret
        (SSH_Lib.Protocol.Buffers.To_Array (Private_B),
         SSH_Lib.Protocol.Buffers.To_Array (Public_A),
         Shared_BA);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "group14 reverse shared secret computes");
      Check (SSH_Lib.Protocol.Buffers.To_Array (Shared_AB)
             = SSH_Lib.Protocol.Buffers.To_Array (Shared_BA),
             "group14 shared secrets match both directions");

      Status_Value := CryptoLib.Diffie_Hellman.Generate_Group1_Keypair
        (Source_A, Group1_Private, Group1_Public);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "group1 DH key generation succeeds");
      Check (SSH_Lib.Protocol.Buffers.Length (Group1_Private) = 256
             and then SSH_Lib.Protocol.Buffers.Length (Group1_Public) > 0,
             "group1 key generation emits private scalar and public mpint");

      Status_Value := CryptoLib.Diffie_Hellman.Compute_Group1_Shared_Secret
        (SSH_Lib.Protocol.Buffers.To_Array (Group1_Private),
         SSH_Lib.Protocol.Buffers.To_Array (Group1_Public),
         Group1_Shared);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "group1 shared secret computes");
      Check (SSH_Lib.Protocol.Buffers.Length (Group1_Shared) > 0,
             "group1 shared secret emits mpint output");
   end Assert_Group14_Diffie_Hellman;


   procedure Assert_ECDH_Nistp256_Diffie_Hellman is
      Source_A : CryptoLib.Random.Random_Source;
      Source_B : CryptoLib.Random.Random_Source;
      Private_A : Stream_Element_Array (1 .. 32) := [others => 0];
      Private_B : Stream_Element_Array (1 .. 32) := [others => 0];
      Public_A  : Stream_Element_Array (1 .. 65) := [others => 0];
      Public_B  : Stream_Element_Array (1 .. 65) := [others => 0];
      Shared_AB : Stream_Element_Array (1 .. 32) := [others => 16#AA#];
      Shared_BA : Stream_Element_Array (1 .. 32) := [others => 16#55#];
      Status_Value : CryptoLib.Errors.Status;
      Pattern_A : constant Stream_Element_Array (1 .. 8) :=
        [16#21#, 16#43#, 16#65#, 16#87#, 16#A9#, 16#CB#, 16#ED#, 16#0F#];
      Pattern_B : constant Stream_Element_Array (1 .. 8) :=
        [16#10#, 16#32#, 16#54#, 16#76#, 16#98#, 16#BA#, 16#DC#, 16#FE#];
   begin
      CryptoLib.Random.Initialize_Deterministic (Source_A, Pattern_A);
      CryptoLib.Random.Initialize_Deterministic (Source_B, Pattern_B);

      Status_Value := SSH_Lib.ECDSA.Generate_ECDH_Nistp256_Keypair
        (Source_A, Private_A, Public_A);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "NIST P-256 ECDH key generation succeeds");
      Check (Private_A /= [Private_A'Range => 0]
             and then Public_A (Public_A'First) = 16#04#,
             "NIST P-256 ECDH key generation emits private scalar and raw public point");

      Status_Value := SSH_Lib.ECDSA.Generate_ECDH_Nistp256_Keypair
        (Source_B, Private_B, Public_B);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "second NIST P-256 ECDH key generation succeeds");

      Status_Value := SSH_Lib.ECDSA.Compute_ECDH_Nistp256_Shared_Secret
        (Private_A, Public_B, Shared_AB);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "NIST P-256 ECDH shared secret computes");

      Status_Value := SSH_Lib.ECDSA.Compute_ECDH_Nistp256_Shared_Secret
        (Private_B, Public_A, Shared_BA);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "NIST P-256 ECDH peer shared secret computes");
      Check (Shared_AB = Shared_BA and then Shared_AB /= [Shared_AB'Range => 0],
             "NIST P-256 ECDH shared secrets match and are nonzero");
   end Assert_ECDH_Nistp256_Diffie_Hellman;

   procedure Assert_ECDH_Nistp384_Nistp521_Basepoints is
      Private_P384 : constant Stream_Element_Array (1 .. 48) :=
        [1 .. 47 => 0, 48 => 1];
      Base_P384 : constant Stream_Element_Array :=
        Hex_To_Bytes
          ("04"
           & "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"
           & "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F");
      Public_Blob_P384 : constant Stream_Element_Array :=
        Hex_To_Bytes
          ("0000001365636473612D736861322D6E69737470333834"
           & "000000086E69737470333834"
           & "00000061"
           & "04"
           & "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"
           & "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F");
      Expected_P384_X : constant Stream_Element_Array :=
        Hex_To_Bytes
          ("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7");
      Shared_P384 : Stream_Element_Array (1 .. 48) := [others => 16#AA#];
      Signature_P384 : CryptoLib.Buffers.Packet_Buffer;

      Private_P521 : constant Stream_Element_Array (1 .. 66) :=
        [1 .. 65 => 0, 66 => 1];
      Base_P521 : constant Stream_Element_Array :=
        Hex_To_Bytes
          ("04"
           & "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F"
           & "828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C"
           & "1856A429BF97E7E31C2E5BD66"
           & "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817"
           & "AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A"
           & "272C24088BE94769FD16650");
      Public_Blob_P521 : constant Stream_Element_Array :=
        Hex_To_Bytes
          ("0000001365636473612D736861322D6E69737470353231"
           & "000000086E69737470353231"
           & "00000085"
           & "04"
           & "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F"
           & "828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C"
           & "1856A429BF97E7E31C2E5BD66"
           & "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817"
           & "AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A"
           & "272C24088BE94769FD16650");
      Expected_P521_X : constant Stream_Element_Array :=
        Hex_To_Bytes
          ("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F"
           & "828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C"
           & "1856A429BF97E7E31C2E5BD66");
      Shared_P521 : Stream_Element_Array (1 .. 66) := [others => 16#55#];
      Signature_P521 : CryptoLib.Buffers.Packet_Buffer;
      Short_Point : constant Stream_Element_Array (1 .. 2) := [16#04#, 0];
   begin
      Check (Base_P384'Length = 97, "NIST P-384 base point fixture length");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.ECDSA.Validate_Raw_Point_Nistp384 (Base_P384),
         CryptoLib.Errors.Ok,
         "crypto primitives", "NIST P-384 base point validates");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.ECDSA.Compute_ECDH_Nistp384_Shared_Secret
           (Private_P384, Base_P384, Shared_P384),
         CryptoLib.Errors.Ok,
         "crypto primitives", "NIST P-384 scalar-one ECDH computes");
      Check (Shared_P384 = Expected_P384_X,
             "NIST P-384 scalar-one ECDH returns base X coordinate");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.ECDSA.Public_Matches_Private_Nistp384
           (Public_Blob_P384, [1 => 1]),
         CryptoLib.Errors.Ok,
         "crypto primitives", "NIST P-384 public key matches scalar one");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.ECDSA.Sign_Nistp384
           ([1 => 1], ECDSA_Message, Signature_P384),
         CryptoLib.Errors.Ok,
         "crypto primitives", "NIST P-384 local signing succeeds");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.ECDSA.Verify_Nistp384
           (Public_Blob_P384,
            CryptoLib.Buffers.To_Array (Signature_P384),
            ECDSA_Message),
         CryptoLib.Errors.Ok,
         "crypto primitives", "NIST P-384 generated signature verifies");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.ECDSA.Validate_Raw_Point_Nistp384 (Short_Point),
         CryptoLib.Errors.Handshake_Failed,
         "crypto primitives", "NIST P-384 short point is rejected");

      Check (Base_P521'Length = 133, "NIST P-521 base point fixture length");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.ECDSA.Validate_Raw_Point_Nistp521 (Base_P521),
         CryptoLib.Errors.Ok,
         "crypto primitives", "NIST P-521 base point validates");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.ECDSA.Compute_ECDH_Nistp521_Shared_Secret
           (Private_P521, Base_P521, Shared_P521),
         CryptoLib.Errors.Ok,
         "crypto primitives", "NIST P-521 scalar-one ECDH computes");
      Check (Shared_P521 = Expected_P521_X,
             "NIST P-521 scalar-one ECDH returns base X coordinate");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.ECDSA.Public_Matches_Private_Nistp521
           (Public_Blob_P521, [1 => 1]),
         CryptoLib.Errors.Ok,
         "crypto primitives", "NIST P-521 public key matches scalar one");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.ECDSA.Sign_Nistp521
           ([1 => 1], ECDSA_Message, Signature_P521),
         CryptoLib.Errors.Ok,
         "crypto primitives", "NIST P-521 local signing succeeds");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.ECDSA.Verify_Nistp521
           (Public_Blob_P521,
            CryptoLib.Buffers.To_Array (Signature_P521),
            ECDSA_Message),
         CryptoLib.Errors.Ok,
         "crypto primitives", "NIST P-521 generated signature verifies");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.ECDSA.Validate_Raw_Point_Nistp521 (Short_Point),
         CryptoLib.Errors.Handshake_Failed,
         "crypto primitives", "NIST P-521 short point is rejected");
   end Assert_ECDH_Nistp384_Nistp521_Basepoints;

   procedure Assert_RSA_SHA2_256_Verification is
      Mutated_Signature : Stream_Element_Array := RSA_Signature;
      Mutated_Message   : Stream_Element_Array := RSA_Message;
   begin
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.RSA.Validate_Public_Key_Blob (RSA_Public_Blob),
         CryptoLib.Errors.Ok,
         "crypto primitives", "RSA SHA-256 public key blob validates");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Signatures.Verify
           ("rsa-sha2-256", RSA_Public_Blob, RSA_Signature, RSA_Message),
         CryptoLib.Errors.Ok,
         "crypto primitives", "RSA SHA-256 PKCS1v15 signature verifies");

      Mutated_Signature (Mutated_Signature'Last) :=
        Mutated_Signature (Mutated_Signature'Last) xor 16#01#;
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Signatures.Verify
           ("rsa-sha2-256", RSA_Public_Blob, Mutated_Signature, RSA_Message),
         CryptoLib.Errors.Handshake_Failed,
         "crypto primitives", "mutated RSA signature is rejected");

      Mutated_Message (Mutated_Message'First) :=
        Mutated_Message (Mutated_Message'First) xor 16#01#;
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Signatures.Verify
           ("rsa-sha2-256", RSA_Public_Blob, RSA_Signature, Mutated_Message),
         CryptoLib.Errors.Handshake_Failed,
         "crypto primitives", "mutated RSA signed message is rejected");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Signatures.Verify
           ("rsa-sha2-512", RSA_Public_Blob, RSA_Signature, RSA_Message),
         CryptoLib.Errors.Handshake_Failed,
         "crypto primitives", "RSA SHA-512 rejects a SHA-256 fixture signature");
   end Assert_RSA_SHA2_256_Verification;



   procedure Assert_RSA_SHA2_512_Verification is
      Mutated_Signature : Stream_Element_Array := RSA_SHA512_Signature;
      Mutated_Message   : Stream_Element_Array := RSA_SHA512_Message;
   begin
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.RSA.Validate_Public_Key_Blob (RSA_SHA512_Public_Blob),
         CryptoLib.Errors.Ok,
         "crypto primitives", "RSA SHA-512 public key blob validates");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Signatures.Verify
           ("rsa-sha2-512", RSA_SHA512_Public_Blob,
            RSA_SHA512_Signature, RSA_SHA512_Message),
         CryptoLib.Errors.Ok,
         "crypto primitives", "RSA SHA-512 PKCS1v15 signature verifies");

      Mutated_Signature (Mutated_Signature'Last) :=
        Mutated_Signature (Mutated_Signature'Last) xor 16#01#;
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Signatures.Verify
           ("rsa-sha2-512", RSA_SHA512_Public_Blob,
            Mutated_Signature, RSA_SHA512_Message),
         CryptoLib.Errors.Handshake_Failed,
         "crypto primitives", "mutated RSA SHA-512 signature is rejected");

      Mutated_Message (Mutated_Message'First) :=
        Mutated_Message (Mutated_Message'First) xor 16#01#;
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Signatures.Verify
           ("rsa-sha2-512", RSA_SHA512_Public_Blob,
            RSA_SHA512_Signature, Mutated_Message),
         CryptoLib.Errors.Handshake_Failed,
         "crypto primitives", "mutated RSA SHA-512 signed message is rejected");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Signatures.Verify
           ("rsa-sha2-256", RSA_SHA512_Public_Blob,
            RSA_SHA512_Signature, RSA_SHA512_Message),
         CryptoLib.Errors.Handshake_Failed,
         "crypto primitives", "RSA SHA-256 rejects a SHA-512 fixture signature");
   end Assert_RSA_SHA2_512_Verification;


   procedure Assert_Ed25519_Verification is
      Mutated_Signature : Stream_Element_Array := Ed25519_Signature;
      Mutated_Message   : Stream_Element_Array := Ed25519_Message;
      Generated_Signature : Stream_Element_Array (1 .. 64);
   begin
      SSH_Lib.Tests.Assertions.Check_Status
        (CryptoLib.Ed25519.Sign
           (Ed25519_Seed, Ed25519_Public_Key,
            Ed25519_Message, Generated_Signature),
         CryptoLib.Errors.Ok,
         "crypto primitives", "Ed25519 RFC 8032 seed signs");
      Check (Generated_Signature = Ed25519_Signature,
             "Ed25519 RFC 8032 generated signature matches vector");
      SSH_Lib.Tests.Assertions.Check_Status
        (CryptoLib.Ed25519.Verify
           (Ed25519_Public_Key, Generated_Signature, Ed25519_Message),
         CryptoLib.Errors.Ok,
         "crypto primitives", "generated Ed25519 RFC 8032 signature verifies");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Signatures.Verify
           ("ssh-ed25519", Ed25519_Public_Blob,
            Ed25519_Signature, Ed25519_Message),
         CryptoLib.Errors.Ok,
         "crypto primitives", "Ed25519 RFC 8032 signature verifies");

      Mutated_Signature (Mutated_Signature'Last) :=
        Mutated_Signature (Mutated_Signature'Last) xor 16#01#;
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Signatures.Verify
           ("ssh-ed25519", Ed25519_Public_Blob,
            Mutated_Signature, Ed25519_Message),
         CryptoLib.Errors.Handshake_Failed,
         "crypto primitives", "mutated Ed25519 signature is rejected");

      Mutated_Message (Mutated_Message'First) :=
        Mutated_Message (Mutated_Message'First) xor 16#01#;
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Signatures.Verify
           ("ssh-ed25519", Ed25519_Public_Blob,
            Ed25519_Signature, Mutated_Message),
         CryptoLib.Errors.Handshake_Failed,
         "crypto primitives", "mutated Ed25519 signed message is rejected");
   end Assert_Ed25519_Verification;


   procedure Assert_ECDSA_Nistp256_Verification is
      Mutated_Signature : Stream_Element_Array := ECDSA_Signature;
      Mutated_Message   : Stream_Element_Array := ECDSA_Message;
      Generated_Signature : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   begin
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.ECDSA.Validate_Public_Nistp256 (ECDSA_Public_Blob),
         CryptoLib.Errors.Ok,
         "crypto primitives", "ECDSA P-256 public key blob validates");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.ECDSA.Validate_Signature_Nistp256 (ECDSA_Signature),
         CryptoLib.Errors.Ok,
         "crypto primitives", "ECDSA P-256 signature blob validates");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Signatures.Verify
           ("ecdsa-sha2-nistp256", ECDSA_Public_Blob,
            ECDSA_Signature, ECDSA_Message),
         CryptoLib.Errors.Ok,
         "crypto primitives", "ECDSA P-256 signature verifies");

      Mutated_Signature (Mutated_Signature'Last) :=
        Mutated_Signature (Mutated_Signature'Last) xor 16#01#;
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Signatures.Verify
           ("ecdsa-sha2-nistp256", ECDSA_Public_Blob,
            Mutated_Signature, ECDSA_Message),
         CryptoLib.Errors.Handshake_Failed,
         "crypto primitives", "mutated ECDSA P-256 signature is rejected");

      Mutated_Message (Mutated_Message'First) :=
        Mutated_Message (Mutated_Message'First) xor 16#01#;
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Signatures.Verify
           ("ecdsa-sha2-nistp256", ECDSA_Public_Blob,
            ECDSA_Signature, Mutated_Message),
         CryptoLib.Errors.Handshake_Failed,
         "crypto primitives", "mutated ECDSA P-256 message is rejected");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.ECDSA.Public_Matches_Private_Nistp256
           (ECDSA_Public_Blob, ECDSA_Private_Scalar_Mpint),
         CryptoLib.Errors.Ok,
         "crypto primitives", "ECDSA P-256 public key matches private scalar");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.ECDSA.Sign_Nistp256
           (ECDSA_Private_Scalar_Mpint, ECDSA_Message, Generated_Signature),
         CryptoLib.Errors.Ok,
         "crypto primitives", "ECDSA P-256 private scalar signs");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.ECDSA.Verify_Nistp256
           (ECDSA_Public_Blob,
            SSH_Lib.Protocol.Buffers.To_Array (Generated_Signature),
            ECDSA_Message),
         CryptoLib.Errors.Ok,
         "crypto primitives", "generated ECDSA P-256 signature verifies");
   end Assert_ECDSA_Nistp256_Verification;

   procedure Assert_AES_CTR_Cipher is
      Key_Data : constant Stream_Element_Array (1 .. 16) :=
        [16#2B#, 16#7E#, 16#15#, 16#16#, 16#28#, 16#AE#, 16#D2#, 16#A6#,
         16#AB#, 16#F7#, 16#15#, 16#88#, 16#09#, 16#CF#, 16#4F#, 16#3C#];
      IV_Data : constant Stream_Element_Array (1 .. 16) :=
        [16#F0#, 16#F1#, 16#F2#, 16#F3#, 16#F4#, 16#F5#, 16#F6#, 16#F7#,
         16#F8#, 16#F9#, 16#FA#, 16#FB#, 16#FC#, 16#FD#, 16#FE#, 16#FF#];
      Plaintext : constant Stream_Element_Array (1 .. 16) :=
        [16#6B#, 16#C1#, 16#BE#, 16#E2#, 16#2E#, 16#40#, 16#9F#, 16#96#,
         16#E9#, 16#3D#, 16#7E#, 16#11#, 16#73#, 16#93#, 16#17#, 16#2A#];
      Ciphertext : constant Stream_Element_Array (1 .. 16) :=
        [16#87#, 16#4D#, 16#61#, 16#91#, 16#B6#, 16#20#, 16#E3#, 16#26#,
         16#1B#, 16#EF#, 16#68#, 16#64#, 16#99#, 16#0D#, 16#B6#, 16#CE#];
      Cipher_Item : CryptoLib.Ciphers.Cipher_State;
      Output_Data : Stream_Element_Array (1 .. 16);
      Status_Value : CryptoLib.Errors.Status;
   begin
      CryptoLib.Ciphers.Reset (Cipher_Item);
      Status_Value := CryptoLib.Ciphers.Initialize
        (Cipher_Item, "aes128-ctr", CryptoLib.Ciphers.Client_To_Server,
         Key_Data, IV_Data);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "AES-128-CTR initializes");
      Check (CryptoLib.Ciphers.Is_Active (Cipher_Item),
             "AES-128-CTR cipher state is active");

      Status_Value := CryptoLib.Ciphers.Encrypt
        (Cipher_Item, Plaintext, Output_Data);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "AES-128-CTR known-vector encrypt succeeds");
      Check (Output_Data = Ciphertext,
             "AES-128-CTR known-vector ciphertext matches NIST SP 800-38A F.5.1");

      CryptoLib.Ciphers.Reset (Cipher_Item);
      Status_Value := CryptoLib.Ciphers.Initialize
        (Cipher_Item, "aes128-ctr", CryptoLib.Ciphers.Server_To_Client,
         Key_Data, IV_Data);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "AES-128-CTR decrypt state initializes");
      Status_Value := CryptoLib.Ciphers.Decrypt
        (Cipher_Item, Ciphertext, Output_Data);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "AES-128-CTR known-vector decrypt succeeds");
      Check (Output_Data = Plaintext,
             "AES-128-CTR known-vector plaintext restored");

      declare
         Two_Block_Plaintext : constant Stream_Element_Array (1 .. 32) :=
           [16#6B#, 16#C1#, 16#BE#, 16#E2#, 16#2E#, 16#40#, 16#9F#, 16#96#,
            16#E9#, 16#3D#, 16#7E#, 16#11#, 16#73#, 16#93#, 16#17#, 16#2A#,
            16#AE#, 16#2D#, 16#8A#, 16#57#, 16#1E#, 16#03#, 16#AC#, 16#9C#,
            16#9E#, 16#B7#, 16#6F#, 16#AC#, 16#45#, 16#AF#, 16#8E#, 16#51#];
         Two_Block_Ciphertext : constant Stream_Element_Array (1 .. 32) :=
           [16#87#, 16#4D#, 16#61#, 16#91#, 16#B6#, 16#20#, 16#E3#, 16#26#,
            16#1B#, 16#EF#, 16#68#, 16#64#, 16#99#, 16#0D#, 16#B6#, 16#CE#,
            16#98#, 16#06#, 16#F6#, 16#6B#, 16#79#, 16#70#, 16#FD#, 16#FF#,
            16#86#, 16#17#, 16#18#, 16#7B#, 16#B9#, 16#FF#, 16#FD#, 16#FF#];
         Segmented_Output : Stream_Element_Array (1 .. 32) := [others => 0];
      begin
         CryptoLib.Ciphers.Reset (Cipher_Item);
         Status_Value := CryptoLib.Ciphers.Initialize
           (Cipher_Item, "aes128-ctr", CryptoLib.Ciphers.Server_To_Client,
            Key_Data, IV_Data);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "crypto primitives", "AES-128-CTR segmented decrypt initializes");
         Status_Value := CryptoLib.Ciphers.Decrypt
           (Cipher_Item, Two_Block_Ciphertext (1 .. 4), Segmented_Output (1 .. 4));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "crypto primitives", "AES-128-CTR packet-length segment decrypts");
         Status_Value := CryptoLib.Ciphers.Decrypt
           (Cipher_Item, Two_Block_Ciphertext (5 .. 32), Segmented_Output (5 .. 32));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "crypto primitives", "AES-128-CTR packet-body segment decrypts");
         Check (Segmented_Output = Two_Block_Plaintext,
                "AES-128-CTR segmented decrypt preserves keystream position");

         CryptoLib.Ciphers.Reset (Cipher_Item);
         Status_Value := CryptoLib.Ciphers.Initialize
           (Cipher_Item, "aes128-ctr", CryptoLib.Ciphers.Client_To_Server,
            Key_Data, IV_Data);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "crypto primitives", "AES-128-CTR segmented encrypt initializes");
         Segmented_Output := [others => 0];
         Status_Value := CryptoLib.Ciphers.Encrypt
           (Cipher_Item, Two_Block_Plaintext (1 .. 4), Segmented_Output (1 .. 4));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "crypto primitives", "AES-128-CTR packet-length segment encrypts");
         Status_Value := CryptoLib.Ciphers.Encrypt
           (Cipher_Item, Two_Block_Plaintext (5 .. 32), Segmented_Output (5 .. 32));
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "crypto primitives", "AES-128-CTR packet-body segment encrypts");
         Check (Segmented_Output = Two_Block_Ciphertext,
                "AES-128-CTR segmented encrypt preserves keystream position");
      end;

      declare
         CBC_IV : constant Stream_Element_Array (1 .. 16) :=
           [16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
            16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#];
         CBC_Ciphertext : constant Stream_Element_Array (1 .. 16) :=
           [16#76#, 16#49#, 16#AB#, 16#AC#, 16#81#, 16#19#, 16#B2#, 16#46#,
            16#CE#, 16#E9#, 16#8E#, 16#9B#, 16#12#, 16#E9#, 16#19#, 16#7D#];
      begin
         CryptoLib.Ciphers.Reset (Cipher_Item);
         Status_Value := CryptoLib.Ciphers.Initialize
           (Cipher_Item, "aes128-cbc", CryptoLib.Ciphers.Client_To_Server,
            Key_Data, CBC_IV);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "crypto primitives", "AES-128-CBC initializes");
         Status_Value := CryptoLib.Ciphers.Encrypt
           (Cipher_Item, Plaintext, Output_Data);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "crypto primitives", "AES-128-CBC known-vector encrypt succeeds");
         Check (Output_Data = CBC_Ciphertext,
                "AES-128-CBC known-vector ciphertext matches NIST SP 800-38A F.2.1");

         CryptoLib.Ciphers.Reset (Cipher_Item);
         Status_Value := CryptoLib.Ciphers.Initialize
           (Cipher_Item, "aes128-cbc", CryptoLib.Ciphers.Server_To_Client,
            Key_Data, CBC_IV);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "crypto primitives", "AES-128-CBC decrypt state initializes");
         Status_Value := CryptoLib.Ciphers.Decrypt
           (Cipher_Item, CBC_Ciphertext, Output_Data);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "crypto primitives", "AES-128-CBC known-vector decrypt succeeds");
         Check (Output_Data = Plaintext,
                "AES-128-CBC known-vector plaintext restored");
      end;

      declare
         DES3_Key : constant Stream_Element_Array (1 .. 24) :=
           [16#01#, 16#23#, 16#45#, 16#67#, 16#89#, 16#AB#, 16#CD#, 16#EF#,
            16#FE#, 16#DC#, 16#BA#, 16#98#, 16#76#, 16#54#, 16#32#, 16#10#,
            16#89#, 16#AB#, 16#CD#, 16#EF#, 16#01#, 16#23#, 16#45#, 16#67#];
         DES3_IV : constant Stream_Element_Array (1 .. 8) :=
           [16#12#, 16#34#, 16#56#, 16#78#, 16#90#, 16#AB#, 16#CD#, 16#EF#];
         DES3_Ciphertext : constant Stream_Element_Array (1 .. 8) :=
           [16#20#, 16#40#, 16#11#, 16#F9#, 16#86#, 16#E3#, 16#56#, 16#47#];
         DES3_Plaintext : constant Stream_Element_Array (1 .. 8) :=
           [16#4E#, 16#6F#, 16#77#, 16#20#, 16#69#, 16#73#, 16#20#, 16#74#];
         DES3_Output : Stream_Element_Array (1 .. 8) := [others => 0];
      begin
         Status_Value := CryptoLib.Ciphers.Decrypt_CBC_Raw
           ("3des-cbc", DES3_Key, DES3_IV, DES3_Ciphertext, DES3_Output);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "crypto primitives", "3DES-CBC raw decrypt succeeds for encrypted key files");
         Check (DES3_Output = DES3_Plaintext,
                "3DES-CBC raw decrypt restores OpenSSL known-vector plaintext");

         CryptoLib.Ciphers.Reset (Cipher_Item);
         Status_Value := CryptoLib.Ciphers.Initialize
           (Cipher_Item, "3des-cbc", CryptoLib.Ciphers.Client_To_Server,
            DES3_Key, DES3_IV);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "crypto primitives", "3DES-CBC transport encrypt state initializes");
         DES3_Output := [others => 0];
         Status_Value := CryptoLib.Ciphers.Encrypt
           (Cipher_Item, DES3_Plaintext, DES3_Output);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "crypto primitives", "3DES-CBC transport encrypt succeeds");
         Check (DES3_Output = DES3_Ciphertext,
                "3DES-CBC transport encrypt matches OpenSSL known-vector ciphertext");

         CryptoLib.Ciphers.Reset (Cipher_Item);
         Status_Value := CryptoLib.Ciphers.Initialize
           (Cipher_Item, "3des-cbc", CryptoLib.Ciphers.Server_To_Client,
            DES3_Key, DES3_IV);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "crypto primitives", "3DES-CBC transport decrypt state initializes");
         DES3_Output := [others => 0];
         Status_Value := CryptoLib.Ciphers.Decrypt
           (Cipher_Item, DES3_Ciphertext, DES3_Output);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "crypto primitives", "3DES-CBC transport decrypt succeeds");
         Check (DES3_Output = DES3_Plaintext,
                "3DES-CBC transport decrypt restores known-vector plaintext");
      end;

      Status_Value := CryptoLib.Ciphers.Initialize
        (Cipher_Item, "blowfish-cbc", CryptoLib.Ciphers.Client_To_Server,
         Key_Data, IV_Data);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "crypto primitives", "legacy unsupported cipher is rejected");
   end Assert_AES_CTR_Cipher;


   procedure Assert_MLKEM768_Core_Arithmetic is
      use CryptoLib.MLKEM768_Core;
      Zero_Poly       : constant Polynomial := [others => 0];
      X_Poly          : Polynomial := [others => 0];
      High_Left       : Polynomial := [others => 0];
      High_Right      : Polynomial := [others => 0];
      Product         : Polynomial;
      Roundtrip       : Polynomial;
      Encoded         : Encoded_Poly_12;
      Sum_Value       : Polynomial;
      Difference_Value : Polynomial;
      Rho             : MLKEM_Public_Seed := [others => 0];
      Sigma           : constant MLKEM_Noise_Seed := [others => 16#11#];
      Coins           : constant MLKEM_Noise_Seed := [others => 16#22#];
      Public_Item     : PKE_Public_Key;
      Secret_Item     : PKE_Secret_Key;
      Ciphertext_Item : PKE_Ciphertext;
      Message         : MLKEM_Message := [others => 0];
      Decrypted       : MLKEM_Message;
   begin
      X_Poly (1) := 1;
      Product := Ring_Multiply_Reference (X_Poly, X_Poly);
      Check (Product (2) = 1,
             "ML-KEM reference ring multiply maps x*x to x^2");
      Check (Product (0) = 0 and then Product (1) = 0,
             "ML-KEM reference ring multiply leaves unrelated low terms zero");

      High_Left (200) := 1;
      High_Right (100) := 1;
      Product := Ring_Multiply_Reference (High_Left, High_Right);
      Check (Product (44) = Q_Value - 1,
             "ML-KEM reference ring multiply reduces x^300 to -x^44");

      Encoded := Encode_12 (Product);
      Roundtrip := Decode_12 (Encoded);
      Check (Roundtrip (44) = Product (44),
             "ML-KEM 12-bit polynomial encoding preserves reduced coefficient");

      Sum_Value := Add (Product, X_Poly);
      Difference_Value := Subtract (Sum_Value, X_Poly);
      Check (Difference_Value (44) = Product (44),
             "ML-KEM add/subtract helpers preserve ring value");

      Check (NTT (Zero_Poly) = Zero_Poly,
             "ML-KEM NTT maps zero polynomial to zero");
      Check (Inverse_NTT (Zero_Poly) = Zero_Poly,
             "ML-KEM inverse NTT maps zero polynomial to zero");

      Rho (1) := 16#42#;
      Message (1) := 16#A5#;
      PKE_Keygen_From_Seeds (Rho, Sigma, Public_Item, Secret_Item);
      PKE_Encrypt_Deterministic (Public_Item, Message, Coins, Ciphertext_Item);
      Decrypted := PKE_Decrypt (Secret_Item, Ciphertext_Item);
      Check (Public_Item'Length = 1184 and then Secret_Item'Length = 1152,
             "ML-KEM CPA-PKE key material uses FIPS 203 byte lengths");
      Check (Ciphertext_Item'Length = 1088,
             "ML-KEM CPA-PKE ciphertext uses FIPS 203 byte length");
      Check (Poly_To_Message (Message_To_Poly (Message)) = Message,
             "ML-KEM message polynomial conversion round-trips exactly");
      Check (Decrypted'Length = Message'Length,
             "ML-KEM CPA-PKE decrypt returns a 32-byte message boundary");
   end Assert_MLKEM768_Core_Arithmetic;


   procedure Assert_MLKEM768_CCA_KEM is
      use CryptoLib.MLKEM768;
      Pattern         : Stream_Element_Array (1 .. 96) := [others => 0];
      Source_Item     : CryptoLib.Random.Random_Source;
      Enc_Source      : CryptoLib.Random.Random_Source;
      Public_Item     : Public_Key;
      Secret_Item     : Secret_Key;
      Ciphertext_Item : Ciphertext;
      Mutated         : Ciphertext;
      Shared_Left     : Shared_Key;
      Shared_Right    : Shared_Key;
      Shared_Bad      : Shared_Key;
      Status_Value    : CryptoLib.Errors.Status;
   begin
      for Index_Value in Pattern'Range loop
         Pattern (Index_Value) := Stream_Element ((Index_Value * 17 + 29) mod 256);
      end loop;

      CryptoLib.Random.Initialize_Deterministic (Source_Item, Pattern);
      Status_Value := Generate_Keypair (Source_Item, Public_Item, Secret_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "ML-KEM-768 CCA keygen succeeds");
      Check (Public_Item'Length = Public_Key_Length,
             "ML-KEM-768 public key uses FIPS 203 byte length");
      Check (Secret_Item'Length = Secret_Key_Length,
             "ML-KEM-768 secret key uses FIPS 203 byte layout length");

      CryptoLib.Random.Initialize_Deterministic (Enc_Source, Pattern);
      Status_Value := Encapsulate
        (Enc_Source, Public_Item, Ciphertext_Item, Shared_Left);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "ML-KEM-768 CCA encapsulation succeeds");
      Check (Ciphertext_Item'Length = Ciphertext_Length,
             "ML-KEM-768 ciphertext uses FIPS 203 byte length");

      Status_Value := Decapsulate (Secret_Item, Ciphertext_Item, Shared_Right);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "ML-KEM-768 CCA decapsulation succeeds");
      Check (Shared_Left = Shared_Right,
             "ML-KEM-768 CCA encapsulated and decapsulated shared secrets match");

      Mutated := Ciphertext_Item;
      Mutated (Mutated'Last) := Mutated (Mutated'Last) xor 16#01#;
      Status_Value := Decapsulate (Secret_Item, Mutated, Shared_Bad);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "ML-KEM-768 CCA decapsulation handles invalid ciphertext");
      Check (Shared_Bad /= Shared_Right,
             "ML-KEM-768 CCA invalid ciphertext uses z fallback KDF input");
   end Assert_MLKEM768_CCA_KEM;

   procedure Assert_SNTRUP761_KEM_Boundary is
      use CryptoLib.SNTRUP761;
      Pattern         : Stream_Element_Array (1 .. 96) := [others => 0];
      Source_Item     : CryptoLib.Random.Random_Source;
      Enc_Source      : CryptoLib.Random.Random_Source;
      Public_Item     : Public_Key;
      Secret_Item     : Secret_Key;
      Ciphertext_Item : Ciphertext;
      Mutated_Item    : Ciphertext;
      Shared_Left     : Shared_Key;
      Shared_Right    : Shared_Key;
      Shared_Bad      : Shared_Key;
      Status_Value    : CryptoLib.Errors.Status;
   begin
      for Index_Value in Pattern'Range loop
         Pattern (Index_Value) := Stream_Element ((Index_Value * 19 + 7) mod 256);
      end loop;

      CryptoLib.Random.Initialize_Deterministic (Source_Item, Pattern);
      CryptoLib.Random.Initialize_Deterministic (Enc_Source, Pattern);

      Status_Value := Generate_Keypair (Source_Item, Public_Item, Secret_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "SNTRUP761 KEM keypair generation succeeds");
      Check (Public_Item'Length = Public_Key_Length and then Secret_Item'Length = Secret_Key_Length,
             "SNTRUP761 KEM uses OpenSSH public/secret key sizes");

      Status_Value := Encapsulate (Enc_Source, Public_Item, Ciphertext_Item, Shared_Left);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "SNTRUP761 KEM encapsulation succeeds");
      Check (Ciphertext_Item'Length = Ciphertext_Length,
             "SNTRUP761 KEM ciphertext uses OpenSSH byte length");

      Status_Value := Decapsulate (Secret_Item, Ciphertext_Item, Shared_Right);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "SNTRUP761 KEM decapsulation succeeds");
      Check (Shared_Left = Shared_Right,
             "SNTRUP761 KEM encapsulated and decapsulated shared secrets match");

      Mutated_Item := Ciphertext_Item;
      Mutated_Item (Mutated_Item'Last) := Mutated_Item (Mutated_Item'Last) xor 16#01#;
      Status_Value := Decapsulate (Secret_Item, Mutated_Item, Shared_Bad);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "crypto primitives", "SNTRUP761 KEM handles invalid ciphertext");
      Check (Shared_Bad /= Shared_Right,
             "SNTRUP761 KEM invalid ciphertext uses fallback secret");
   end Assert_SNTRUP761_KEM_Boundary;


   procedure Assert_Crypto_Primitives is
   begin
      Assert_AES_CTR_Cipher;
      Assert_Curve25519_RFC7748_Vectors;
      Assert_Group14_Diffie_Hellman;
      Assert_ECDH_Nistp256_Diffie_Hellman;
      Assert_ECDH_Nistp384_Nistp521_Basepoints;
      Assert_RSA_SHA2_256_Verification;
      Assert_RSA_SHA2_512_Verification;
      Assert_Ed25519_Verification;
      Assert_ECDSA_Nistp256_Verification;
      Assert_MLKEM768_Core_Arithmetic;
      Assert_MLKEM768_CCA_KEM;
      Assert_SNTRUP761_KEM_Boundary;
   end Assert_Crypto_Primitives;
end SSH_Lib.Tests.Fixtures.Crypto_Primitives;
