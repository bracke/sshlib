with Ada.Streams;
with Ada.Text_IO;
with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Negative_Tests;
with SSH_Lib.Protocol.Packets;
with SSH_Lib.Protocol.Protected_Packets;
with SSH_Lib.Protocol.Protected_Packets.Test_Support;

procedure Test_Packet_Protection_Negative is
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use type Interfaces.Unsigned_32;
   use type CryptoLib.Errors.Status;

   Key_Data : constant Ada.Streams.Stream_Element_Array (1 .. 32) :=
     [1 => 16#00#, 2 => 16#01#, 3 => 16#02#, 4 => 16#03#,
      5 => 16#04#, 6 => 16#05#, 7 => 16#06#, 8 => 16#07#,
      9 => 16#08#, 10 => 16#09#, 11 => 16#0A#, 12 => 16#0B#,
      13 => 16#0C#, 14 => 16#0D#, 15 => 16#0E#, 16 => 16#0F#,
      17 => 16#10#, 18 => 16#11#, 19 => 16#12#, 20 => 16#13#,
      21 => 16#14#, 22 => 16#15#, 23 => 16#16#, 24 => 16#17#,
      25 => 16#18#, 26 => 16#19#, 27 => 16#1A#, 28 => 16#1B#,
      29 => 16#1C#, 30 => 16#1D#, 31 => 16#1E#, 32 => 16#1F#];

   Payload_Data : constant Ada.Streams.Stream_Element_Array (1 .. 6) :=
     [1 => 16#00#, 2 => 16#0A#, 3 => 16#0D#,
      4 => 16#7F#, 5 => 16#80#, 6 => 16#FF#];

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   procedure Check_Status
     (Actual_Status   : CryptoLib.Errors.Status;
      Expected_Status : CryptoLib.Errors.Status;
      Label_Text      : String) is
   begin
      Check (Actual_Status = Expected_Status, Label_Text);
   end Check_Status;

   procedure Check_Matrix_Mappings is
      type Case_Array is array (Positive range <>) of
        SSH_Lib.Protocol.Negative_Tests.Negative_Case;
      Cases : constant Case_Array :=
        [SSH_Lib.Protocol.Negative_Tests.Bad_Mac,
         SSH_Lib.Protocol.Negative_Tests.Wrong_Sequence_Mac,
         SSH_Lib.Protocol.Negative_Tests.Truncated_Encrypted_Packet,
         SSH_Lib.Protocol.Negative_Tests.Oversized_Packet,
         SSH_Lib.Protocol.Negative_Tests.Invalid_Padding_Length,
         SSH_Lib.Protocol.Negative_Tests.Packet_After_Dirty_State,
         SSH_Lib.Protocol.Negative_Tests.Sequence_Number_Not_Incremented_Once,
         SSH_Lib.Protocol.Negative_Tests.Packet_Length_Before_Allocation,
         SSH_Lib.Protocol.Negative_Tests.Padding_Length_Exceeds_Packet,
         SSH_Lib.Protocol.Negative_Tests.Mac_Failure_Dirties_Session];
   begin
      for Case_Item of Cases loop
         Check_Status
           (SSH_Lib.Protocol.Negative_Tests.Expected_Status (Case_Item),
            CryptoLib.Errors.Handshake_Failed,
            "packet-protection mapping: " &
            SSH_Lib.Protocol.Negative_Tests.Case_Label (Case_Item));
      end loop;
   end Check_Matrix_Mappings;

   procedure Check_Round_Trip_And_Sequences is
      Encode_State : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Decode_State : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Packet_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Payload_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Result_Status : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Protected_Packets.Reset (Encode_State, Key_Data);
      SSH_Lib.Protocol.Protected_Packets.Reset (Decode_State, Key_Data);

      Result_Status := SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
        (Encode_State, Payload_Data, Packet_Buffer, True, 16#AA#);
      Check_Status (Result_Status, CryptoLib.Errors.Ok, "protected encode succeeds");
      Check (SSH_Lib.Protocol.Protected_Packets.Outbound_Sequence (Encode_State) = 1,
             "outbound sequence increments exactly once");

      Result_Status := SSH_Lib.Protocol.Protected_Packets.Decode_Protected_Packet
        (Decode_State, SSH_Lib.Protocol.Buffers.To_Array (Packet_Buffer), Payload_Buffer);
      Check_Status (Result_Status, CryptoLib.Errors.Ok, "protected decode succeeds");
      Check (SSH_Lib.Protocol.Protected_Packets.Inbound_Sequence (Decode_State) = 1,
             "inbound sequence increments exactly once");
      Check (SSH_Lib.Protocol.Buffers.To_Array (Payload_Buffer) = Payload_Data,
             "protected packet preserves binary payload bytes");
      Check (not SSH_Lib.Protocol.Protected_Packets.Is_Dirty (Decode_State),
             "valid protected packet does not dirty state");
   end Check_Round_Trip_And_Sequences;

   procedure Check_Bad_Mac_Dirties_State is
      Encode_State : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Decode_State : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Packet_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Payload_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Result_Status : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Protected_Packets.Reset (Encode_State, Key_Data);
      SSH_Lib.Protocol.Protected_Packets.Reset (Decode_State, Key_Data);
      Result_Status := SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
        (Encode_State, Payload_Data, Packet_Buffer, True, 16#AA#);
      Check_Status (Result_Status, CryptoLib.Errors.Ok, "bad-mac fixture encode");

      declare
         Tampered : Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Packet_Buffer);
      begin
         Tampered (Tampered'Last) := Tampered (Tampered'Last) xor 16#01#;
         Result_Status := SSH_Lib.Protocol.Protected_Packets.Decode_Protected_Packet
           (Decode_State, Tampered, Payload_Buffer);
      end;
      Check_Status (Result_Status, CryptoLib.Errors.Handshake_Failed,
                    "bad MAC rejected by protected decode");
      Check (SSH_Lib.Protocol.Protected_Packets.Is_Dirty (Decode_State),
             "bad MAC dirties protected packet state");
      Check_Status (SSH_Lib.Protocol.Protected_Packets.Last_Failure (Decode_State),
                    CryptoLib.Errors.Handshake_Failed,
                    "bad MAC last failure recorded");

      Result_Status := SSH_Lib.Protocol.Protected_Packets.Decode_Protected_Packet
        (Decode_State, SSH_Lib.Protocol.Buffers.To_Array (Packet_Buffer), Payload_Buffer);
      Check_Status (Result_Status, CryptoLib.Errors.Read_Failed,
                    "packet after dirty state is rejected deterministically");
   end Check_Bad_Mac_Dirties_State;

   procedure Check_Wrong_Sequence_Mac_Dirties_State is
      Encode_State : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Decode_State : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Packet_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Payload_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Result_Status : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Protected_Packets.Reset (Encode_State, Key_Data);
      SSH_Lib.Protocol.Protected_Packets.Reset (Decode_State, Key_Data);
      SSH_Lib.Protocol.Protected_Packets.Set_Sequences_For_Test
        (Decode_State, Inbound_Value => 1, Outbound_Value => 0);
      Result_Status := SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
        (Encode_State, Payload_Data, Packet_Buffer, True, 16#AA#);
      Check_Status (Result_Status, CryptoLib.Errors.Ok, "wrong-sequence fixture encode");
      Result_Status := SSH_Lib.Protocol.Protected_Packets.Decode_Protected_Packet
        (Decode_State, SSH_Lib.Protocol.Buffers.To_Array (Packet_Buffer), Payload_Buffer);
      Check_Status (Result_Status, CryptoLib.Errors.Handshake_Failed,
                    "wrong sequence MAC rejected");
      Check (SSH_Lib.Protocol.Protected_Packets.Is_Dirty (Decode_State),
             "wrong sequence MAC dirties protected state");
   end Check_Wrong_Sequence_Mac_Dirties_State;

   procedure Check_Truncated_Protected_Packet_Dirties_State is
      Encode_State : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Decode_State : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Packet_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Payload_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Result_Status : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Protected_Packets.Reset (Encode_State, Key_Data);
      SSH_Lib.Protocol.Protected_Packets.Reset (Decode_State, Key_Data);
      Result_Status := SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
        (Encode_State, Payload_Data, Packet_Buffer, True, 16#AA#);
      Check_Status (Result_Status, CryptoLib.Errors.Ok, "truncated fixture encode");

      declare
         Packet_Array : constant Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Packet_Buffer);
      begin
         Result_Status := SSH_Lib.Protocol.Protected_Packets.Decode_Protected_Packet
           (Decode_State,
            Packet_Array (Packet_Array'First .. Packet_Array'Last - 1),
            Payload_Buffer);
      end;
      Check_Status (Result_Status, CryptoLib.Errors.Handshake_Failed,
                    "truncated protected packet rejected");
      Check (SSH_Lib.Protocol.Protected_Packets.Is_Dirty (Decode_State),
             "truncated protected packet dirties protected state");
   end Check_Truncated_Protected_Packet_Dirties_State;

   procedure Check_Invalid_Padding_With_Valid_Mac_Dirties_State is
      Clear_State : SSH_Lib.Protocol.Packets.Protocol_State;
      Decode_State : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Clear_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Protected_Packet : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Payload_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Result_Status : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Packets.Reset (Clear_State);
      SSH_Lib.Protocol.Protected_Packets.Reset (Decode_State, Key_Data);
      Result_Status := SSH_Lib.Protocol.Packets.Encode_Cleartext_Packet
        (Clear_State, Payload_Data, Clear_Packet, True, 16#AA#);
      Check_Status (Result_Status, CryptoLib.Errors.Ok,
                    "invalid-padding clear fixture encode");

      declare
         Tampered_Clear : Ada.Streams.Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Clear_Packet);
      begin
         --  Byte 5 is the SSH padding_length field after the 4-byte length.
         Tampered_Clear (Tampered_Clear'First + 4) := 1;
         Result_Status :=
           SSH_Lib.Protocol.Protected_Packets.Test_Support.Attach_Inbound_Mac
             (Decode_State, Tampered_Clear, Protected_Packet);
      end;
      Check_Status (Result_Status, CryptoLib.Errors.Ok,
                    "invalid-padding fixture receives valid MAC");
      Result_Status := SSH_Lib.Protocol.Protected_Packets.Decode_Protected_Packet
        (Decode_State,
         SSH_Lib.Protocol.Buffers.To_Array (Protected_Packet),
         Payload_Buffer);
      Check_Status (Result_Status, CryptoLib.Errors.Handshake_Failed,
                    "invalid padding rejected after MAC verification");
      Check (SSH_Lib.Protocol.Protected_Packets.Is_Dirty (Decode_State),
             "invalid padding dirties protected state");
   end Check_Invalid_Padding_With_Valid_Mac_Dirties_State;

begin
   Check_Matrix_Mappings;
   Check_Round_Trip_And_Sequences;
   Check_Bad_Mac_Dirties_State;
   Check_Wrong_Sequence_Mac_Dirties_State;
   Check_Truncated_Protected_Packet_Dirties_State;
   Check_Invalid_Padding_With_Valid_Mac_Dirties_State;
   Ada.Text_IO.Put_Line ("test_packet_protection_negative passed");
end Test_Packet_Protection_Negative;
