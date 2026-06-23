with Ada.Streams;
with CryptoLib.Errors;
with Interfaces;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Transport_Messages;
with SSH_Lib.Tests.Assertions;

package body SSH_Lib.Tests.Fixtures.Transport_Messages is

   use Ada.Streams;
   use type SSH_Lib.Protocol.Transport_Messages.Transport_Message_Kind;
   use type CryptoLib.Errors.Status;
   use type Interfaces.Unsigned_32;

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         raise Program_Error with Label_Text;
      end if;
   end Check;

   procedure Assert_Transport_Message_Classification is
      Disconnect_Payload : constant Stream_Element_Array (1 .. 1) := [1 => 1];
      Ignore_Payload     : constant Stream_Element_Array (1 .. 1) := [1 => 2];
      Unimpl_Payload     : constant Stream_Element_Array (1 .. 1) := [1 => 3];
      Debug_Payload      : constant Stream_Element_Array (1 .. 1) := [1 => 4];
      Channel_Payload    : constant Stream_Element_Array (1 .. 1) := [1 => 91];
   begin
      Check
        (SSH_Lib.Protocol.Transport_Messages.Classify (Disconnect_Payload)
         = SSH_Lib.Protocol.Transport_Messages.Transport_Disconnect,
         "disconnect transport message classified");
      Check
        (SSH_Lib.Protocol.Transport_Messages.Classify (Ignore_Payload)
         = SSH_Lib.Protocol.Transport_Messages.Transport_Ignore,
         "ignore transport message classified");
      Check
        (SSH_Lib.Protocol.Transport_Messages.Classify (Unimpl_Payload)
         = SSH_Lib.Protocol.Transport_Messages.Transport_Unimplemented,
         "unimplemented transport message classified");
      Check
        (SSH_Lib.Protocol.Transport_Messages.Classify (Debug_Payload)
         = SSH_Lib.Protocol.Transport_Messages.Transport_Debug,
         "debug transport message classified");
      Check
        (SSH_Lib.Protocol.Transport_Messages.Classify (Channel_Payload)
         = SSH_Lib.Protocol.Transport_Messages.Transport_Other,
         "channel message is not a transport control message");

      Check
        (not SSH_Lib.Protocol.Transport_Messages.Is_Ignorable_During_Wait
           (Disconnect_Payload),
         "disconnect is not ignorable during protected waits");
      Check
        (SSH_Lib.Protocol.Transport_Messages.Is_Ignorable_During_Wait
           (Ignore_Payload),
         "ignore is ignorable during protected waits");
      Check
        (SSH_Lib.Protocol.Transport_Messages.Is_Ignorable_During_Wait
           (Unimpl_Payload),
         "unimplemented is ignorable during protected waits");
      Check
        (SSH_Lib.Protocol.Transport_Messages.Is_Ignorable_During_Wait
           (Debug_Payload),
         "debug is ignorable during protected waits");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Transport_Messages.Failure_Status
           (Disconnect_Payload, CryptoLib.Errors.Read_Failed),
         CryptoLib.Errors.Connection_Failed,
         "transport message classification", "disconnect maps to connection failure");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Transport_Messages.Failure_Status
           (Channel_Payload, CryptoLib.Errors.Read_Failed),
         CryptoLib.Errors.Read_Failed,
         "transport message classification", "non-transport message keeps caller status");

      declare
         Disconnect_Buffer : constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
           SSH_Lib.Protocol.Transport_Messages.Encode_Disconnect
             (11, "SSH_Lib session closed");
         Disconnect_Data   : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Disconnect_Buffer);
         Reason_Code       : Interfaces.Unsigned_32 := 0;
         Next_Index        : Stream_Element_Offset := 1;
         Description_Field : SSH_Lib.Protocol.Buffers.Packet_Buffer;
         Language_Field    : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      begin
         Check
           (Disconnect_Data'Length > 1
            and then Disconnect_Data (Disconnect_Data'First) = 1,
            "disconnect encoder emits SSH_MSG_DISCONNECT");
         Check
           (SSH_Lib.Protocol.Transport_Messages.Classify (Disconnect_Data)
            = SSH_Lib.Protocol.Transport_Messages.Transport_Disconnect,
            "encoded disconnect classifies as disconnect");
         SSH_Lib.Tests.Assertions.Check_Status
           (SSH_Lib.Protocol.Numbers.Decode_Uint32
              (Disconnect_Data, Disconnect_Data'First + 1, Reason_Code, Next_Index),
            CryptoLib.Errors.Ok,
            "transport message disconnect encoder",
            "disconnect reason decodes");
         Check (Reason_Code = 11, "disconnect reason code preserved");
         SSH_Lib.Tests.Assertions.Check_Status
           (SSH_Lib.Protocol.Numbers.Decode_SSH_String
              (Disconnect_Data, Next_Index, Description_Field, Next_Index),
            CryptoLib.Errors.Ok,
            "transport message disconnect encoder",
            "disconnect description decodes");
         Check
           (SSH_Lib.Protocol.Buffers.To_Array (Description_Field)'Length > 0,
            "disconnect description is present");
         SSH_Lib.Tests.Assertions.Check_Status
           (SSH_Lib.Protocol.Numbers.Decode_SSH_String
              (Disconnect_Data, Next_Index, Language_Field, Next_Index),
            CryptoLib.Errors.Ok,
            "transport message disconnect encoder",
            "disconnect language decodes");
         Check
           (SSH_Lib.Protocol.Buffers.To_Array (Language_Field)'Length = 0,
            "disconnect language tag is empty");
      end;
   end Assert_Transport_Message_Classification;
end SSH_Lib.Tests.Fixtures.Transport_Messages;
