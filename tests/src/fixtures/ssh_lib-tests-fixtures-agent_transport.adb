with Ada.Streams;
with SSH_Lib.Agent;
with SSH_Lib.Agent.Client;
with SSH_Lib.Agent.Transport;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Tests.Assertions;

package body SSH_Lib.Tests.Fixtures.Agent_Transport is

   use Ada.Streams;
   use type CryptoLib.Errors.Status;

   procedure Check_Status
     (Actual_Status   : CryptoLib.Errors.Status;
      Expected_Status : CryptoLib.Errors.Status;
      Label_Text      : String) is
   begin
      SSH_Lib.Tests.Assertions.Assert
        (Actual_Status = Expected_Status, Label_Text);
   end Check_Status;

   procedure Assert_Agent_Transport_And_Client_Boundaries is
      Connection      : SSH_Lib.Agent.Transport.Agent_Connection;
      Identities      : SSH_Lib.Agent.Identity_List;
      Signature_Blob  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Buffer    : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value    : CryptoLib.Errors.Status;
      Empty_Payload   : constant Stream_Element_Array (1 .. 0) := [others => 0];
      Key_Blob        : constant Stream_Element_Array (1 .. 4) :=
        [1 => 16#00#, 2 => 16#7F#, 3 => 16#80#, 4 => 16#FF#];
      Data_To_Sign    : constant Stream_Element_Array (1 .. 6) :=
        [1 => 16#00#, 2 => 16#0A#, 3 => 16#0D#,
         4 => 16#7F#, 5 => 16#80#, 6 => 16#FF#];
   begin
      Status_Value := SSH_Lib.Agent.Transport.Connect ("", Connection);
      Check_Status (Status_Value, CryptoLib.Errors.Connection_Failed,
                    "agent transport empty SSH_AUTH_SOCK path rejected");

      Status_Value := SSH_Lib.Agent.Transport.Connect
        ("/tmp/ssh_lib_missing_agent.sock", 0, Connection);
      Check_Status (Status_Value, CryptoLib.Errors.Timeout,
                    "agent transport zero connect timeout maps to Timeout");

      Status_Value := SSH_Lib.Agent.Transport.Send_Message (Connection, Empty_Payload);
      Check_Status (Status_Value, CryptoLib.Errors.Write_Failed,
                    "agent transport send on closed connection rejected");

      Status_Value := SSH_Lib.Agent.Transport.Receive_Message (Connection, Reply_Buffer);
      Check_Status (Status_Value, CryptoLib.Errors.Read_Failed,
                    "agent transport receive on closed connection rejected");
      SSH_Lib.Protocol.Buffers.Clear (Reply_Buffer);

      Status_Value := SSH_Lib.Agent.Transport.Close (Connection);
      Check_Status (Status_Value, CryptoLib.Errors.Ok,
                    "agent transport close remains idempotent");

      Status_Value := SSH_Lib.Agent.Client.Request_Identities
        ("", 30_000, Identities);
      Check_Status (Status_Value, CryptoLib.Errors.Connection_Failed,
                    "agent client list identities empty socket path rejected");
      SSH_Lib.Tests.Assertions.Assert
        (SSH_Lib.Agent.Count (Identities) = 0,
         "agent client clears identity list after connect failure");

      Status_Value := SSH_Lib.Agent.Client.Request_Identities
        ("/tmp/ssh_lib_missing_agent.sock", 0, Identities);
      Check_Status (Status_Value, CryptoLib.Errors.Timeout,
                    "agent client list identities zero timeout maps to Timeout");
      SSH_Lib.Tests.Assertions.Assert
        (SSH_Lib.Agent.Count (Identities) = 0,
         "agent client leaves identity list empty after timeout");

      Status_Value := SSH_Lib.Agent.Client.Request_Signature
        ("", 30_000, Key_Blob, Data_To_Sign, "rsa-sha2-256", Signature_Blob);
      Check_Status (Status_Value, CryptoLib.Errors.Connection_Failed,
                    "agent client sign empty socket path rejected after request encoding");
      SSH_Lib.Tests.Assertions.Assert
        (SSH_Lib.Protocol.Buffers.Is_Empty (Signature_Blob),
         "agent client clears signature blob after connect failure");

      Status_Value := SSH_Lib.Agent.Client.Request_Signature
        ("/tmp/ssh_lib_missing_agent.sock", 0, Key_Blob, Data_To_Sign,
         "rsa-sha2-256", Signature_Blob);
      Check_Status (Status_Value, CryptoLib.Errors.Timeout,
                    "agent client sign zero timeout maps to Timeout");
      SSH_Lib.Tests.Assertions.Assert
        (SSH_Lib.Protocol.Buffers.Is_Empty (Signature_Blob),
         "agent client leaves signature blob empty after timeout");

      Status_Value := SSH_Lib.Agent.Client.Request_Signature
        ("/tmp/ssh_lib_missing_agent.sock", 30_000, Key_Blob, Data_To_Sign,
         "ssh-rsa", Signature_Blob);
      Check_Status (Status_Value, CryptoLib.Errors.Connection_Failed,
                    "agent client permits last-resort ssh-rsa request encoding before transport");
      SSH_Lib.Tests.Assertions.Assert
        (SSH_Lib.Protocol.Buffers.Is_Empty (Signature_Blob),
         "agent client clears signature blob after final connect failure");
   end Assert_Agent_Transport_And_Client_Boundaries;
end SSH_Lib.Tests.Fixtures.Agent_Transport;
