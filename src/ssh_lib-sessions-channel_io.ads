with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Send and receive channel-layer payloads over an open, encrypted session.
--
--  The channel-I/O plumbing that carries channel-open, exec, and data messages
--  once the session is fully opened and authenticated, plus pending window-adjust
--  bookkeeping and the test hooks used to drive it without a live peer.
package SSH_Lib.Sessions.Channel_IO is
   --  Report whether live channel I/O is enabled and the session is ready for it.
   --  @param Item the session to test
   --  @return True when live channel I/O is enabled and the session is fully open, authenticated, and encrypted
   function Enabled (Item : Session) return Boolean;

   --  Force-enable live channel I/O on a session for testing.
   --  @param Item the session to enable
   procedure Enable_For_Test (Item : in out Session);

   type Channel_Response_Kind is (Open_Response, Exec_Response);

   --  Encrypt and send one channel-layer payload over the session transport.
   --  @param Item    the session to send on
   --  @param Payload the channel message payload to send
   --  @return Ok on success, an error status on failure
   function Send_Channel_Payload
     (Item    : in out Session;
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Queue a synthetic channel response for tests to have Read_Channel_Response return.
   --  @param Item    the session whose test queue is appended
   --  @param Kind    the response kind (channel-open or exec confirmation)
   --  @param Payload the payload to enqueue
   --  @return Ok on success, an error status if the queue is full
   function Queue_Channel_Response_For_Test
     (Item    : in out Session;
      Kind    : Channel_Response_Kind;
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Read the next channel response of a given kind for the expected local channel.
   --  @param Item                      the session to read from
   --  @param Kind                      the expected response kind (open or exec)
   --  @param Expected_Local_Channel_Id the local channel id the response must match
   --  @param Payload                   the received response payload
   --  @return Ok on a matching response, an error status otherwise
   function Read_Channel_Response
     (Item                      : in out Session;
      Kind                      : Channel_Response_Kind;
      Expected_Local_Channel_Id : Interfaces.Unsigned_32;
      Payload                   : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Consume any pending window-adjust for a channel, clearing it from the session.
   --  @param Item             the session holding the pending adjust
   --  @param Local_Channel_Id the local channel id whose adjust is wanted
   --  @param Bytes_To_Add     the pending window increment, or 0 if none
   --  @return True if a nonzero window adjust for that channel was pending and taken
   function Take_Pending_Window_Adjust
     (Item             : in out Session;
      Local_Channel_Id : Interfaces.Unsigned_32;
      Bytes_To_Add     : out Interfaces.Unsigned_32)
      return Boolean;

   --  Return the last cleartext channel payload sent, for test inspection.
   --  @param Item the session to inspect
   --  @return the most recent plaintext channel payload
   function Last_Plain_Channel_Payload_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Return the last encrypted channel payload sent, for test inspection.
   --  @param Item the session to inspect
   --  @return the most recent protected (encrypted) channel payload
   function Last_Protected_Channel_Payload_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;
end SSH_Lib.Sessions.Channel_IO;
