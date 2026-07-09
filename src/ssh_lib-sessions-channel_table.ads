with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Per-session table of open SSH channels and their I/O.
--
--  Allocates and releases local channel ids within a Session, tracks how many
--  are active, and drives the CHANNEL_OPEN / exec request/response exchanges
--  over the session's live transport.  It also exposes the session's configured
--  I/O timeouts and reader mode, and marks the session dirty on failure.
package SSH_Lib.Sessions.Channel_Table is
   --  Allocate a free local channel id and record it as active.
   --  @param Item             the session whose channel table to grow
   --  @param Local_Channel_Id the newly allocated local channel number
   --  @return Ok on success, or a failure status when the table is exhausted
   function Allocate
     (Item             : in out Session;
      Local_Channel_Id : out Interfaces.Unsigned_32)
      return CryptoLib.Errors.Status;

   --  Release a previously allocated local channel id, freeing its slot.
   --  @param Item             the session whose channel table to shrink
   --  @param Local_Channel_Id the local channel number to release
   procedure Release
     (Item             : in out Session;
      Local_Channel_Id : Interfaces.Unsigned_32);

   --  Return the channel-table generation counter (bumped on allocate/release).
   --  @param Item the session to query
   --  @return the current generation value
   function Current_Generation (Item : Session) return Interfaces.Unsigned_32;

   --  Return the session's configured channel read timeout in milliseconds.
   --  @param Item the session to query
   --  @return the read timeout in milliseconds (0 means immediate)
   function Session_Read_Timeout_MS (Item : Session) return Natural;

   --  Return the session's configured channel write timeout in milliseconds.
   --  @param Item the session to query
   --  @return the write timeout in milliseconds (0 means immediate)
   function Session_Write_Timeout_MS (Item : Session) return Natural;

   --  Report whether the background channel reader is enabled for this session.
   --  @param Item the session to query
   --  @return True if the background channel reader option is set
   function Background_Channel_Reader_Enabled (Item : Session) return Boolean;

   --  Send a CHANNEL_OPEN payload over the live transport.
   --  @param Item    the session to send on
   --  @param Payload the encoded CHANNEL_OPEN packet body
   --  @return Ok on success, Timeout or Write_Failed on a send failure
   function Send_Open_Payload
     (Item    : in out Session;
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Send a channel "exec" request payload over the live transport.
   --  @param Item    the session to send on
   --  @param Payload the encoded exec channel-request packet body
   --  @return Ok on success, Timeout or Write_Failed on a send failure
   function Send_Exec_Payload
     (Item    : in out Session;
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Read a server-initiated (forwarded) CHANNEL_OPEN request from the peer.
   --  @param Item    the session to read from
   --  @param Payload the received forwarded CHANNEL_OPEN packet body
   --  @return Ok on success or a read failure status
   function Read_Inbound_Forwarded_Open
     (Item    : in out Session;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Read the CHANNEL_OPEN confirmation/failure for an expected local channel.
   --  @param Item                      the session to read from
   --  @param Expected_Local_Channel_Id the local channel the response is for
   --  @param Payload                   the received open-response packet body
   --  @return Ok on success, or a channel-open/read failure status
   function Read_Open_Response
     (Item                      : in out Session;
      Expected_Local_Channel_Id : Interfaces.Unsigned_32;
      Payload                   : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Read the exec-request success/failure reply for an expected local channel.
   --  @param Item                      the session to read from
   --  @param Expected_Local_Channel_Id the local channel the response is for
   --  @param Payload                   the received exec-response packet body
   --  @return Ok on success, or a channel-request/read failure status
   function Read_Exec_Response
     (Item                      : in out Session;
      Expected_Local_Channel_Id : Interfaces.Unsigned_32;
      Payload                   : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Mark the session as failed with a cause, dirtying it against reuse.
   --  @param Item         the session to mark
   --  @param Status_Value the failure status to record
   procedure Mark_Failed
     (Item         : in out Session;
      Status_Value : CryptoLib.Errors.Status);

   --  Dequeue the next buffered channel stdout payload (testing only).
   --  @param Item the session whose stdout queue to pop
   --  @return the next buffered stdout packet, or empty if none
   function Take_Next_Channel_Stdout_For_Test
     (Item : in out Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Return the number of currently active channels.
   --  @param Item the session to query
   --  @return the count of open channels
   function Active_Count (Item : Session) return Natural;

   --  Report whether a given local channel id is currently active.
   --  @param Item             the session to query
   --  @param Local_Channel_Id the local channel number to test
   --  @return True if the channel is in the table
   function Contains
     (Item             : Session;
      Local_Channel_Id : Interfaces.Unsigned_32)
      return Boolean;

   --  Report whether live (socket-backed) channel I/O is enabled.
   --  @param Item the session to query
   --  @return True if live channel I/O is active
   function Live_Channel_IO_Enabled (Item : Session) return Boolean;

   --  Clear the channel table back to its empty initial state.
   --  @param Item the session to reset
   procedure Reset (Item : in out Session);
end SSH_Lib.Sessions.Channel_Table;
