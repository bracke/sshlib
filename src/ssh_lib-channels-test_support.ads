with Ada.Streams;
with Interfaces;
with CryptoLib.Errors;

--  @summary Test-only harness for driving a Channel through states the test suite could not otherwise reach.
--
--  These helpers exist purely for the AUnit suite: they inject channel state,
--  feed synthetic inbound payloads through the channel state machine, capture
--  the last encoded outbound control packets, and toggle fault-injection flags
--  so tests can exercise timeout, cleanup, and background-drain paths
--  deterministically without a live SSH peer.
package SSH_Lib.Channels.Test_Support is
   --  Force the channel into the exec-active state (open confirmed and exec
   --  request accepted) with the given identifiers and flow-control windows.
   --  @param Item                       the channel to mutate
   --  @param Local_Channel_Id           the local channel number to assign
   --  @param Remote_Channel_Id          the peer's channel number to assign
   --  @param Remote_Remaining_Window    the initial remote (send) window credit
   --  @param Remote_Maximum_Packet_Size the peer's maximum packet size
   procedure Mark_Exec_Active_For_Test
     (Item                         : in out Channel;
      Local_Channel_Id             : Interfaces.Unsigned_32 := 0;
      Remote_Channel_Id            : Interfaces.Unsigned_32 := 1;
      Remote_Remaining_Window      : Interfaces.Unsigned_32 := 2_097_152;
      Remote_Maximum_Packet_Size   : Interfaces.Unsigned_32 := 32_768);

   --  Force the channel into the open-but-exec-not-yet-confirmed state, so
   --  tests can verify data cannot race ahead of the exec CHANNEL_SUCCESS.
   --  @param Item                       the channel to mutate
   --  @param Local_Channel_Id           the local channel number to assign
   --  @param Remote_Channel_Id          the peer's channel number to assign
   --  @param Remote_Remaining_Window    the initial remote (send) window credit
   --  @param Remote_Maximum_Packet_Size the peer's maximum packet size
   procedure Mark_Channel_Open_Not_Exec_For_Test
     (Item                         : in out Channel;
      Local_Channel_Id             : Interfaces.Unsigned_32 := 0;
      Remote_Channel_Id            : Interfaces.Unsigned_32 := 1;
      Remote_Remaining_Window      : Interfaces.Unsigned_32 := 2_097_152;
      Remote_Maximum_Packet_Size   : Interfaces.Unsigned_32 := 32_768);

   --  Record that the remote program has terminated with the given exit code.
   --  @param Item the channel to mutate
   --  @param Code the remote command exit status to record
   procedure Mark_Exit_Status_Known_For_Test
     (Item : in out Channel;
      Code : Integer);

   --  Mark that this endpoint has already sent CHANNEL_CLOSE.
   --  @param Item the channel to mutate
   procedure Mark_Local_Close_Sent_For_Test
     (Item : in out Channel);

   --  Mark that this endpoint has already sent CHANNEL_EOF (local half-close).
   --  @param Item the channel to mutate
   procedure Mark_Local_EOF_Sent_For_Test
     (Item : in out Channel);

   --  Append bytes to the channel's pending-stdout buffer as if received.
   --  @param Item the channel to mutate
   --  @param Data the stdout bytes to enqueue
   --  @return Ok on success, Internal_Error if the append fails
   function Queue_Stdout_For_Test
     (Item : in out Channel;
      Data : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Append bytes to the channel's pending-stderr buffer as if received.
   --  @param Item the channel to mutate
   --  @param Data the stderr bytes to enqueue
   --  @return Ok on success, Internal_Error if the append fails
   function Queue_Stderr_For_Test
     (Item : in out Channel;
      Data : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Feed one decoded inbound channel-message payload through the channel
   --  state machine (data, extended-data, window-adjust, EOF, close, request).
   --  @param Item    the channel to drive
   --  @param Payload the raw channel message payload beginning with its msg type
   --  @return Ok if accepted, or the failure status the state machine produced
   function Dispatch_Inbound_Payload_For_Test
     (Item    : in out Channel;
      Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Return the most recently encoded outbound CHANNEL_DATA payload.
   --  @param Item the channel to inspect
   --  @return the last CHANNEL_DATA packet bytes, or empty if none
   function Last_Channel_Data_Payload_For_Test
     (Item : Channel)
      return Ada.Streams.Stream_Element_Array;

   --  Return the most recently encoded outbound CHANNEL_EOF payload.
   --  @param Item the channel to inspect
   --  @return the last CHANNEL_EOF packet bytes, or empty if none
   function Last_EOF_Payload_For_Test
     (Item : Channel)
      return Ada.Streams.Stream_Element_Array;

   --  Return the most recently encoded outbound CHANNEL_CLOSE payload.
   --  @param Item the channel to inspect
   --  @return the last CHANNEL_CLOSE packet bytes, or empty if none
   function Last_Close_Payload_For_Test
     (Item : Channel)
      return Ada.Streams.Stream_Element_Array;

   --  Return the most recently encoded outbound CHANNEL_WINDOW_ADJUST payload.
   --  @param Item the channel to inspect
   --  @return the last CHANNEL_WINDOW_ADJUST packet bytes, or empty if none
   function Last_Window_Adjust_Payload_For_Test
     (Item : Channel)
      return Ada.Streams.Stream_Element_Array;

   --  Return the most recently encoded outbound CHANNEL_SUCCESS payload.
   --  @param Item the channel to inspect
   --  @return the last CHANNEL_SUCCESS packet bytes, or empty if none
   function Last_Channel_Success_Payload_For_Test
     (Item : Channel)
      return Ada.Streams.Stream_Element_Array;

   --  Return the most recently encoded outbound CHANNEL_FAILURE payload.
   --  @param Item the channel to inspect
   --  @return the last CHANNEL_FAILURE packet bytes, or empty if none
   function Last_Channel_Failure_Payload_For_Test
     (Item : Channel)
      return Ada.Streams.Stream_Element_Array;

   --  Return the running total of outbound data bytes sent on the channel.
   --  @param Item the channel to inspect
   --  @return the count of outbound CHANNEL_DATA bytes
   function Outbound_Data_Byte_Count_For_Test (Item : Channel) return Natural;

   --  Return the running total of outbound data packets sent on the channel.
   --  @param Item the channel to inspect
   --  @return the count of outbound CHANNEL_DATA packets
   function Outbound_Data_Packet_Count_For_Test (Item : Channel) return Natural;

   --  Return the channel's remaining local receive-window credit.
   --  @param Item the channel to inspect
   --  @return the local remaining window in bytes
   function Local_Remaining_Window_For_Test
     (Item : Channel)
      return Interfaces.Unsigned_32;

   --  Return the channel's remaining remote send-window credit.
   --  @param Item the channel to inspect
   --  @return the remote remaining window in bytes
   function Remote_Remaining_Window_For_Test
     (Item : Channel)
      return Interfaces.Unsigned_32;

   --  Set the channel's local initial and remaining receive-window sizes.
   --  @param Item                  the channel to mutate
   --  @param Initial_Window_Size   the local initial window size to assign
   --  @param Remaining_Window_Size the local remaining window credit to assign
   procedure Set_Local_Window_For_Test
     (Item                  : in out Channel;
      Initial_Window_Size   : Interfaces.Unsigned_32;
      Remaining_Window_Size : Interfaces.Unsigned_32);

   --  Toggle injecting a write timeout after a partial write.
   --  @param Item  the channel to mutate
   --  @param Value True to arm the fault, False to clear it
   procedure Set_Write_Timeout_After_Partial_For_Test
     (Item  : in out Channel;
      Value : Boolean);

   --  Toggle injecting a timeout while sending CHANNEL_EOF.
   --  @param Item  the channel to mutate
   --  @param Value True to arm the fault, False to clear it
   procedure Set_Send_EOF_Timeout_For_Test
     (Item  : in out Channel;
      Value : Boolean);

   --  Toggle simulating a remote close arriving after a partial write.
   --  @param Item  the channel to mutate
   --  @param Value True to arm the fault, False to clear it
   procedure Set_Remote_Close_After_Partial_For_Test
     (Item  : in out Channel;
      Value : Boolean);

   --  Toggle injecting a timeout during channel close.
   --  @param Item  the channel to mutate
   --  @param Value True to arm the fault, False to clear it
   procedure Set_Close_Timeout_For_Test
     (Item  : in out Channel;
      Value : Boolean);

   --  Toggle raising an exception during close cleanup.
   --  @param Item  the channel to mutate
   --  @param Value True to arm the fault, False to clear it
   procedure Set_Close_Exception_For_Cleanup_Test
     (Item  : in out Channel;
      Value : Boolean);

   --  Set the channel's read and write timeout budgets.
   --  @param Item             the channel to mutate
   --  @param Read_Timeout_MS  the read timeout in milliseconds
   --  @param Write_Timeout_MS the write timeout in milliseconds
   procedure Set_Timeouts_For_Test
     (Item             : in out Channel;
      Read_Timeout_MS  : Natural;
      Write_Timeout_MS : Natural);

   --  Mark the channel dirty/failed with the given failure reason.
   --  @param Item   the channel to mutate
   --  @param Reason the failure status to record
   procedure Mark_Dirty_For_Test
     (Item   : in out Channel;
      Reason : CryptoLib.Errors.Status := CryptoLib.Errors.Read_Failed);

   --  Report whether the channel has been marked dirty.
   --  @param Item the channel to inspect
   --  @return True if the channel is dirty, False otherwise
   function Is_Dirty_For_Test (Item : Channel) return Boolean;

   --  Return the channel's last recorded failure status.
   --  @param Item the channel to inspect
   --  @return the last failure status
   function Last_Failure_For_Test (Item : Channel) return CryptoLib.Errors.Status;

   --  Enable the live protected-packet IO path and reset its cipher state so
   --  tests can exercise real encode/decode of channel packets.
   --  @param Item the channel to mutate
   procedure Enable_Live_Channel_IO_For_Test (Item : in out Channel);

   --  Encode Payload as a protected inbound packet (peer sequence framing) and
   --  queue it for the next live-IO read.
   --  @param Item    the channel to mutate
   --  @param Payload the cleartext channel payload to protect and enqueue
   --  @return Ok on success, or the encode/store failure status
   function Queue_Protected_Inbound_For_Test
     (Item    : in out Channel;
      Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   --  Return the last protected outbound packet emitted on the live-IO path.
   --  @param Item the channel to inspect
   --  @return the last protected outbound packet bytes, or empty if none
   function Last_Protected_Outbound_For_Test
     (Item : Channel)
      return Ada.Streams.Stream_Element_Array;

   --  Return the number of bytes queued in the pending-stdout buffer.
   --  @param Item the channel to inspect
   --  @return the pending stdout length in bytes
   function Pending_Stdout_Length_For_Test (Item : Channel) return Natural;

   --  Report whether the live protected-packet IO path is enabled.
   --  @param Item the channel to inspect
   --  @return True if live channel IO is enabled, False otherwise
   function Live_Channel_IO_Enabled_For_Test (Item : Channel) return Boolean;

   --  Set the last status recorded by the background drain task.
   --  @param Item         the channel to mutate
   --  @param Status_Value the background last-status value to assign
   procedure Set_Background_Last_Status_For_Test
     (Item   : in out Channel;
      Status_Value : CryptoLib.Errors.Status);

   --  Set whether the background drain task is marked running.
   --  @param Item  the channel to mutate
   --  @param Value the background-running flag to assign
   procedure Set_Background_Running_For_Test
     (Item  : in out Channel;
      Value : Boolean);

   --  Set whether background draining has been requested.
   --  @param Item  the channel to mutate
   --  @param Value the background-requested flag to assign
   procedure Set_Background_Requested_For_Test
     (Item  : in out Channel;
      Value : Boolean);

   --  Toggle raising an exception while stopping the background task (cleanup).
   --  @param Item  the channel to mutate
   --  @param Value True to arm the fault, False to clear it
   procedure Set_Stop_Background_Exception_For_Cleanup_Test
     (Item  : in out Channel;
      Value : Boolean);

   --  Toggle raising an exception from inside the background task (cleanup).
   --  @param Item  the channel to mutate
   --  @param Value True to arm the fault, False to clear it
   procedure Set_Background_Task_Exception_For_Cleanup_Test
     (Item  : in out Channel;
      Value : Boolean);

   --  Toggle forcing a terminal failure of the background drain.
   --  @param Item  the channel to mutate
   --  @param Value True to arm the fault, False to clear it
   procedure Set_Background_Drain_Terminal_Failure_For_Test
     (Item  : in out Channel;
      Value : Boolean);

   --  Toggle raising an exception while starting the background task (cleanup).
   --  @param Item  the channel to mutate
   --  @param Value True to arm the fault, False to clear it
   procedure Set_Start_Background_Exception_For_Cleanup_Test
     (Item  : in out Channel;
      Value : Boolean);

   --  Return the number of bytes queued in the pending-stderr buffer.
   --  @param Item the channel to inspect
   --  @return the pending stderr length in bytes
   function Pending_Stderr_Length_For_Test (Item : Channel) return Natural;
end SSH_Lib.Channels.Test_Support;
