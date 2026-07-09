with CryptoLib.Errors;

--  @summary Decide when a failure must poison the session or channel, and pick the failure status.
--
--  Centralizes the policy for whether an error status is recoverable (an expected
--  protocol outcome) or must mark the session/channel as permanently dirty, and
--  produces the canonical failure status to report for dirtied operations.
package SSH_Lib.Protocol.Failure_State is
   --  Decide whether a status must permanently dirty the whole session.
   --  @param Status_Value the operation's result status
   --  @return True for unrecoverable transport errors; False for Ok and expected protocol outcomes
   function Session_Must_Be_Dirtied
     (Status_Value : CryptoLib.Errors.Status)
      return Boolean;

   --  Decide whether a status must permanently dirty the channel.
   --  @param Status_Value the operation's result status
   --  @param Partial_IO   whether partial I/O occurred, in which case any non-Ok status dirties
   --  @return True if the channel must be dirtied
   function Channel_Must_Be_Dirtied
     (Status_Value : CryptoLib.Errors.Status;
      Partial_IO   : Boolean := False)
      return Boolean;

   --  Map a default status into a non-benign session-operation failure status.
   --  @param Default_Status the intended status to report
   --  @return the default status, or Channel_Open_Failed when it is Ok or End_Of_Stream
   function Dirty_Session_Operation_Status
     (Default_Status : CryptoLib.Errors.Status := CryptoLib.Errors.Channel_Open_Failed)
      return CryptoLib.Errors.Status;

   --  Choose the status to report for a dirtied channel read.
   --  @param Queued_Data_Available whether already-buffered data remains readable
   --  @return Ok if buffered data is still available, Read_Failed otherwise
   function Dirty_Channel_Read_Status
     (Queued_Data_Available : Boolean)
      return CryptoLib.Errors.Status;

   --  Return the canonical status for a dirtied channel write.
   --  @return Write_Failed
   function Dirty_Channel_Write_Status
      return CryptoLib.Errors.Status;

   --  Return the canonical status for a dirtied channel request.
   --  @return Channel_Request_Failed
   function Dirty_Channel_Request_Status
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Failure_State;
