with SSH_Lib.Sessions.Live_Transcript;

--  @summary Attach and detach a live-transport transcript driver to a session.
--
--  Owns the lifecycle of the Live_Transcript driver that backs a session's real
--  network I/O: allocation and disposal, attaching and detaching it to a session,
--  and closing it.  Detaching without closing hands ownership back to the caller.
package SSH_Lib.Sessions.Live_Attachment is
   subtype Transcript_Access is SSH_Lib.Sessions.Live_Transcript.Driver_Access;

   --  Allocate a new live-transport transcript driver.
   --  @return an access to the newly created transcript driver
   function Create return Transcript_Access;

   --  Free a transcript driver and reset the access to null.
   --  @param Pointer the transcript driver to dispose of, set to null on return
   procedure Destroy (Pointer : in out Transcript_Access);

   --  Attach a transcript driver to a session, transferring ownership to the session.
   --  @param Item    the session to attach the transcript to
   --  @param Pointer the transcript driver to attach, cleared on return
   procedure Attach
     (Item    : in out Session;
      Pointer : in out Transcript_Access);

   --  Report whether a transcript driver is currently attached to the session.
   --  @param Item the session to test
   --  @return True if a transcript is attached
   function Attached (Item : Session) return Boolean;

   --  Return the transcript driver attached to the session.
   --  @param Item the session to query
   --  @return the attached transcript driver, or null if none is attached
   function Transcript (Item : in out Session) return Transcript_Access;

   --  Detach the transcript from the session without closing it, leaving it caller-owned.
   --  @param Item the session to detach the transcript from
   procedure Detach_Without_Close (Item : in out Session);

   --  Close and dispose of the session's attached transcript driver.
   --  @param Item the session whose attached transcript is closed
   procedure Close_Attached (Item : in out Session);
end SSH_Lib.Sessions.Live_Attachment;
