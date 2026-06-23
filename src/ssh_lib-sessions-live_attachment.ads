with SSH_Lib.Sessions.Live_Transcript;

package SSH_Lib.Sessions.Live_Attachment is
   subtype Transcript_Access is SSH_Lib.Sessions.Live_Transcript.Driver_Access;

   function Create return Transcript_Access;

   procedure Destroy (Pointer : in out Transcript_Access);

   procedure Attach
     (Item    : in out Session;
      Pointer : in out Transcript_Access);

   function Attached (Item : Session) return Boolean;

   function Transcript (Item : in out Session) return Transcript_Access;

   procedure Detach_Without_Close (Item : in out Session);

   procedure Close_Attached (Item : in out Session);
end SSH_Lib.Sessions.Live_Attachment;
