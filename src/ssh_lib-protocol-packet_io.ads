with SSH_Lib.Deadlines;
with SSH_Lib.Operation_Control;
with CryptoLib.Errors;
with SSH_Lib.Transport;

--  @summary Classifies the outcome of a bounded packet read/write into a status.
--
--  Given how far a deadline- or cancellation-bounded transport I/O got (bytes
--  transferred versus expected, any low-level failure, deadline expiry), these
--  helpers decide the resulting status and poison the transport when a partial
--  transfer leaves it in an ambiguous state, so a torn packet is never silently
--  resumed.
package SSH_Lib.Protocol.Packet_IO is
   type Packet_Read_Stage is
     (Packet_Length_Field,
      Packet_Body);

   --  Classify the outcome of a deadline-bounded packet read.
   --  @param Transport      the transport handle, marked dirty on a partial read
   --  @param Limit          the deadline that bounded the read
   --  @param Expected_Bytes the number of bytes the read was to obtain
   --  @param Bytes_Read     the number of bytes actually read
   --  @param Failure        the low-level read status (Ok if none)
   --  @param Stage          which packet field was being read
   --  @param Partial_Packet True if bytes of the packet were already consumed
   --  @return Ok on a complete read, otherwise the classified failure status
   function Complete_Bounded_Read
     (Transport      : in out SSH_Lib.Transport.Transport_Handle;
      Limit          : SSH_Lib.Deadlines.Deadline;
      Expected_Bytes : Natural;
      Bytes_Read     : Natural;
      Failure        : CryptoLib.Errors.Status;
      Stage          : Packet_Read_Stage;
      Partial_Packet : Boolean := False)
      return CryptoLib.Errors.Status;

   --  Classify the outcome of a deadline-bounded packet write.
   --  @param Transport            the transport handle, marked dirty on a torn
   --                              write
   --  @param Limit                the deadline that bounded the write
   --  @param Total_Bytes          the number of bytes the write was to send
   --  @param Bytes_Written        the number of bytes actually written
   --  @param Failure              the low-level write status (Ok if none)
   --  @param Ambiguous_Acceptance True if the peer may have partly accepted the
   --                              write
   --  @return Ok on a complete write, otherwise the classified failure status
   function Complete_Bounded_Write
     (Transport            : in out SSH_Lib.Transport.Transport_Handle;
      Limit                : SSH_Lib.Deadlines.Deadline;
      Total_Bytes          : Natural;
      Bytes_Written        : Natural;
      Failure              : CryptoLib.Errors.Status;
      Ambiguous_Acceptance : Boolean := False)
      return CryptoLib.Errors.Status;

   --  Classify a bounded packet read driven by an operation control (deadline
   --  plus cancellation).
   --  @param Transport      the transport handle, marked dirty on a partial read
   --  @param Operation      the operation control supplying deadline and cancel
   --  @param Expected_Bytes the number of bytes the read was to obtain
   --  @param Bytes_Read     the number of bytes actually read
   --  @param Failure        the low-level read status (Ok if none)
   --  @param Stage          which packet field was being read
   --  @param Partial_Packet True if bytes of the packet were already consumed
   --  @return Ok on completion, Cancelled if cancelled, else the failure status
   function Complete_Bounded_Read
     (Transport      : in out SSH_Lib.Transport.Transport_Handle;
      Operation      : SSH_Lib.Operation_Control.Operation_State;
      Expected_Bytes : Natural;
      Bytes_Read     : Natural;
      Failure        : CryptoLib.Errors.Status;
      Stage          : Packet_Read_Stage;
      Partial_Packet : Boolean := False)
      return CryptoLib.Errors.Status;

   --  Classify a bounded packet write driven by an operation control (deadline
   --  plus cancellation).
   --  @param Transport            the transport handle, marked dirty on a torn
   --                              write
   --  @param Operation            the operation control supplying deadline and
   --                              cancel
   --  @param Total_Bytes          the number of bytes the write was to send
   --  @param Bytes_Written        the number of bytes actually written
   --  @param Failure              the low-level write status (Ok if none)
   --  @param Ambiguous_Acceptance True if the peer may have partly accepted the
   --                              write
   --  @return Ok on completion, Cancelled if cancelled, else the failure status
   function Complete_Bounded_Write
     (Transport            : in out SSH_Lib.Transport.Transport_Handle;
      Operation            : SSH_Lib.Operation_Control.Operation_State;
      Total_Bytes          : Natural;
      Bytes_Written        : Natural;
      Failure              : CryptoLib.Errors.Status;
      Ambiguous_Acceptance : Boolean := False)
      return CryptoLib.Errors.Status;

   --  Poison the transport for a malformed inbound packet and return the
   --  appropriate protocol failure status.
   --  @param Transport            the transport handle to mark dirty
   --  @param After_Authentication True once authentication has completed, which
   --                              selects Read_Failed rather than Handshake_Failed
   --  @return Read_Failed after authentication, otherwise Handshake_Failed
   function Register_Malformed_Packet
     (Transport             : in out SSH_Lib.Transport.Transport_Handle;
      After_Authentication  : Boolean)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Packet_IO;
