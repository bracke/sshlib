with SSH_Lib.Deadlines;
with SSH_Lib.Operation_Control;
with CryptoLib.Errors;
with SSH_Lib.Transport;

package SSH_Lib.Protocol.Packet_IO is
   type Packet_Read_Stage is
     (Packet_Length_Field,
      Packet_Body);

   function Complete_Bounded_Read
     (Transport      : in out SSH_Lib.Transport.Transport_Handle;
      Limit          : SSH_Lib.Deadlines.Deadline;
      Expected_Bytes : Natural;
      Bytes_Read     : Natural;
      Failure        : CryptoLib.Errors.Status;
      Stage          : Packet_Read_Stage;
      Partial_Packet : Boolean := False)
      return CryptoLib.Errors.Status;

   function Complete_Bounded_Write
     (Transport            : in out SSH_Lib.Transport.Transport_Handle;
      Limit                : SSH_Lib.Deadlines.Deadline;
      Total_Bytes          : Natural;
      Bytes_Written        : Natural;
      Failure              : CryptoLib.Errors.Status;
      Ambiguous_Acceptance : Boolean := False)
      return CryptoLib.Errors.Status;

   function Complete_Bounded_Read
     (Transport      : in out SSH_Lib.Transport.Transport_Handle;
      Operation      : SSH_Lib.Operation_Control.Operation_State;
      Expected_Bytes : Natural;
      Bytes_Read     : Natural;
      Failure        : CryptoLib.Errors.Status;
      Stage          : Packet_Read_Stage;
      Partial_Packet : Boolean := False)
      return CryptoLib.Errors.Status;

   function Complete_Bounded_Write
     (Transport            : in out SSH_Lib.Transport.Transport_Handle;
      Operation            : SSH_Lib.Operation_Control.Operation_State;
      Total_Bytes          : Natural;
      Bytes_Written        : Natural;
      Failure              : CryptoLib.Errors.Status;
      Ambiguous_Acceptance : Boolean := False)
      return CryptoLib.Errors.Status;

   function Register_Malformed_Packet
     (Transport             : in out SSH_Lib.Transport.Transport_Handle;
      After_Authentication  : Boolean)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Packet_IO;
