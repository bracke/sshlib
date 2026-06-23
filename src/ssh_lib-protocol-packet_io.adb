
package body SSH_Lib.Protocol.Packet_IO is
   use CryptoLib.Errors;

   function Complete_Bounded_Read
     (Transport      : in out SSH_Lib.Transport.Transport_Handle;
      Limit          : SSH_Lib.Deadlines.Deadline;
      Expected_Bytes : Natural;
      Bytes_Read     : Natural;
      Failure        : CryptoLib.Errors.Status;
      Stage          : Packet_Read_Stage;
      Partial_Packet : Boolean := False)
      return CryptoLib.Errors.Status
   is
      pragma Unreferenced (Stage);
      Have_Partial_Packet : constant Boolean :=
        Partial_Packet or else (Bytes_Read > 0 and then Bytes_Read < Expected_Bytes);
   begin
      if Expected_Bytes = 0 then
         return Ok;
      end if;

      if Failure /= Ok then
         if Have_Partial_Packet then
            SSH_Lib.Transport.Mark_Dirty (Transport, Failure);
         end if;
         return Failure;
      elsif not SSH_Lib.Transport.Is_Open (Transport) then
         return Connection_Failed;
      elsif Bytes_Read >= Expected_Bytes then
         return Ok;
      elsif SSH_Lib.Deadlines.Expired (Limit) then
         if Have_Partial_Packet then
            SSH_Lib.Transport.Mark_Dirty (Transport, Timeout);
         end if;
         return Timeout;
      else
         if Have_Partial_Packet then
            SSH_Lib.Transport.Mark_Dirty (Transport, Read_Failed);
            return Read_Failed;
         end if;
         return Timeout;
      end if;
   exception
      when others =>
         SSH_Lib.Transport.Mark_Dirty (Transport, Internal_Error);
         return Internal_Error;
   end Complete_Bounded_Read;

   function Complete_Bounded_Write
     (Transport            : in out SSH_Lib.Transport.Transport_Handle;
      Limit                : SSH_Lib.Deadlines.Deadline;
      Total_Bytes          : Natural;
      Bytes_Written        : Natural;
      Failure              : CryptoLib.Errors.Status;
      Ambiguous_Acceptance : Boolean := False)
      return CryptoLib.Errors.Status
   is
      Have_Ambiguous_Write : constant Boolean :=
        Ambiguous_Acceptance or else (Bytes_Written > 0 and then Bytes_Written < Total_Bytes);
   begin
      if Total_Bytes = 0 then
         if SSH_Lib.Transport.Is_Open (Transport) then
            return Ok;
         else
            return Connection_Failed;
         end if;
      end if;

      if Failure /= Ok then
         if Have_Ambiguous_Write then
            SSH_Lib.Transport.Mark_Dirty (Transport, Failure);
         end if;
         return Failure;
      elsif not SSH_Lib.Transport.Is_Open (Transport) then
         return Connection_Failed;
      elsif Bytes_Written >= Total_Bytes then
         return Ok;
      elsif SSH_Lib.Deadlines.Expired (Limit) then
         if Have_Ambiguous_Write then
            SSH_Lib.Transport.Mark_Dirty (Transport, Timeout);
         end if;
         return Timeout;
      else
         if Have_Ambiguous_Write then
            SSH_Lib.Transport.Mark_Dirty (Transport, Write_Failed);
            return Write_Failed;
         end if;
         return Timeout;
      end if;
   exception
      when others =>
         SSH_Lib.Transport.Mark_Dirty (Transport, Internal_Error);
         return Internal_Error;
   end Complete_Bounded_Write;

   function Complete_Bounded_Read
     (Transport      : in out SSH_Lib.Transport.Transport_Handle;
      Operation      : SSH_Lib.Operation_Control.Operation_State;
      Expected_Bytes : Natural;
      Bytes_Read     : Natural;
      Failure        : CryptoLib.Errors.Status;
      Stage          : Packet_Read_Stage;
      Partial_Packet : Boolean := False)
      return CryptoLib.Errors.Status
   is
      Control_Status : constant Status := SSH_Lib.Operation_Control.Check (Operation);
      Have_Partial_Packet : constant Boolean :=
        Partial_Packet or else (Bytes_Read > 0 and then Bytes_Read < Expected_Bytes);
   begin
      if Control_Status = Cancelled then
         if Have_Partial_Packet then
            SSH_Lib.Transport.Mark_Dirty (Transport, Cancelled);
         end if;
         return Cancelled;
      end if;

      return Complete_Bounded_Read
        (Transport,
         SSH_Lib.Operation_Control.Deadline (Operation),
         Expected_Bytes,
         Bytes_Read,
         (if Control_Status = Timeout and then Failure = Ok then Ok else Failure),
         Stage,
         Partial_Packet);
   exception
      when others =>
         SSH_Lib.Transport.Mark_Dirty (Transport, Internal_Error);
         return Internal_Error;
   end Complete_Bounded_Read;

   function Complete_Bounded_Write
     (Transport            : in out SSH_Lib.Transport.Transport_Handle;
      Operation            : SSH_Lib.Operation_Control.Operation_State;
      Total_Bytes          : Natural;
      Bytes_Written        : Natural;
      Failure              : CryptoLib.Errors.Status;
      Ambiguous_Acceptance : Boolean := False)
      return CryptoLib.Errors.Status
   is
      Control_Status : constant Status := SSH_Lib.Operation_Control.Check (Operation);
      Have_Ambiguous_Write : constant Boolean :=
        Ambiguous_Acceptance or else (Bytes_Written > 0 and then Bytes_Written < Total_Bytes);
   begin
      if Control_Status = Cancelled then
         if Have_Ambiguous_Write then
            SSH_Lib.Transport.Mark_Dirty (Transport, Cancelled);
         end if;
         return Cancelled;
      end if;

      return Complete_Bounded_Write
        (Transport,
         SSH_Lib.Operation_Control.Deadline (Operation),
         Total_Bytes,
         Bytes_Written,
         (if Control_Status = Timeout and then Failure = Ok then Ok else Failure),
         Ambiguous_Acceptance);
   exception
      when others =>
         SSH_Lib.Transport.Mark_Dirty (Transport, Internal_Error);
         return Internal_Error;
   end Complete_Bounded_Write;

   function Register_Malformed_Packet
     (Transport             : in out SSH_Lib.Transport.Transport_Handle;
      After_Authentication  : Boolean)
      return CryptoLib.Errors.Status
   is
      Result : constant Status :=
        (if After_Authentication then Read_Failed else Handshake_Failed);
   begin
      SSH_Lib.Transport.Mark_Dirty (Transport, Result);
      return Result;
   exception
      when others =>
         SSH_Lib.Transport.Mark_Dirty (Transport, Internal_Error);
         return Internal_Error;
   end Register_Malformed_Packet;
end SSH_Lib.Protocol.Packet_IO;
