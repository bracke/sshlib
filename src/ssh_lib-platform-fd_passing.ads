with GNAT.Sockets;
with Interfaces.C;
with CryptoLib.Errors;

--  @summary SCM_RIGHTS file-descriptor passing over a Unix-domain socket.
--
--  Wraps sendmsg/recvmsg ancillary-data (SCM_RIGHTS) so the connection
--  multiplexer can hand live socket file descriptors to another process over a
--  local control socket.  Bounded to Max_File_Descriptors_Per_Message fds per
--  message.
package SSH_Lib.Platform.FD_Passing is
   subtype File_Descriptor is Interfaces.C.int;
   type File_Descriptor_Array is array (Positive range <>) of File_Descriptor;

   Max_File_Descriptors_Per_Message : constant Natural := 8;

   --  Send the given file descriptors as SCM_RIGHTS ancillary data over Socket.
   --  @param Socket      the connected Unix-domain socket to send over
   --  @param Descriptors the open file descriptors to transfer to the peer
   --  @return Ok on success, an error status on a socket or size failure
   function Send_File_Descriptors
     (Socket      : GNAT.Sockets.Socket_Type;
      Descriptors : File_Descriptor_Array)
      return CryptoLib.Errors.Status;

   --  Receive file descriptors sent as SCM_RIGHTS ancillary data over Socket.
   --  @param Socket         the connected Unix-domain socket to read from
   --  @param Descriptors    the buffer receiving the transferred descriptors
   --  @param Received_Count the number of descriptors actually received
   --  @return Ok on success, an error status on a socket or size failure
   function Receive_File_Descriptors
     (Socket         : GNAT.Sockets.Socket_Type;
      Descriptors    : out File_Descriptor_Array;
      Received_Count : out Natural)
      return CryptoLib.Errors.Status;
end SSH_Lib.Platform.FD_Passing;
