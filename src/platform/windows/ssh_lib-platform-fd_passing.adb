package body SSH_Lib.Platform.FD_Passing is

   use type Interfaces.C.int;

   --  Windows has no SCM_RIGHTS ancillary-data mechanism: a socket descriptor cannot
   --  be handed to another process over a local socket the way it can on POSIX. The
   --  multiplexer uses a different transport there, so these report the feature as
   --  absent rather than pretending to pass a descriptor that could not survive.

   function Send_File_Descriptors
     (Socket      : GNAT.Sockets.Socket_Type;
      Descriptors : File_Descriptor_Array)
      return CryptoLib.Errors.Status
   is
      pragma Unreferenced (Socket, Descriptors);
   begin
      return CryptoLib.Errors.Unsupported_Feature;
   end Send_File_Descriptors;

   function Receive_File_Descriptors
     (Socket         : GNAT.Sockets.Socket_Type;
      Descriptors    : out File_Descriptor_Array;
      Received_Count : out Natural)
      return CryptoLib.Errors.Status
   is
      pragma Unreferenced (Socket);
   begin
      Descriptors := [others => -1];
      Received_Count := 0;
      return CryptoLib.Errors.Unsupported_Feature;
   end Receive_File_Descriptors;

end SSH_Lib.Platform.FD_Passing;
