with Ada.Streams;
with GNAT.Sockets;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Agent.Transport is
   type Agent_Connection is limited private;

   function Connect
     (Socket_Path : String;
      Item        : out Agent_Connection)
      return CryptoLib.Errors.Status;

   function Connect
     (Socket_Path : String;
      Timeout_MS  : Natural;
      Item        : out Agent_Connection)
      return CryptoLib.Errors.Status;

   function Send_Message
     (Item    : in out Agent_Connection;
      Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Send_Message
     (Item       : in out Agent_Connection;
      Payload    : Ada.Streams.Stream_Element_Array;
      Timeout_MS : Natural)
      return CryptoLib.Errors.Status;

   function Receive_Message
     (Item    : in out Agent_Connection;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Receive_Message
     (Item       : in out Agent_Connection;
      Payload    : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Timeout_MS : Natural)
      return CryptoLib.Errors.Status;

   function Close
     (Item : in out Agent_Connection)
      return CryptoLib.Errors.Status;

private
   type Agent_Connection is limited record
      Connected : Boolean := False;
      Socket    : GNAT.Sockets.Socket_Type;
   end record;
end SSH_Lib.Agent.Transport;
