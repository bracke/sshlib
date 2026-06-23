with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Sessions.Channel_IO is
   function Enabled (Item : Session) return Boolean;

   procedure Enable_For_Test (Item : in out Session);

   type Channel_Response_Kind is (Open_Response, Exec_Response);

   function Send_Channel_Payload
     (Item    : in out Session;
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Queue_Channel_Response_For_Test
     (Item    : in out Session;
      Kind    : Channel_Response_Kind;
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Read_Channel_Response
     (Item                      : in out Session;
      Kind                      : Channel_Response_Kind;
      Expected_Local_Channel_Id : Interfaces.Unsigned_32;
      Payload                   : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Take_Pending_Window_Adjust
     (Item             : in out Session;
      Local_Channel_Id : Interfaces.Unsigned_32;
      Bytes_To_Add     : out Interfaces.Unsigned_32)
      return Boolean;

   function Last_Plain_Channel_Payload_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Last_Protected_Channel_Payload_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;
end SSH_Lib.Sessions.Channel_IO;
