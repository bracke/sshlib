with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Sessions.Channel_Table is
   function Allocate
     (Item             : in out Session;
      Local_Channel_Id : out Interfaces.Unsigned_32)
      return CryptoLib.Errors.Status;

   procedure Release
     (Item             : in out Session;
      Local_Channel_Id : Interfaces.Unsigned_32);

   function Current_Generation (Item : Session) return Interfaces.Unsigned_32;

   function Session_Read_Timeout_MS (Item : Session) return Natural;

   function Session_Write_Timeout_MS (Item : Session) return Natural;

   function Background_Channel_Reader_Enabled (Item : Session) return Boolean;

   function Send_Open_Payload
     (Item    : in out Session;
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Send_Exec_Payload
     (Item    : in out Session;
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Read_Inbound_Forwarded_Open
     (Item    : in out Session;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Read_Open_Response
     (Item                      : in out Session;
      Expected_Local_Channel_Id : Interfaces.Unsigned_32;
      Payload                   : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Read_Exec_Response
     (Item                      : in out Session;
      Expected_Local_Channel_Id : Interfaces.Unsigned_32;
      Payload                   : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   procedure Mark_Failed
     (Item         : in out Session;
      Status_Value : CryptoLib.Errors.Status);

   function Take_Next_Channel_Stdout_For_Test
     (Item : in out Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Active_Count (Item : Session) return Natural;

   function Contains
     (Item             : Session;
      Local_Channel_Id : Interfaces.Unsigned_32)
      return Boolean;

   function Live_Channel_IO_Enabled (Item : Session) return Boolean;

   procedure Reset (Item : in out Session);
end SSH_Lib.Sessions.Channel_Table;
