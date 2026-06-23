with CryptoLib.Errors;
with SSH_Lib.Identity_Files;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Sessions.Userauth_IO is
   function Enabled (Item : Session) return Boolean;

   procedure Enable_For_Test (Item : in out Session);

   function Run_Userauth_Service_Request
     (Item : in out Session)
      return CryptoLib.Errors.Status;

   function Run_Agent_Userauth
     (Item      : in out Session;
      User_Name : String)
      return CryptoLib.Errors.Status;

   function Run_Identity_File_Userauth
     (Item      : in out Session;
      User_Name : String;
      Key       : SSH_Lib.Identity_Files.Identity_Key)
      return CryptoLib.Errors.Status;

   function Run_Password_Userauth
     (Item      : in out Session;
      User_Name : String;
      Password  : String)
      return CryptoLib.Errors.Status;

   function Run_Keyboard_Interactive_Userauth
     (Item      : in out Session;
      User_Name : String;
      Password  : String)
      return CryptoLib.Errors.Status;

   function Last_Plain_Service_Request_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Last_Protected_Service_Request_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Last_Plain_Userauth_Payload_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Last_Protected_Userauth_Payload_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Last_Plain_Service_Response_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Last_Protected_Service_Response_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Last_Plain_Userauth_Response_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Last_Protected_Userauth_Response_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Last_Agent_Sign_Request_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   function Last_Agent_Sign_Response_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;
end SSH_Lib.Sessions.Userauth_IO;
