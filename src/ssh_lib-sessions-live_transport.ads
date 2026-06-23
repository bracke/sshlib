with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Sessions.Live_Transport is
   function Connect_And_Run_Handshake
     (Options : Session_Options;
      Item    : in out Session)
      return CryptoLib.Errors.Status;

   function Connect_Through_Proxy_Jump
     (Options : Session_Options;
      Item    : in out Session)
      return CryptoLib.Errors.Status;

   function Connect_Through_Proxy_Command
     (Options : Session_Options;
      Item    : in out Session)
      return CryptoLib.Errors.Status;

   function Rekey
     (Item : in out Session)
      return CryptoLib.Errors.Status;

   function Rekey_With_Peer_Kexinit
     (Item           : in out Session;
      Server_Kexinit : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   procedure Note_Protected_Outbound
     (Item            : in out Session;
      Wire_Byte_Count : Natural);

   procedure Note_Protected_Inbound
     (Item            : in out Session;
      Wire_Byte_Count : Natural);

   function Automatic_Rekey_Needed
     (Item : Session)
      return Boolean;

   function Check_Automatic_Rekey
     (Item : in out Session)
      return CryptoLib.Errors.Status;
end SSH_Lib.Sessions.Live_Transport;
