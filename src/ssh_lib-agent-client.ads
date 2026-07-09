with Ada.Streams;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Client for the ssh-agent protocol over a Unix-domain socket.
--
--  Connects to a running ssh-agent, lists its held identities, and asks it to
--  sign data with a chosen key, framing and parsing the agent wire messages.
package SSH_Lib.Agent.Client is
   --  Connect to the agent and retrieve the list of identities it holds.
   --  @param Socket_Path filesystem path of the agent's Unix-domain socket (SSH_AUTH_SOCK)
   --  @param Identities  the identities returned by the agent
   --  @return Ok on success, or the failure status of the connect/exchange
   function Request_Identities
     (Socket_Path : String;
      Identities  : out SSH_Lib.Agent.Identity_List)
      return CryptoLib.Errors.Status;

   --  Retrieve the agent's identities, bounding the exchange with a timeout.
   --  @param Socket_Path filesystem path of the agent's Unix-domain socket
   --  @param Timeout_MS  maximum time to wait for the exchange, in milliseconds
   --  @param Identities  the identities returned by the agent
   --  @return Ok on success, Timeout on expiry, or another failure status
   function Request_Identities
     (Socket_Path : String;
      Timeout_MS  : Natural;
      Identities  : out SSH_Lib.Agent.Identity_List)
      return CryptoLib.Errors.Status;

   --  Ask the agent to sign Data_To_Sign with the identity named by Key_Blob.
   --  @param Socket_Path          filesystem path of the agent's Unix-domain socket
   --  @param Key_Blob             SSH public-key blob selecting the signing identity
   --  @param Data_To_Sign         the bytes to be signed by the agent
   --  @param Public_Key_Algorithm signature algorithm name (e.g. "rsa-sha2-256")
   --  @param Signature_Blob       the SSH-encoded signature returned by the agent
   --  @return Ok on success, or the failure status of the connect/exchange
   function Request_Signature
     (Socket_Path           : String;
      Key_Blob              : Ada.Streams.Stream_Element_Array;
      Data_To_Sign          : Ada.Streams.Stream_Element_Array;
      Public_Key_Algorithm  : String;
      Signature_Blob        : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Ask the agent to sign data, bounding the exchange with a timeout.
   --  @param Socket_Path          filesystem path of the agent's Unix-domain socket
   --  @param Timeout_MS           maximum time to wait for the exchange, in milliseconds
   --  @param Key_Blob             SSH public-key blob selecting the signing identity
   --  @param Data_To_Sign         the bytes to be signed by the agent
   --  @param Public_Key_Algorithm signature algorithm name (e.g. "rsa-sha2-256")
   --  @param Signature_Blob       the SSH-encoded signature returned by the agent
   --  @return Ok on success, Timeout on expiry, or another failure status
   function Request_Signature
     (Socket_Path           : String;
      Timeout_MS            : Natural;
      Key_Blob              : Ada.Streams.Stream_Element_Array;
      Data_To_Sign          : Ada.Streams.Stream_Element_Array;
      Public_Key_Algorithm  : String;
      Signature_Blob        : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;
end SSH_Lib.Agent.Client;
