with CryptoLib.Errors;
with SSH_Lib.Identity_Files;
with SSH_Lib.Protocol.Buffers;

--  @summary Drives the SSH userauth exchange over the live session transport.
--
--  Requests the ssh-userauth service and runs each authentication method
--  (public-key via agent or identity file, password, keyboard-interactive) as a
--  send/receive exchange on the authenticated transcript.  The Last_*_For_Test
--  accessors expose the most recently sent or received plaintext/protected
--  payloads so tests can assert on the exact bytes on the wire.
package SSH_Lib.Sessions.Userauth_IO is
   --  Report whether userauth I/O is enabled for this session.
   --  @param Item the session to query
   --  @return True if userauth I/O is active
   function Enabled (Item : Session) return Boolean;

   --  Force-enable userauth I/O so tests can drive the exchange (testing only).
   --  @param Item the session to enable
   procedure Enable_For_Test (Item : in out Session);

   --  Send the ssh-userauth SERVICE_REQUEST and read the service acceptance.
   --  @param Item the session to run on
   --  @return Ok on acceptance, or a handshake/read failure status
   function Run_Userauth_Service_Request
     (Item : in out Session)
      return CryptoLib.Errors.Status;

   --  Run public-key userauth using a key held by the ssh-agent.
   --  @param Item      the session to authenticate
   --  @param User_Name the remote user name to authenticate as
   --  @return Ok on success, Authentication_Failed on rejection, else a failure
   function Run_Agent_Userauth
     (Item      : in out Session;
      User_Name : String)
      return CryptoLib.Errors.Status;

   --  Run public-key userauth using a locally loaded identity key.
   --  @param Item      the session to authenticate
   --  @param User_Name the remote user name to authenticate as
   --  @param Key       the identity (private) key to sign with
   --  @return Ok on success, Authentication_Failed on rejection, else a failure
   function Run_Identity_File_Userauth
     (Item      : in out Session;
      User_Name : String;
      Key       : SSH_Lib.Identity_Files.Identity_Key)
      return CryptoLib.Errors.Status;

   --  Run the "password" userauth method with the given credentials.
   --  @param Item      the session to authenticate
   --  @param User_Name the remote user name to authenticate as
   --  @param Password  the password to submit
   --  @return Ok on success, Authentication_Failed on rejection, else a failure
   function Run_Password_Userauth
     (Item      : in out Session;
      User_Name : String;
      Password  : String)
      return CryptoLib.Errors.Status;

   --  Run the "keyboard-interactive" userauth method, answering prompts with
   --  the given password.
   --  @param Item      the session to authenticate
   --  @param User_Name the remote user name to authenticate as
   --  @param Password  the response used to answer server prompts
   --  @return Ok on success, Authentication_Failed on rejection, else a failure
   function Run_Keyboard_Interactive_Userauth
     (Item      : in out Session;
      User_Name : String;
      Password  : String)
      return CryptoLib.Errors.Status;

   --  Return the last plaintext SERVICE_REQUEST sent (testing only).
   --  @param Item the session to query
   --  @return the captured plaintext service-request payload
   function Last_Plain_Service_Request_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Return the last protected (on-wire) SERVICE_REQUEST sent (testing only).
   --  @param Item the session to query
   --  @return the captured protected service-request payload
   function Last_Protected_Service_Request_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Return the last plaintext userauth request sent (testing only).
   --  @param Item the session to query
   --  @return the captured plaintext userauth payload
   function Last_Plain_Userauth_Payload_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Return the last protected (on-wire) userauth request sent (testing only).
   --  @param Item the session to query
   --  @return the captured protected userauth payload
   function Last_Protected_Userauth_Payload_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Return the last plaintext SERVICE_ACCEPT received (testing only).
   --  @param Item the session to query
   --  @return the captured plaintext service-response payload
   function Last_Plain_Service_Response_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Return the last protected (on-wire) SERVICE_ACCEPT received (testing only).
   --  @param Item the session to query
   --  @return the captured protected service-response payload
   function Last_Protected_Service_Response_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Return the last plaintext userauth response received (testing only).
   --  @param Item the session to query
   --  @return the captured plaintext userauth response payload
   function Last_Plain_Userauth_Response_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Return the last protected (on-wire) userauth response received (testing only).
   --  @param Item the session to query
   --  @return the captured protected userauth response payload
   function Last_Protected_Userauth_Response_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Return the last sign request sent to the ssh-agent (testing only).
   --  @param Item the session to query
   --  @return the captured agent sign-request payload
   function Last_Agent_Sign_Request_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Return the last sign response received from the ssh-agent (testing only).
   --  @param Item the session to query
   --  @return the captured agent sign-response payload
   function Last_Agent_Sign_Response_For_Test
     (Item : Session)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;
end SSH_Lib.Sessions.Userauth_IO;
