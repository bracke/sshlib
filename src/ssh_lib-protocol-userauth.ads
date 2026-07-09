with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Auth_Methods;
with SSH_Lib.Protocol.Buffers;

--  @summary Encoding of SSH userauth requests and parsing of server replies.
--
--  Builds SSH_MSG_USERAUTH_REQUEST payloads for the none, password,
--  publickey (preflight and signed), and keyboard-interactive methods, and
--  classifies the server's userauth responses (success, failure, banner,
--  PK_OK, password-change, keyboard-interactive info request) into a Reply.
package SSH_Lib.Protocol.Userauth is

   SSH_MSG_USERAUTH_REQUEST : constant Ada.Streams.Stream_Element := 50;
   SSH_MSG_USERAUTH_FAILURE : constant Ada.Streams.Stream_Element := 51;
   SSH_MSG_USERAUTH_SUCCESS : constant Ada.Streams.Stream_Element := 52;
   SSH_MSG_USERAUTH_BANNER  : constant Ada.Streams.Stream_Element := 53;
   SSH_MSG_USERAUTH_PK_OK         : constant Ada.Streams.Stream_Element := 60;
   SSH_MSG_USERAUTH_INFO_REQUEST  : constant Ada.Streams.Stream_Element := 60;
   SSH_MSG_USERAUTH_INFO_RESPONSE : constant Ada.Streams.Stream_Element := 61;

   type Reply_Context is
     (Preflight_Reply,
      Signed_Reply,
      Password_Reply,
      Keyboard_Interactive_Reply);
   type Reply_Kind is
     (Auth_Success,
      Auth_Failure,
      Auth_Banner,
      Public_Key_Ok,
      Password_Change_Required,
      Keyboard_Interactive_Info_Request,
      Unexpected_Reply);

   Max_Keyboard_Interactive_Prompts : constant Positive := 8;
   subtype Keyboard_Interactive_Prompt_Index is Positive
     range 1 .. Max_Keyboard_Interactive_Prompts;

   type Keyboard_Interactive_Prompt is record
      Text : Ada.Strings.Unbounded.Unbounded_String;
      Echo : Boolean := False;
   end record;

   type Keyboard_Interactive_Prompt_Array is
     array (Keyboard_Interactive_Prompt_Index) of Keyboard_Interactive_Prompt;

   type Keyboard_Interactive_Response_Array is
     array (Keyboard_Interactive_Prompt_Index)
     of Ada.Strings.Unbounded.Unbounded_String;

   type Reply is record
      Kind                 : Reply_Kind := Unexpected_Reply;
      Failure              : SSH_Lib.Protocol.Auth_Methods.Failure_Info;
      Public_Key_Algorithm          : Ada.Strings.Unbounded.Unbounded_String;
      Public_Key_Blob               : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Keyboard_Interactive_Name     : Ada.Strings.Unbounded.Unbounded_String;
      Keyboard_Interactive_Instruction : Ada.Strings.Unbounded.Unbounded_String;
      Keyboard_Interactive_Language_Tag : Ada.Strings.Unbounded.Unbounded_String;
      Keyboard_Interactive_Prompts  : Interfaces.Unsigned_32 := 0;
      Keyboard_Interactive_Echoes   : Interfaces.Unsigned_32 := 0;
      Keyboard_Interactive_Prompt_Items : Keyboard_Interactive_Prompt_Array;
   end record;

   --  Encode a publickey preflight request (has-signature = false) that asks
   --  the server whether the key is acceptable before signing.
   --  @param User_Name            the authenticating user name
   --  @param Public_Key_Algorithm the publickey algorithm name
   --  @param Public_Key_Blob      the public-key blob
   --  @return the encoded USERAUTH_REQUEST packet
   function Encode_Publickey_Test_Request
     (User_Name            : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Build the exact byte string a publickey signature must cover: the
   --  session identifier prefixed to the signed userauth request fields.
   --  @param Session_Identifier   the SSH session identifier (exchange hash)
   --  @param User_Name            the authenticating user name
   --  @param Public_Key_Algorithm the publickey algorithm name
   --  @param Public_Key_Blob      the public-key blob
   --  @return the data-to-be-signed buffer
   function Build_Publickey_Signature_Payload
     (Session_Identifier   : Ada.Streams.Stream_Element_Array;
      User_Name            : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a signed publickey request (has-signature = true) carrying the
   --  computed signature blob.
   --  @param User_Name            the authenticating user name
   --  @param Public_Key_Algorithm the publickey algorithm name
   --  @param Public_Key_Blob      the public-key blob
   --  @param Signature_Blob       the signature over the signature payload
   --  @return the encoded USERAUTH_REQUEST packet
   function Encode_Publickey_Signed_Request
     (User_Name            : String;
      Public_Key_Algorithm : String;
      Public_Key_Blob      : Ada.Streams.Stream_Element_Array;
      Signature_Blob       : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a "none" method userauth request (probes available methods).
   --  @param User_Name the authenticating user name
   --  @return the encoded USERAUTH_REQUEST packet
   function Encode_None_Request
     (User_Name : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a password method userauth request.
   --  @param User_Name the authenticating user name
   --  @param Password  the password to submit
   --  @return the encoded USERAUTH_REQUEST packet
   function Encode_Password_Request
     (User_Name : String;
      Password  : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a password-change userauth request supplying old and new passwords.
   --  @param User_Name    the authenticating user name
   --  @param Old_Password the current password
   --  @param New_Password the replacement password
   --  @return the encoded USERAUTH_REQUEST packet
   function Encode_Password_Change_Request
     (User_Name    : String;
      Old_Password : String;
      New_Password : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a keyboard-interactive method userauth request.
   --  @param User_Name the authenticating user name
   --  @return the encoded USERAUTH_REQUEST packet
   function Encode_Keyboard_Interactive_Request
     (User_Name : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a keyboard-interactive INFO_RESPONSE carrying a single response.
   --  @param Response the single prompt response
   --  @return the encoded USERAUTH_INFO_RESPONSE packet
   function Encode_Keyboard_Interactive_Response
     (Response : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Encode a keyboard-interactive INFO_RESPONSE carrying multiple responses.
   --  @param Response_Count the number of responses to include
   --  @param Responses      the response array (first Response_Count entries used)
   --  @return the encoded USERAUTH_INFO_RESPONSE packet
   function Encode_Keyboard_Interactive_Responses
     (Response_Count : Natural;
      Responses      : Keyboard_Interactive_Response_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer;

   --  Parse a server userauth reply payload into a classified Reply, using the
   --  request Context to disambiguate the overlapping message number 60.
   --  @param Payload the received userauth message payload
   --  @param Context the context of the request that this reply answers
   --  @param Result  the parsed and classified reply
   --  @return Ok on success, or an error Status if the payload is malformed
   function Parse_Userauth_Reply
     (Payload : Ada.Streams.Stream_Element_Array;
      Context : Reply_Context;
      Result  : out Reply)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Userauth;
