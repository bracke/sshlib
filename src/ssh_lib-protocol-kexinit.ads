with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;
with CryptoLib.Random;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary Build, encode, and parse the SSH_MSG_KEXINIT algorithm-negotiation message.
--
--  Models the RFC 4253 SSH_MSG_KEXINIT (message number 20): the random cookie,
--  the ten comma-separated algorithm name-lists, the first-kex-follows flag and
--  reserved field, plus the raw wire payload retained for the exchange hash.
package SSH_Lib.Protocol.Kexinit is

   Message_Number : constant Ada.Streams.Stream_Element := 20;

   subtype Cookie_Index is Positive range 1 .. 16;
   type Cookie_Bytes is array (Cookie_Index) of Ada.Streams.Stream_Element;

   type Kexinit_Message is record
      Cookie                                      : Cookie_Bytes := [others => 0];
      Kex_Algorithms                              : Ada.Strings.Unbounded.Unbounded_String;
      Server_Host_Key_Algorithms                  : Ada.Strings.Unbounded.Unbounded_String;
      Encryption_Algorithms_Client_To_Server      : Ada.Strings.Unbounded.Unbounded_String;
      Encryption_Algorithms_Server_To_Client      : Ada.Strings.Unbounded.Unbounded_String;
      Mac_Algorithms_Client_To_Server             : Ada.Strings.Unbounded.Unbounded_String;
      Mac_Algorithms_Server_To_Client             : Ada.Strings.Unbounded.Unbounded_String;
      Compression_Algorithms_Client_To_Server     : Ada.Strings.Unbounded.Unbounded_String;
      Compression_Algorithms_Server_To_Client     : Ada.Strings.Unbounded.Unbounded_String;
      Languages_Client_To_Server                  : Ada.Strings.Unbounded.Unbounded_String;
      Languages_Server_To_Client                  : Ada.Strings.Unbounded.Unbounded_String;
      First_Kex_Packet_Follows                    : Boolean := False;
      Reserved                                    : Interfaces.Unsigned_32 := 0;
      Raw_Payload                                 : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   end record;

   --  Reset a KEXINIT message to empty, zeroing the cookie and name-lists.
   --  @param Item the message to clear
   procedure Clear (Item : out Kexinit_Message);

   --  Build the client's KEXINIT with a random cookie and this library's supported algorithms.
   --  @param Source_Item randomness source used to fill the 16-byte cookie
   --  @param Item        the populated client KEXINIT message
   --  @param Payload     the encoded wire payload of Item (with message number)
   --  @return Ok on success, or a failure status from randomness or encoding
   function Construct_Client
     (Source_Item : in out CryptoLib.Random.Random_Source;
      Item        : out Kexinit_Message;
      Payload     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Serialize a KEXINIT message to its RFC 4253 wire payload.
   --  @param Item    the message to encode
   --  @param Payload the resulting wire payload (message number, cookie, name-lists, trailer)
   --  @return Ok on success, or a failure status on encoding error
   function Encode
     (Item    : Kexinit_Message;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   --  Parse a received KEXINIT wire payload into its fields, retaining the raw bytes.
   --  @param Payload the raw SSH_MSG_KEXINIT wire payload to decode
   --  @param Item    the decoded message (including Raw_Payload)
   --  @return Ok on success, or a failure status on a malformed payload
   function Parse
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Kexinit_Message)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Kexinit;
