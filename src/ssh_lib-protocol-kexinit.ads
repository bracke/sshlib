with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;
with CryptoLib.Random;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

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

   procedure Clear (Item : out Kexinit_Message);

   function Construct_Client
     (Source_Item : in out CryptoLib.Random.Random_Source;
      Item        : out Kexinit_Message;
      Payload     : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Encode
     (Item    : Kexinit_Message;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return CryptoLib.Errors.Status;

   function Parse
     (Payload : Ada.Streams.Stream_Element_Array;
      Item    : out Kexinit_Message)
      return CryptoLib.Errors.Status;
end SSH_Lib.Protocol.Kexinit;
