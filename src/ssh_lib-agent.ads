with Ada.Streams;
with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

package SSH_Lib.Agent is

   Max_Identities          : constant Natural := 128;
   Max_Public_Key_Blob     : constant Natural := 64 * 1024;
   Max_Comment_Length      : constant Natural := 4 * 1024;
   Max_Agent_Message_Size  : constant Natural := 1024 * 1024;

   type Identity_List is private;

   procedure Clear (Item : out Identity_List);

   function Count (Item : Identity_List) return Natural;

   function Add_Identity
     (Item     : in out Identity_List;
      Key_Blob : Ada.Streams.Stream_Element_Array;
      Comment  : String)
      return CryptoLib.Errors.Status;

   function Public_Key_Blob
     (Item  : Identity_List;
      Index : Positive)
      return Ada.Streams.Stream_Element_Array;

   function Comment
     (Item  : Identity_List;
      Index : Positive)
      return String;

private
   type Agent_Identity is record
      Key_Blob : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Comment  : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   type Identity_Array is array (Positive range 1 .. Max_Identities) of Agent_Identity;

   type Identity_List is record
      Items      : Identity_Array;
      Item_Count : Natural := 0;
   end record;
end SSH_Lib.Agent;
