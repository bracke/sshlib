with Ada.Streams;
with Ada.Strings.Unbounded;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;

--  @summary In-memory list of ssh-agent identities (public-key blob plus comment).
--
--  Holds the identities returned by an agent, each a public-key blob and its
--  human-readable comment, with fixed capacity and size bounds so parsing an
--  untrusted SSH_AGENT_IDENTITIES_ANSWER cannot exhaust memory.
package SSH_Lib.Agent is

   Max_Identities          : constant Natural := 128;
   Max_Public_Key_Blob     : constant Natural := 64 * 1024;
   Max_Comment_Length      : constant Natural := 4 * 1024;
   Max_Agent_Message_Size  : constant Natural := 1024 * 1024;

   type Identity_List is private;

   --  Reset the list to empty, discarding all stored identities.
   --  @param Item the identity list to clear
   procedure Clear (Item : out Identity_List);

   --  Return the number of identities currently held.
   --  @param Item the identity list to inspect
   --  @return the count of stored identities
   function Count (Item : Identity_List) return Natural;

   --  Append one identity (public-key blob and comment) to the list.
   --  @param Item     the identity list to extend
   --  @param Key_Blob the SSH public-key blob for the identity
   --  @param Comment  the identity's human-readable comment
   --  @return Ok if added, or a failure status if the list is full or a bound
   --          is exceeded
   function Add_Identity
     (Item     : in out Identity_List;
      Key_Blob : Ada.Streams.Stream_Element_Array;
      Comment  : String)
      return CryptoLib.Errors.Status;

   --  Return the public-key blob of the identity at the given position.
   --  @param Item  the identity list to inspect
   --  @param Index the 1-based position of the identity
   --  @return the stored public-key blob
   function Public_Key_Blob
     (Item  : Identity_List;
      Index : Positive)
      return Ada.Streams.Stream_Element_Array;

   --  Return the comment of the identity at the given position.
   --  @param Item  the identity list to inspect
   --  @param Index the 1-based position of the identity
   --  @return the stored comment string
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
