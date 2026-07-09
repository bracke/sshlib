with Ada.Streams;
with Ada.Strings.Unbounded;
with CryptoLib.Errors;

--  @summary The SSH version-string (identification banner) exchange.
--
--  Produces the local "SSH-2.0-..." identification line and parses the remote
--  peer's identification out of the incoming byte stream, tolerating leading
--  banner lines (RFC 4253 section 4.2).  Identification_State remembers the
--  local and remote version strings for the rest of the handshake.
package SSH_Lib.Protocol.Identification is

   Max_Identification_Line_Length : constant Natural := 255;
   Max_Banner_Lines               : constant Natural := 20;

   type Identification_State is private;

   --  Reset the state to the local identification with no remote value recorded.
   --  @param Item the state to (re)initialize
   procedure Reset (Item : out Identification_State);

   --  Report whether the remote peer's identification has been parsed and stored.
   --  @param Item the identification state
   --  @return True once a remote identification has been recorded
   function Has_Remote_Identification
     (Item : Identification_State)
      return Boolean;

   --  Return the local identification string held in the state.
   --  @param Item the identification state
   --  @return the local "SSH-2.0-..." version string
   function Local_Text
     (Item : Identification_State)
      return String;

   --  Return the remote peer's identification string held in the state.
   --  @param Item the identification state
   --  @return the stored remote version string, or the empty string if none
   function Remote_Text
     (Item : Identification_State)
      return String;

   --  Return this library's fixed local identification string.
   --  @return the "SSH-2.0-SSH_Lib_1.0" version string
   function Local_Identification return String;

   --  Return the local identification as the CR-LF-terminated wire line to send.
   --  @return the identification line bytes, including its trailing CR LF
   function Local_Identification_Line
      return Ada.Streams.Stream_Element_Array;

   --  Parse the remote identification from an incoming byte stream, skipping banner lines.
   --  @param Data            the received bytes to scan
   --  @param Remote_Text     the parsed remote identification string
   --  @param Consumed_Index  the offset just past the consumed identification line
   --  @param Accept_SSH_1_99 whether to accept an "SSH-1.99-" compatibility banner
   --  @return Ok when a complete identification line was parsed, an error status otherwise
   function Parse_Remote_Identification
     (Data              : Ada.Streams.Stream_Element_Array;
      Remote_Text       : out Ada.Strings.Unbounded.Unbounded_String;
      Consumed_Index    : out Ada.Streams.Stream_Element_Offset;
      Accept_SSH_1_99   : Boolean := False)
      return CryptoLib.Errors.Status;

   --  Parse the remote identification and store it in the state on success.
   --  @param Item            the state updated with the parsed remote identification
   --  @param Data            the received bytes to scan
   --  @param Consumed_Index  the offset just past the consumed identification line
   --  @param Accept_SSH_1_99 whether to accept an "SSH-1.99-" compatibility banner
   --  @return Ok when a complete identification line was parsed and stored, an error status otherwise
   function Parse_And_Store_Remote_Identification
     (Item              : in out Identification_State;
      Data              : Ada.Streams.Stream_Element_Array;
      Consumed_Index    : out Ada.Streams.Stream_Element_Offset;
      Accept_SSH_1_99   : Boolean := False)
      return CryptoLib.Errors.Status;

private
   type Identification_State is record
      Local_Value      : Ada.Strings.Unbounded.Unbounded_String;
      Remote_Value     : Ada.Strings.Unbounded.Unbounded_String;
      Has_Remote_Value : Boolean := False;
   end record;
end SSH_Lib.Protocol.Identification;
