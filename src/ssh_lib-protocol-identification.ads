with Ada.Streams;
with Ada.Strings.Unbounded;
with CryptoLib.Errors;

package SSH_Lib.Protocol.Identification is

   Max_Identification_Line_Length : constant Natural := 255;
   Max_Banner_Lines               : constant Natural := 20;

   type Identification_State is private;

   procedure Reset (Item : out Identification_State);

   function Has_Remote_Identification
     (Item : Identification_State)
      return Boolean;

   function Local_Text
     (Item : Identification_State)
      return String;

   function Remote_Text
     (Item : Identification_State)
      return String;

   function Local_Identification return String;

   function Local_Identification_Line
      return Ada.Streams.Stream_Element_Array;

   function Parse_Remote_Identification
     (Data              : Ada.Streams.Stream_Element_Array;
      Remote_Text       : out Ada.Strings.Unbounded.Unbounded_String;
      Consumed_Index    : out Ada.Streams.Stream_Element_Offset;
      Accept_SSH_1_99   : Boolean := False)
      return CryptoLib.Errors.Status;

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
