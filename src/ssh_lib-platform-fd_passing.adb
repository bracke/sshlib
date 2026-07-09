with System;

package body SSH_Lib.Platform.FD_Passing is
   package C renames Interfaces.C;
   use type C.int;
   use type C.long;
   use type C.size_t;

   SOL_SOCKET : constant C.int := 1;
   SCM_RIGHTS : constant C.int := 1;

   type IOVec is record
      Base : System.Address;
      Len  : C.size_t;
   end record
     with Convention => C;

   type MsgHdr is record
      Name        : System.Address := System.Null_Address;
      Name_Len    : C.unsigned := 0;
      IOV         : System.Address := System.Null_Address;
      IOV_Len     : C.size_t := 0;
      Control     : System.Address := System.Null_Address;
      Control_Len : C.size_t := 0;
      Flags       : C.int := 0;
   end record
     with Convention => C;

   type CMsgHdr is record
      Len   : C.size_t := 0;
      Level : C.int := 0;
      Kind  : C.int := 0;
   end record
     with Convention => C;

   CMsg_Header_Size : constant C.size_t :=
     C.size_t ((CMsgHdr'Size + System.Storage_Unit - 1) / System.Storage_Unit);
   C_Int_Size : constant C.size_t :=
     C.size_t ((C.int'Size + System.Storage_Unit - 1) / System.Storage_Unit);
   Size_T_Size : constant C.size_t :=
     C.size_t ((C.size_t'Size + System.Storage_Unit - 1) / System.Storage_Unit);

   function Align (Value : C.size_t) return C.size_t is
   begin
      return ((Value + Size_T_Size - 1) / Size_T_Size) * Size_T_Size;
   end Align;

   function CMsg_Space (Data_Length : C.size_t) return C.size_t is
   begin
      return Align (CMsg_Header_Size) + Align (Data_Length);
   end CMsg_Space;

   function CMsg_Length (Data_Length : C.size_t) return C.size_t is
   begin
      return Align (CMsg_Header_Size) + Data_Length;
   end CMsg_Length;

   function sendmsg
     (Socket : C.int;
      Msg    : access MsgHdr;
      Flags  : C.int) return C.long;
   pragma Import (C, sendmsg, "sendmsg");

   function recvmsg
     (Socket : C.int;
      Msg    : access MsgHdr;
      Flags  : C.int) return C.long;
   pragma Import (C, recvmsg, "recvmsg");

   function Send_File_Descriptors
     (Socket      : GNAT.Sockets.Socket_Type;
      Descriptors : File_Descriptor_Array)
      return CryptoLib.Errors.Status
   is
      use CryptoLib.Errors;

      Descriptor_Count : constant Natural := Descriptors'Length;
      Data_Length      : constant C.size_t :=
        C.size_t (Descriptor_Count) * C_Int_Size;
      Control_Length   : constant C.size_t := CMsg_Space (Data_Length);
      type Control_Buffer is array (C.size_t range <>) of aliased C.unsigned_char;
      Control          : aliased Control_Buffer (0 .. Control_Length - 1) :=
        [others => 0];
      Marker           : aliased C.char := C.char'Val (0);
      Vec              : aliased IOVec :=
        (Base => Marker'Address, Len => 1);
      Msg              : aliased MsgHdr :=
        (Name        => System.Null_Address,
         Name_Len    => 0,
         IOV         => Vec'Address,
         IOV_Len     => 1,
         Control     => Control'Address,
         Control_Len => Control_Length,
         Flags       => 0);
      Header           : CMsgHdr
        with Import, Address => Control (Control'First)'Address;
      Result           : C.long;
      Data_First       : constant C.size_t := Align (CMsg_Header_Size);
   begin
      if Descriptor_Count = 0
        or else Descriptor_Count > Max_File_Descriptors_Per_Message
      then
         return Unsupported_Feature;
      end if;

      Header.Len := CMsg_Length (Data_Length);
      Header.Level := SOL_SOCKET;
      Header.Kind := SCM_RIGHTS;

      for Index in Descriptors'Range loop
         declare
            Offset : constant C.size_t :=
              Data_First
              + C.size_t (Index - Descriptors'First) * C_Int_Size;
            Item : C.int
              with Address => Control (Offset)'Address;
         begin
            Item := Descriptors (Index);
         end;
      end loop;

      Result := sendmsg (C.int (GNAT.Sockets.To_C (Socket)), Msg'Access, 0);
      if Result = 1 then
         return Ok;
      end if;
      return Write_Failed;
   exception
      when others =>
         return Internal_Error;
   end Send_File_Descriptors;

   function Receive_File_Descriptors
     (Socket         : GNAT.Sockets.Socket_Type;
      Descriptors    : out File_Descriptor_Array;
      Received_Count : out Natural)
      return CryptoLib.Errors.Status
   is
      use CryptoLib.Errors;

      Capacity       : constant Natural := Descriptors'Length;
      Data_Capacity  : constant C.size_t := C.size_t (Capacity) * C_Int_Size;
      Control_Length : constant C.size_t := CMsg_Space (Data_Capacity);
      type Control_Buffer is array (C.size_t range <>) of aliased C.unsigned_char;
      Control        : aliased Control_Buffer (0 .. Control_Length - 1) :=
        [others => 0];
      Marker         : aliased C.char := C.char'Val (0);
      Vec            : aliased IOVec :=
        (Base => Marker'Address, Len => 1);
      Msg            : aliased MsgHdr :=
        (Name        => System.Null_Address,
         Name_Len    => 0,
         IOV         => Vec'Address,
         IOV_Len     => 1,
         Control     => Control'Address,
         Control_Len => Control_Length,
         Flags       => 0);
      Header         : CMsgHdr
        with Import, Address => Control (Control'First)'Address;
      Result         : C.long;
      Data_First     : constant C.size_t := Align (CMsg_Header_Size);
      Data_Length    : C.size_t;
   begin
      Descriptors := [others => -1];
      Received_Count := 0;
      if Capacity = 0 or else Capacity > Max_File_Descriptors_Per_Message then
         return Unsupported_Feature;
      end if;

      Result := recvmsg (C.int (GNAT.Sockets.To_C (Socket)), Msg'Access, 0);
      if Result <= 0 then
         return Read_Failed;
      elsif Header.Level /= SOL_SOCKET
        or else Header.Kind /= SCM_RIGHTS
        or else Header.Len < CMsg_Length (C_Int_Size)
      then
         return Invalid_Command;
      end if;

      Data_Length := Header.Len - Align (CMsg_Header_Size);
      if Data_Length = 0
        or else Data_Length mod C_Int_Size /= 0
        or else Natural (Data_Length / C_Int_Size) > Capacity
      then
         return Invalid_Command;
      end if;

      Received_Count := Natural (Data_Length / C_Int_Size);
      for Index in 0 .. Received_Count - 1 loop
         declare
            Offset : constant C.size_t :=
              Data_First + C.size_t (Index) * C_Int_Size;
            Item : C.int
              with Address => Control (Offset)'Address;
         begin
            Descriptors (Descriptors'First + Index) := Item;
         end;
      end loop;
      return Ok;
   exception
      when others =>
         Descriptors := [others => -1];
         Received_Count := 0;
         return Internal_Error;
   end Receive_File_Descriptors;
end SSH_Lib.Platform.FD_Passing;
