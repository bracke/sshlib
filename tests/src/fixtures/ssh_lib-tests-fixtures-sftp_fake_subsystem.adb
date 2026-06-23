with Ada.Streams;
with Interfaces;

with AUnit.Assertions;
with CryptoLib.Errors;

with SSH_Lib.Channels.Test_Support;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.SFTP;

package body SSH_Lib.Tests.Fixtures.SFTP_Fake_Subsystem is
   use Ada.Streams;
   use type CryptoLib.Errors.Status;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;

   function Bytes (Value : String) return Stream_Element_Array is
      Result : Stream_Element_Array (1 .. Stream_Element_Offset (Value'Length));
      Cursor : Stream_Element_Offset := Result'First;
   begin
      for Ch of Value loop
         Result (Cursor) := Stream_Element (Character'Pos (Ch));
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end Bytes;

   function U32
     (Value : Interfaces.Unsigned_32) return Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Numbers.Encode_Uint32 (Value);
   end U32;

   function U64
     (Value : Interfaces.Unsigned_64) return Stream_Element_Array
   is
      Result : Stream_Element_Array (1 .. 8);
   begin
      for Index in 0 .. 7 loop
         Result (Result'First + Stream_Element_Offset (Index)) :=
           Stream_Element
             ((Value / 2 ** Natural ((7 - Index) * 8)) mod 2 ** 8);
      end loop;
      return Result;
   end U64;

   procedure Append
     (Packet : in out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Data   : Stream_Element_Array)
   is
   begin
      AUnit.Assertions.Assert
        (SSH_Lib.Protocol.Buffers.Append (Packet, Data) = CryptoLib.Errors.Ok,
         "append test packet bytes");
   end Append;

   procedure Append_Byte
     (Packet : in out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Value  : Stream_Element)
   is
   begin
      AUnit.Assertions.Assert
        (SSH_Lib.Protocol.Buffers.Append_Byte (Packet, Value) =
         CryptoLib.Errors.Ok,
         "append test packet byte");
   end Append_Byte;

   procedure Append_String
     (Packet : in out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Value  : String)
   is
   begin
      Append (Packet, U32 (Interfaces.Unsigned_32 (Value'Length)));
      if Value'Length > 0 then
         Append (Packet, Bytes (Value));
      end if;
   end Append_String;

   function Framed
     (Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return Stream_Element_Array
   is
      Payload_Data : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Payload);
      Result       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   begin
      Append (Result, U32 (Interfaces.Unsigned_32 (Payload_Data'Length)));
      Append (Result, Payload_Data);
      return SSH_Lib.Protocol.Buffers.To_Array (Result);
   end Framed;

   function Version_Reply
     (Version : Interfaces.Unsigned_32) return Stream_Element_Array
   is
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   begin
      Append_Byte (Payload, SSH_Lib.SFTP.SSH_FXP_VERSION);
      Append (Payload, U32 (Version));
      Append_String (Payload, SSH_Lib.SFTP.Versions_Extension);
      Append_String (Payload, "3,4,5,6");
      return Framed (Payload);
   end Version_Reply;

   function Status_Reply
     (Request_Id : Interfaces.Unsigned_32;
      Code       : Interfaces.Unsigned_32 := SSH_Lib.SFTP.SSH_FX_OK)
      return Stream_Element_Array
   is
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   begin
      Append_Byte (Payload, SSH_Lib.SFTP.SSH_FXP_STATUS);
      Append (Payload, U32 (Request_Id));
      Append (Payload, U32 (Code));
      Append_String (Payload, "ok");
      Append_String (Payload, "en");
      return Framed (Payload);
   end Status_Reply;

   function Handle_Reply
     (Request_Id : Interfaces.Unsigned_32;
      Handle     : String) return Stream_Element_Array
   is
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   begin
      Append_Byte (Payload, SSH_Lib.SFTP.SSH_FXP_HANDLE);
      Append (Payload, U32 (Request_Id));
      Append_String (Payload, Handle);
      return Framed (Payload);
   end Handle_Reply;

   function Data_Reply
     (Request_Id : Interfaces.Unsigned_32;
      Data       : String) return Stream_Element_Array
   is
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   begin
      Append_Byte (Payload, SSH_Lib.SFTP.SSH_FXP_DATA);
      Append (Payload, U32 (Request_Id));
      Append_String (Payload, Data);
      return Framed (Payload);
   end Data_Reply;

   function Attrs_Reply
     (Request_Id : Interfaces.Unsigned_32;
      Version    : Natural;
      Size       : Interfaces.Unsigned_64) return Stream_Element_Array
   is
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   begin
      Append_Byte (Payload, SSH_Lib.SFTP.SSH_FXP_ATTRS);
      Append (Payload, U32 (Request_Id));
      if Version <= 3 then
         Append (Payload, U32 (1));
         Append (Payload, U64 (Size));
      else
         Append (Payload, U32 (1));
         Append_Byte (Payload, 1);
         Append (Payload, U64 (Size));
      end if;
      return Framed (Payload);
   end Attrs_Reply;

   procedure Queue
     (Channel : in out SSH_Lib.Channels.Channel;
      Packet  : Stream_Element_Array)
   is
   begin
      AUnit.Assertions.Assert
        (SSH_Lib.Channels.Test_Support.Queue_Stdout_For_Test
           (Channel, Packet) = CryptoLib.Errors.Ok,
         "queue fake SFTP reply");
   end Queue;

   procedure Assert_Ok
     (Status_Value : CryptoLib.Errors.Status;
      Label        : String)
   is
   begin
      AUnit.Assertions.Assert
        (Status_Value = CryptoLib.Errors.Ok, Label & ": " & CryptoLib.Errors.Status'Image (Status_Value));
   end Assert_Ok;

   procedure Run_Versioned_Open_Read_Write_Close
     (Requested_Version : Interfaces.Unsigned_32)
   is
      Channel      : SSH_Lib.Channels.Channel;
      Version      : Natural := 0;
      Extensions   : SSH_Lib.SFTP.Extension_Info;
      Read_Handle  : SSH_Lib.SFTP.File_Handle;
      Write_Handle : SSH_Lib.SFTP.File_Handle;
      Read_Data    : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test (Channel);

      Queue (Channel, Version_Reply (Requested_Version));
      Assert_Ok
        (SSH_Lib.SFTP.Initialize
           (Channel, Natural (Requested_Version), Version, Extensions),
         "initialize fake SFTP subsystem");
      AUnit.Assertions.Assert
        (Version = Natural (Requested_Version), "negotiated requested version");
      AUnit.Assertions.Assert
        (Extensions.Versions
         and then Extensions.Version_3
         and then Extensions.Version_4
         and then Extensions.Version_5
         and then Extensions.Version_6,
         "parsed versions extension from fake subsystem");
      Queue (Channel, Handle_Reply (1, "read-handle"));
      Assert_Ok
        (SSH_Lib.SFTP.Open_Read
           (Channel, "/fixture/read.txt", Read_Handle, Version),
         "open read handle");
      AUnit.Assertions.Assert
        (SSH_Lib.SFTP.Is_Open (Read_Handle), "read handle is open");

      Queue (Channel, Attrs_Reply (1, Version, 12));
      declare
         Attributes : SSH_Lib.SFTP.File_Attributes;
      begin
         Assert_Ok
           (SSH_Lib.SFTP.FStat (Channel, Read_Handle, Attributes),
            "fstat read handle");
         AUnit.Assertions.Assert
           (Attributes.Size_Known and then Attributes.Size = 12,
            "parsed fstat size");
      end;

      Queue (Channel, Data_Reply (1, "fake-data"));
      Assert_Ok
        (SSH_Lib.SFTP.Read_At (Channel, Read_Handle, 0, 9, Read_Data),
         "read from fake handle");
      AUnit.Assertions.Assert
        (SSH_Lib.Protocol.Buffers.To_Array (Read_Data) = Bytes ("fake-data"),
         "read bytes from fake subsystem");

      Queue (Channel, Status_Reply (1));
      Assert_Ok
        (SSH_Lib.SFTP.Close (Channel, Read_Handle), "close read handle");
      AUnit.Assertions.Assert
        (not SSH_Lib.SFTP.Is_Open (Read_Handle), "read handle closed");

      Queue (Channel, Handle_Reply (1, "write-handle"));
      Assert_Ok
        (SSH_Lib.SFTP.Open_File
           (Channel,
            "/fixture/write.txt",
            Write_Handle,
            SSH_Lib.SFTP.Write_Truncate,
            "0644",
            Version),
         "open write handle");
      AUnit.Assertions.Assert
        (SSH_Lib.SFTP.Is_Open (Write_Handle), "write handle is open");

      Queue (Channel, Status_Reply (1));
      Assert_Ok
        (SSH_Lib.SFTP.Write_At
           (Channel, Write_Handle, 0, Bytes ("upload")),
         "write to fake handle");

      Queue (Channel, Status_Reply (1));
      Assert_Ok
        (SSH_Lib.SFTP.Close (Channel, Write_Handle), "close write handle");
      AUnit.Assertions.Assert
        (not SSH_Lib.SFTP.Is_Open (Write_Handle), "write handle closed");
   end Run_Versioned_Open_Read_Write_Close;

   procedure Run_V3 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Run_Versioned_Open_Read_Write_Close (3);
   end Run_V3;

   procedure Run_V4 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Run_Versioned_Open_Read_Write_Close (4);
   end Run_V4;

   procedure Run_V5 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Run_Versioned_Open_Read_Write_Close (5);
   end Run_V5;

   procedure Run_V6 (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      Run_Versioned_Open_Read_Write_Close (6);
   end Run_V6;

   overriding procedure Register_Tests (Item : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (Item, Run_V3'Access, "fake SFTP subsystem v3");
      Register_Routine (Item, Run_V4'Access, "fake SFTP subsystem v4");
      Register_Routine (Item, Run_V5'Access, "fake SFTP subsystem v5");
      Register_Routine (Item, Run_V6'Access, "fake SFTP subsystem v6");
   end Register_Tests;

   overriding function Name (Item : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (Item);
   begin
      return AUnit.Format ("SSH_Lib fake SFTP subsystem tests");
   end Name;
end SSH_Lib.Tests.Fixtures.SFTP_Fake_Subsystem;
