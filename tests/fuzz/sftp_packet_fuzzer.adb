with Ada.Command_Line;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with CryptoLib.Errors;
with Interfaces;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.SFTP;

procedure SFTP_Packet_Fuzzer is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use type Ada.Streams.Stream_IO.Count;
   use type CryptoLib.Errors.Status;

   Expected_Id : constant Interfaces.Unsigned_32 := 1;

   function Load_File (Path : String) return Stream_Element_Array is
      File_Item : Ada.Streams.Stream_IO.File_Type;
   begin
      Ada.Streams.Stream_IO.Open
        (File_Item, Ada.Streams.Stream_IO.In_File, Path);
      declare
         Size : constant Ada.Streams.Stream_IO.Count :=
           Ada.Streams.Stream_IO.Size (File_Item);
      begin
         if Size = 0 then
            Ada.Streams.Stream_IO.Close (File_Item);
            return Stream_Element_Array'(1 .. 0 => 0);
         end if;

         declare
            Data : Stream_Element_Array (1 .. Stream_Element_Offset (Size));
            Last : Stream_Element_Offset;
         begin
            Ada.Streams.Stream_IO.Read (File_Item, Data, Last);
            Ada.Streams.Stream_IO.Close (File_Item);
            if Last < Data'Last then
               return Data (Data'First .. Last);
            end if;
            return Data;
         end;
      end;
   exception
      when others =>
         if Ada.Streams.Stream_IO.Is_Open (File_Item) then
            Ada.Streams.Stream_IO.Close (File_Item);
         end if;
         return Stream_Element_Array'(1 .. 0 => 0);
   end Load_File;

   procedure Run_Parser
     (Mode   : String;
      Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : out CryptoLib.Errors.Status) is
      Version    : Natural := 0;
      Extensions : SSH_Lib.SFTP.Extension_Info;
      Scratch    : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Algorithm  : Unbounded_String;
      Limits     : SSH_Lib.SFTP.Server_Limits;
      Stats      : SSH_Lib.SFTP.File_System_Stats;
      Attributes : SSH_Lib.SFTP.File_Attributes;
      Names      : Unbounded_String;
   begin
      if Mode = "version" then
         Status_Value := SSH_Lib.SFTP.Parse_Version_Packet
           (Buffer, Version, Extensions);
      elsif Mode = "status" then
         Status_Value := SSH_Lib.SFTP.Parse_Status_Packet
           (Buffer, Expected_Id);
      elsif Mode = "handle" then
         Status_Value := SSH_Lib.SFTP.Parse_Handle_Packet
           (Buffer, Expected_Id, Scratch);
      elsif Mode = "extended" then
         Status_Value := SSH_Lib.SFTP.Parse_Extended_Reply_Packet
           (Buffer, Expected_Id, Scratch);
      elsif Mode = "check-file" then
         Status_Value := SSH_Lib.SFTP.Parse_Check_File_Packet
           (Buffer, Expected_Id, Algorithm, Scratch);
      elsif Mode = "limits" then
         Status_Value := SSH_Lib.SFTP.Parse_Limits_Packet
           (Buffer, Expected_Id, Limits);
      elsif Mode = "statvfs" then
         Status_Value := SSH_Lib.SFTP.Parse_StatVFS_Packet
           (Buffer, Expected_Id, Stats);
      elsif Mode = "attrs-v3" then
         Status_Value := SSH_Lib.SFTP.Parse_Attrs_Packet
           (Buffer, Expected_Id, Attributes);
      elsif Mode = "attrs-v6" then
         Status_Value := SSH_Lib.SFTP.Parse_Attrs_Packet
           (Buffer, Expected_Id, Attributes, 6);
      elsif Mode = "data" then
         Status_Value := SSH_Lib.SFTP.Parse_Data_Packet
           (Buffer, Expected_Id, Scratch);
      elsif Mode = "name-v3" then
         Status_Value := SSH_Lib.SFTP.Parse_Name_Packet
           (Buffer, Expected_Id, Names);
      elsif Mode = "name-v6" then
         Status_Value := SSH_Lib.SFTP.Parse_Name_Packet
           (Buffer, Expected_Id, Names, 6);
      else
         Status_Value := CryptoLib.Errors.Invalid_Command;
      end if;
   end Run_Parser;

   Buffer       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   Status_Value : CryptoLib.Errors.Status;
   Mode         : Unbounded_String := To_Unbounded_String ("version");
   Path         : Unbounded_String;
begin
   if Ada.Command_Line.Argument_Count = 1 then
      Path := To_Unbounded_String (Ada.Command_Line.Argument (1));
   elsif Ada.Command_Line.Argument_Count = 2 then
      Mode := To_Unbounded_String (Ada.Command_Line.Argument (1));
      Path := To_Unbounded_String (Ada.Command_Line.Argument (2));
   else
      Ada.Text_IO.Put_Line
        ("usage: sftp_packet_fuzzer [MODE] INPUT_FILE");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   declare
      Data : constant Stream_Element_Array := Load_File (To_String (Path));
   begin
      Status_Value := SSH_Lib.Protocol.Buffers.Set (Buffer, Data);
      if Status_Value = CryptoLib.Errors.Ok then
         Run_Parser (To_String (Mode), Buffer, Status_Value);
      end if;
   end;

   --  A fuzzer input is interesting when it crashes or violates runtime checks.
   --  All ordinary parser statuses are accepted outcomes.
   Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Success);
end SFTP_Packet_Fuzzer;
