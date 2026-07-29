with Ada.Streams;
with Ada.Text_IO;
with Interfaces;
with SSH_Lib.Channels;
with SSH_Lib.Channels.Test_Support;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Channels;
with SSH_Lib.Protocol.Failure_State;
with SSH_Lib.Sessions;
with SSH_Lib.Sessions.Test_Support;
with SSH_Lib.Tests.Assertions;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Numbers;

package body SSH_Lib.Tests.Fixtures.Timeout_Dirty is

   use Ada.Streams;
   use type CryptoLib.Errors.Status;

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   procedure Check_Status
     (Actual_Status   : CryptoLib.Errors.Status;
      Expected_Status : CryptoLib.Errors.Status;
      Label_Text      : String)
   is
   begin
      SSH_Lib.Tests.Assertions.Check_Status
        (Actual_Status, Expected_Status, "timeout dirty", Label_Text);
   end Check_Status;

   function Sample_Data return Stream_Element_Array is
   begin
      return [1 => 16#00#, 2 => 16#41#, 3 => 16#0A#,
              4 => 16#80#, 5 => 16#FF#, 6 => 16#42#];
   end Sample_Data;

   function Open_Confirmation
     (Local_Channel  : Interfaces.Unsigned_32;
      Remote_Channel : Interfaces.Unsigned_32)
      return Stream_Element_Array
   is
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.Protocol.Buffers.Append_Byte
        (Payload, SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
      if Status_Value /= CryptoLib.Errors.Ok then
         return [1 .. 0 => 0];
      end if;
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Payload, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Local_Channel));
      if Status_Value /= CryptoLib.Errors.Ok then
         return [1 .. 0 => 0];
      end if;
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Payload, SSH_Lib.Protocol.Numbers.Encode_Uint32 (Remote_Channel));
      if Status_Value /= CryptoLib.Errors.Ok then
         return [1 .. 0 => 0];
      end if;
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Payload,
         SSH_Lib.Protocol.Numbers.Encode_Uint32
           (SSH_Lib.Protocol.Channels.Default_Initial_Window_Size));
      if Status_Value /= CryptoLib.Errors.Ok then
         return [1 .. 0 => 0];
      end if;
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Payload,
         SSH_Lib.Protocol.Numbers.Encode_Uint32
           (SSH_Lib.Protocol.Channels.Default_Maximum_Packet_Size));
      if Status_Value /= CryptoLib.Errors.Ok then
         return [1 .. 0 => 0];
      end if;
      return SSH_Lib.Protocol.Buffers.To_Array (Payload);
   end Open_Confirmation;

   procedure Check_Silent_Channel_Read_Timeout is
      Channel_Item : SSH_Lib.Channels.Channel;
      Buffer       : Stream_Element_Array (1 .. 8);
      Last_Index   : Stream_Element_Offset := Buffer'First;
      Result_Status : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test (Channel_Item);
      Result_Status := SSH_Lib.Channels.Read_Some
        (Channel_Item, Buffer, Last_Index);
      Check_Status
        (Result_Status, CryptoLib.Errors.Timeout,
         "silent active channel read maps to Timeout");
      Check
        (not SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "read timeout before receiving bytes does not dirty channel");
      Check
        (Last_Index = Buffer'First - 1,
         "read timeout does not expose stale bytes");
   end Check_Silent_Channel_Read_Timeout;

   procedure Check_Window_Write_Timeout_Before_Bytes is
      Channel_Item : SSH_Lib.Channels.Channel;
      Data_Value   : constant Stream_Element_Array := Sample_Data;
      Result_Status : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item, Remote_Remaining_Window => 0);
      Result_Status := SSH_Lib.Channels.Write (Channel_Item, Data_Value);
      Check_Status
        (Result_Status, CryptoLib.Errors.Timeout,
         "write with no remote window maps to Timeout");
      Check
        (not SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "write timeout before any emitted bytes leaves channel clean");
      Check
        (SSH_Lib.Channels.Test_Support.Outbound_Data_Byte_Count_For_Test
           (Channel_Item) = 0,
         "pre-byte write timeout emits no ambiguous data");
   end Check_Window_Write_Timeout_Before_Bytes;

   procedure Check_Partial_Write_Timeout_Dirties_Channel is
      Channel_Item : SSH_Lib.Channels.Channel;
      Data_Value   : constant Stream_Element_Array := Sample_Data;
      Result_Status : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Remote_Remaining_Window    => 3,
         Remote_Maximum_Packet_Size => 3);
      SSH_Lib.Channels.Test_Support.Set_Write_Timeout_After_Partial_For_Test
        (Channel_Item, True);
      Result_Status := SSH_Lib.Channels.Write (Channel_Item, Data_Value);
      Check_Status
        (Result_Status, CryptoLib.Errors.Timeout,
         "partial write timeout returns Timeout");
      Check
        (SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "partial write timeout dirties channel");
      Check_Status
        (SSH_Lib.Channels.Test_Support.Last_Failure_For_Test (Channel_Item),
         CryptoLib.Errors.Timeout,
         "partial write timeout records timeout failure");
      Check
        (SSH_Lib.Channels.Test_Support.Outbound_Data_Byte_Count_For_Test
           (Channel_Item) = 3,
         "partial write timeout records exactly emitted prefix");
      Result_Status := SSH_Lib.Channels.Write (Channel_Item, Data_Value);
      Check_Status
        (Result_Status, CryptoLib.Errors.Write_Failed,
         "retry after dirty partial-write timeout is rejected");
   end Check_Partial_Write_Timeout_Dirties_Channel;

   procedure Check_Partial_Write_Socket_Failure_Dirties_Channel is
      Channel_Item : SSH_Lib.Channels.Channel;
      Data_Value   : constant Stream_Element_Array := Sample_Data;
      Result_Status : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test
        (Channel_Item,
         Remote_Remaining_Window    => 3,
         Remote_Maximum_Packet_Size => 3);
      SSH_Lib.Channels.Test_Support.Set_Remote_Close_After_Partial_For_Test
        (Channel_Item, True);
      Result_Status := SSH_Lib.Channels.Write (Channel_Item, Data_Value);
      Check_Status
        (Result_Status, CryptoLib.Errors.Write_Failed,
         "partial write socket failure returns Write_Failed");
      Check
        (SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "partial write socket failure dirties channel");
      Check
        (SSH_Lib.Channels.Test_Support.Outbound_Data_Byte_Count_For_Test
           (Channel_Item) = 3,
         "partial socket failure records emitted prefix");
      Result_Status := SSH_Lib.Channels.Send_EOF (Channel_Item);
      Check_Status
        (Result_Status, CryptoLib.Errors.Channel_Request_Failed,
         "dirty channel cannot send EOF after ambiguous write");
   end Check_Partial_Write_Socket_Failure_Dirties_Channel;

   procedure Check_Close_After_Dirty_State_Is_Idempotent is
      Channel_Item : SSH_Lib.Channels.Channel;
      Result_Status : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Channels.Test_Support.Mark_Exec_Active_For_Test (Channel_Item);
      SSH_Lib.Channels.Test_Support.Mark_Dirty_For_Test
        (Channel_Item, CryptoLib.Errors.Write_Failed);
      Result_Status := SSH_Lib.Channels.Close (Channel_Item);
      Check_Status
        (Result_Status, CryptoLib.Errors.Ok,
         "close after dirty channel returns Ok");
      Result_Status := SSH_Lib.Channels.Close (Channel_Item);
      Check_Status
        (Result_Status, CryptoLib.Errors.Ok,
         "second close after dirty cleanup remains Ok");
      Check
        (not SSH_Lib.Channels.Test_Support.Is_Dirty_For_Test (Channel_Item),
         "close clears dirty channel handle state");
   end Check_Close_After_Dirty_State_Is_Idempotent;

   procedure Check_Dirty_Session_Cannot_Open_Channel is
      Session_Item : SSH_Lib.Sessions.Session;
      Channel_Item : SSH_Lib.Channels.Channel;
      Result_Status : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
      SSH_Lib.Sessions.Test_Support.Mark_Dirty_For_Test
        (Session_Item, CryptoLib.Errors.Read_Failed);
      Result_Status := SSH_Lib.Channels.Open_Exec
        (Session_Item, "git-upload-pack 'repo.git'", Channel_Item);
      Check_Status
        (Result_Status, CryptoLib.Errors.Channel_Open_Failed,
         "dirty session cannot open channel");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Dirty_For_Test (Session_Item),
         "failed channel open on dirty session preserves dirty state");
      Check
        (SSH_Lib.Sessions.Test_Support.Active_Channel_Count_For_Test
           (Session_Item) = 0,
         "dirty session open attempt does not allocate channel slot");
   end Check_Dirty_Session_Cannot_Open_Channel;

   procedure Check_Open_Exec_Timeout_Dirties_Session_And_Closes_Channel is
      Session_Item : SSH_Lib.Sessions.Session;
      Channel_Item : SSH_Lib.Channels.Channel;
      Result_Status : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
      SSH_Lib.Sessions.Test_Support.Set_Channel_Open_Timeout_For_Test
        (Session_Item, True);
      Result_Status := SSH_Lib.Channels.Open_Exec
        (Session_Item, "git-upload-pack 'repo.git'", Channel_Item);
      Check_Status
        (Result_Status, CryptoLib.Errors.Timeout,
         "silent server during channel open maps to Timeout");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Dirty_For_Test (Session_Item),
         "channel-open timeout dirties session because read synchronization is lost");
      Check
        (SSH_Lib.Sessions.Test_Support.Active_Channel_Count_For_Test
           (Session_Item) = 0,
         "failed Open_Exec releases channel slot");
      Result_Status := SSH_Lib.Channels.Write (Channel_Item, Sample_Data);
      Check_Status
        (Result_Status, CryptoLib.Errors.Write_Failed,
         "failed Open_Exec leaves returned channel closed/unusable");
   end Check_Open_Exec_Timeout_Dirties_Session_And_Closes_Channel;

   procedure Check_Exec_Timeout_Dirties_Session_And_Releases_Channel is
      Session_Item : SSH_Lib.Sessions.Session;
      Channel_Item : SSH_Lib.Channels.Channel;
      Result_Status : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Sessions.Test_Support.Mark_Authenticated_Open_For_Test (Session_Item);
      Result_Status := SSH_Lib.Sessions.Test_Support.Queue_Channel_Open_Response_For_Test
        (Session_Item, Open_Confirmation (0, 1));
      Check_Status (Result_Status, CryptoLib.Errors.Ok, "queue open confirmation");
      SSH_Lib.Sessions.Test_Support.Set_Channel_Exec_Timeout_For_Test
        (Session_Item, True);
      Result_Status := SSH_Lib.Channels.Open_Exec
        (Session_Item, "git-upload-pack 'repo.git'", Channel_Item);
      Check_Status
        (Result_Status, CryptoLib.Errors.Timeout,
         "silent server during exec request maps to Timeout");
      Check
        (SSH_Lib.Sessions.Test_Support.Is_Dirty_For_Test (Session_Item),
         "exec-reply timeout dirties session");
      Check
        (SSH_Lib.Sessions.Test_Support.Active_Channel_Count_For_Test
           (Session_Item) = 0,
         "exec timeout releases transient channel slot");
   end Check_Exec_Timeout_Dirties_Session_And_Releases_Channel;

   procedure Check_Timeout_Classification_Guards is
   begin
      Check
        (SSH_Lib.Protocol.Failure_State.Session_Must_Be_Dirtied
           (CryptoLib.Errors.Timeout),
         "timeout after synchronization boundary requires dirty session");
      Check
        (SSH_Lib.Protocol.Failure_State.Channel_Must_Be_Dirtied
           (CryptoLib.Errors.Timeout, Partial_IO => True),
         "timeout after partial channel I/O requires dirty channel");
      Check
        (SSH_Lib.Protocol.Failure_State.Dirty_Channel_Write_Status =
           CryptoLib.Errors.Write_Failed,
         "dirty channel write maps to Write_Failed");
      Check
        (SSH_Lib.Protocol.Failure_State.Dirty_Session_Operation_Status =
           CryptoLib.Errors.Channel_Open_Failed,
         "dirty session channel operation maps to Channel_Open_Failed");
   end Check_Timeout_Classification_Guards;

   procedure Assert_All_Timeout_And_Dirty_State_Behavior is
   begin
      Check_Timeout_Classification_Guards;
      Check_Silent_Channel_Read_Timeout;
      Check_Window_Write_Timeout_Before_Bytes;
      Check_Partial_Write_Timeout_Dirties_Channel;
      Check_Partial_Write_Socket_Failure_Dirties_Channel;
      Check_Close_After_Dirty_State_Is_Idempotent;
      Check_Dirty_Session_Cannot_Open_Channel;
      Check_Open_Exec_Timeout_Dirties_Session_And_Closes_Channel;
      Check_Exec_Timeout_Dirties_Session_And_Releases_Channel;
   end Assert_All_Timeout_And_Dirty_State_Behavior;
end SSH_Lib.Tests.Fixtures.Timeout_Dirty;
