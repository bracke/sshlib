with Ada.Streams;
with Interfaces;
with CryptoLib.Errors;

package SSH_Lib.Channels.Test_Support is
   procedure Mark_Exec_Active_For_Test
     (Item                         : in out Channel;
      Local_Channel_Id             : Interfaces.Unsigned_32 := 0;
      Remote_Channel_Id            : Interfaces.Unsigned_32 := 1;
      Remote_Remaining_Window      : Interfaces.Unsigned_32 := 2_097_152;
      Remote_Maximum_Packet_Size   : Interfaces.Unsigned_32 := 32_768);


   procedure Mark_Channel_Open_Not_Exec_For_Test
     (Item                         : in out Channel;
      Local_Channel_Id             : Interfaces.Unsigned_32 := 0;
      Remote_Channel_Id            : Interfaces.Unsigned_32 := 1;
      Remote_Remaining_Window      : Interfaces.Unsigned_32 := 2_097_152;
      Remote_Maximum_Packet_Size   : Interfaces.Unsigned_32 := 32_768);

   procedure Mark_Exit_Status_Known_For_Test
     (Item : in out Channel;
      Code : Integer);

   procedure Mark_Local_Close_Sent_For_Test
     (Item : in out Channel);

   procedure Mark_Local_EOF_Sent_For_Test
     (Item : in out Channel);

   function Queue_Stdout_For_Test
     (Item : in out Channel;
      Data : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Queue_Stderr_For_Test
     (Item : in out Channel;
      Data : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Dispatch_Inbound_Payload_For_Test
     (Item    : in out Channel;
      Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Last_Channel_Data_Payload_For_Test
     (Item : Channel)
      return Ada.Streams.Stream_Element_Array;

   function Last_EOF_Payload_For_Test
     (Item : Channel)
      return Ada.Streams.Stream_Element_Array;

   function Last_Close_Payload_For_Test
     (Item : Channel)
      return Ada.Streams.Stream_Element_Array;

   function Last_Window_Adjust_Payload_For_Test
     (Item : Channel)
      return Ada.Streams.Stream_Element_Array;

   function Last_Channel_Success_Payload_For_Test
     (Item : Channel)
      return Ada.Streams.Stream_Element_Array;

   function Last_Channel_Failure_Payload_For_Test
     (Item : Channel)
      return Ada.Streams.Stream_Element_Array;

   function Outbound_Data_Byte_Count_For_Test (Item : Channel) return Natural;

   function Outbound_Data_Packet_Count_For_Test (Item : Channel) return Natural;

   function Local_Remaining_Window_For_Test
     (Item : Channel)
      return Interfaces.Unsigned_32;

   function Remote_Remaining_Window_For_Test
     (Item : Channel)
      return Interfaces.Unsigned_32;

   procedure Set_Local_Window_For_Test
     (Item                  : in out Channel;
      Initial_Window_Size   : Interfaces.Unsigned_32;
      Remaining_Window_Size : Interfaces.Unsigned_32);

   procedure Set_Write_Timeout_After_Partial_For_Test
     (Item  : in out Channel;
      Value : Boolean);

   procedure Set_Send_EOF_Timeout_For_Test
     (Item  : in out Channel;
      Value : Boolean);

   procedure Set_Remote_Close_After_Partial_For_Test
     (Item  : in out Channel;
      Value : Boolean);

   procedure Set_Close_Timeout_For_Test
     (Item  : in out Channel;
      Value : Boolean);

   procedure Set_Close_Exception_For_Cleanup_Test
     (Item  : in out Channel;
      Value : Boolean);

   procedure Set_Timeouts_For_Test
     (Item             : in out Channel;
      Read_Timeout_MS  : Natural;
      Write_Timeout_MS : Natural);

   procedure Mark_Dirty_For_Test
     (Item   : in out Channel;
      Reason : CryptoLib.Errors.Status := CryptoLib.Errors.Read_Failed);

   function Is_Dirty_For_Test (Item : Channel) return Boolean;

   function Last_Failure_For_Test (Item : Channel) return CryptoLib.Errors.Status;


   procedure Enable_Live_Channel_IO_For_Test (Item : in out Channel);

   function Queue_Protected_Inbound_For_Test
     (Item    : in out Channel;
      Payload : Ada.Streams.Stream_Element_Array)
      return CryptoLib.Errors.Status;

   function Last_Protected_Outbound_For_Test
     (Item : Channel)
      return Ada.Streams.Stream_Element_Array;

   function Pending_Stdout_Length_For_Test (Item : Channel) return Natural;

   function Live_Channel_IO_Enabled_For_Test (Item : Channel) return Boolean;

   procedure Set_Background_Last_Status_For_Test
     (Item   : in out Channel;
      Status_Value : CryptoLib.Errors.Status);

   procedure Set_Background_Running_For_Test
     (Item  : in out Channel;
      Value : Boolean);

   procedure Set_Background_Requested_For_Test
     (Item  : in out Channel;
      Value : Boolean);

   procedure Set_Stop_Background_Exception_For_Cleanup_Test
     (Item  : in out Channel;
      Value : Boolean);

   procedure Set_Background_Task_Exception_For_Cleanup_Test
     (Item  : in out Channel;
      Value : Boolean);

   procedure Set_Background_Drain_Terminal_Failure_For_Test
     (Item  : in out Channel;
      Value : Boolean);

   procedure Set_Start_Background_Exception_For_Cleanup_Test
     (Item  : in out Channel;
      Value : Boolean);

   function Pending_Stderr_Length_For_Test (Item : Channel) return Natural;
end SSH_Lib.Channels.Test_Support;
