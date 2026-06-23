package SSH_Lib.Tests.Fixtures.Live_Channel_Transport is
   procedure Assert_Live_Channel_Transport_Boundary;

   procedure Assert_Live_Channel_Exit_Status_And_Close;

   procedure Assert_Live_Channel_Disconnect_Marks_Failed;

   procedure Assert_Live_Write_Drains_Window_Adjust;

   procedure Assert_Open_Exec_Disconnects_Map_To_Connection_Failed;

   procedure Assert_Data_After_EOF_Is_Rejected;

   procedure Assert_Request_After_Close_Is_Rejected;

   procedure Assert_Duplicate_EOF_And_Close_Are_Rejected;

   procedure Assert_Duplicate_Exit_Status_Is_Rejected;

   procedure Assert_Data_After_Terminal_Status_Is_Rejected;

   procedure Assert_Request_After_Terminal_Status_Is_Rejected;

   procedure Assert_Window_Adjust_After_Terminal_Status_Is_Ignored;

   procedure Assert_Window_Adjust_After_Close_And_Status_Is_Rejected;

   procedure Assert_Exit_Signal_Is_Nonzero_Result;

   procedure Assert_Malformed_Exit_Signal_Is_Rejected;

   procedure Assert_Channel_IO_After_Session_Close_Is_Rejected;

   procedure Assert_Inbound_After_Local_Close_Is_Rejected;

   procedure Assert_Window_Adjust_After_Local_EOF_Is_Ignored;

   procedure Assert_Multiple_Stderr_Packets_Are_Accumulated;

   procedure Assert_Inbound_Exec_Stream_Before_Exec_Success_Is_Rejected;

   procedure Assert_Dirty_Live_Read_Does_Not_Drain_Protected_Input;

   procedure Assert_Background_Stop_Propagates_Terminal_Failure;

   procedure Assert_Background_Restart_After_Terminal_Failure_Is_Rejected;

   procedure Assert_Write_After_Background_Terminal_Failure_Is_Rejected;

   procedure Assert_Exit_Status_After_Background_Terminal_Failure_Preserves_Status;

   procedure Assert_Close_After_Background_Terminal_Failure_Is_Local_Cleanup;

   procedure Assert_Idempotent_Close_Preserves_Background_Terminal_Failure;

   procedure Assert_Read_After_Background_Terminal_Failure_Does_Not_Drain;

   procedure Assert_Background_Reader_After_Terminal_Status_Is_Rejected;

   procedure Assert_Background_Terminal_Failure_Precedes_Dirty_State;

   procedure Assert_Repeated_EOF_After_Background_Terminal_Failure_Preserves_Status;

   procedure Assert_Close_Detaches_Live_Channel_IO;
   procedure Assert_Close_Exception_Detaches_Live_Channel_IO;

   procedure Assert_Close_Exception_Preserves_Background_Terminal_Failure;

   procedure Assert_Background_Running_Is_False_After_Terminal_Failure;

   procedure Assert_Stop_Background_Exception_Preserves_Terminal_Failure;

   procedure Assert_Background_Task_Exception_Preserves_Terminal_Failure;
   procedure Assert_Background_Task_Exception_Normalizes_Stale_Timeout;

   procedure Assert_Background_Normal_Failure_Mirrors_Last_Failure;

   procedure Assert_Background_Timeout_Status_Normalizes_After_Stop;
   procedure Assert_Background_Running_Requires_Request_Flag;
   procedure Assert_Background_Timeout_Status_Uses_Public_Liveness;

   procedure Assert_Start_Background_Clears_Stale_Running_Without_Request;

   procedure Assert_Start_Background_Clears_Stale_Request_Without_Task;

   procedure Assert_Background_Running_Requires_Attached_Task;

   procedure Assert_Start_Background_Exception_Preserves_Terminal_Failure;
   procedure Assert_Start_Background_Exception_Normalizes_Stale_Timeout;

   procedure Assert_Stop_Background_Normalizes_Stale_Timeout;
   procedure Assert_Stop_Background_Exception_Normalizes_Stale_Timeout;
end SSH_Lib.Tests.Fixtures.Live_Channel_Transport;
