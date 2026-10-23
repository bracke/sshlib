with SSH_Lib.Heap_Rooms;

--  @summary A mux message held on the heap: its payload's whole room, a
--  quarter of a megabyte, which made a frame that size where one was
--  declared.
package SSH_Lib.Mux.Message_Rooms is new SSH_Lib.Heap_Rooms.Holders (SSH_Lib.Mux.Mux_Message);
