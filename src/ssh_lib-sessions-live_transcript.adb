with Ada.Calendar;
with Ada.Characters.Handling;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Unchecked_Deallocation;
with GNAT.OS_Lib;
with Interfaces.C;
with System;
with SSH_Lib.Protocol.Identification;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Channels;
with SSH_Lib.Protocol.Global_Requests;
with SSH_Lib.Protocol.Transport_Messages;
with SSH_Lib.Mux;

package body SSH_Lib.Sessions.Live_Transcript is
   use type Ada.Calendar.Time;
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use Interfaces;
   use CryptoLib.Errors;
   use type GNAT.OS_Lib.File_Descriptor;
   use type GNAT.OS_Lib.String_Access;
   use type GNAT.Sockets.Family_Type;
   use type Interfaces.C.int;
   use type SSH_Lib.Mux.Mux_Message_Kind;

   procedure Free_Driver is new
     Ada.Unchecked_Deallocation (Driver, Driver_Access);

   Max_Identification_Reads : constant Natural :=
     SSH_Lib.Protocol.Identification.Max_Banner_Lines + 2;

   Max_Identification_Bytes : constant Natural :=
     (SSH_Lib.Protocol.Identification.Max_Banner_Lines + 1)
     * SSH_Lib.Protocol.Identification.Max_Identification_Line_Length;

   type Poll_FD is record
      FD      : Interfaces.C.int;
      Events  : Interfaces.C.short;
      Revents : Interfaces.C.short;
   end record
     with Convention => C;

   Poll_Input_Event  : constant Interfaces.C.short := 16#0001#;
   Poll_Output_Event : constant Interfaces.C.short := 16#0004#;

   function C_Poll
     (FDs     : access Poll_FD;
      NFDs    : Interfaces.C.unsigned_long;
      Timeout : Interfaces.C.int) return Interfaces.C.int
     with Import, Convention => C, External_Name => "poll";

   function C_Setsockopt
     (Socket : Interfaces.C.int;
      Level  : Interfaces.C.int;
      Option : Interfaces.C.int;
      Optval : System.Address;
      Optlen : Interfaces.C.int) return Interfaces.C.int
     with Import, Convention => C, External_Name => "setsockopt";

   Max_Proxy_IO_Chunk : constant Stream_Element_Offset := 4096;

   procedure Close_Socket_Quietly (Socket_Item : GNAT.Sockets.Socket_Type) is
   begin
      GNAT.Sockets.Close_Socket (Socket_Item);
   exception
      when others =>
         null;
   end Close_Socket_Quietly;

   procedure Reset (Item : out Driver) is
   begin
      Item.Mode := Socket_Mode;
      Item.Outer_Driver := null;
      Item.Owns_Outer_Driver := False;
      Item.Jump_Local_Channel := 0;
      Item.Jump_Remote_Channel := 0;
      SSH_Lib.Protocol.Buffers.Clear (Item.Jump_Read_Buffer);
      Item.Proxy_Process_Open := False;
      Item.Connected := False;
      SSH_Lib.Protocol.Packets.Reset (Item.Clear_State);
      SSH_Lib.Protocol.Protected_Packets.Reset
        (Item.Protected_State, [1 .. 32 => 0]);
      Item.Protected_Installed := False;
      Item.Local_Identification_Text :=
        To_Unbounded_String
          (SSH_Lib.Protocol.Identification.Local_Identification);
      Item.Remote_Identification_Text := Null_Unbounded_String;
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_Clear_Out);
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_Clear_In);
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_Protected_Out);
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_Protected_In);
      Item.Read_Timeout_Configured := False;
      Item.Write_Timeout_Configured := False;
      Item.Read_Timeout_MS := 0;
      Item.Write_Timeout_MS := 0;
      Item.Caller_Read_Timeout_Configured := False;
      Item.Server_Alive_Interval_MS := 0;
      Item.Server_Alive_Count_Max := 3;
      Item.Server_Alive_Missed := 0;
      Item.Server_Alive_Awaiting_Reply := False;
      Item.Proxy_Command_Diagnostic_Item := (others => <>);
   exception
      when others =>
         null;
   end Reset;

   function Timeout_Value (Milliseconds : Natural) return Duration is
   begin
      if Milliseconds = 0 then
         return 0.0;
      end if;
      return Duration (Milliseconds) / 1000.0;
   end Timeout_Value;

   procedure Apply_Socket_Read_Timeout (Item : in out Driver) is
   begin
      if Item.Mode = Socket_Mode
        and then Item.Connected
        and then Item.Read_Timeout_Configured
      then
         GNAT.Sockets.Set_Socket_Option
           (Item.Socket_Item,
            GNAT.Sockets.Socket_Level,
            (Name    => GNAT.Sockets.Receive_Timeout,
             Timeout => Timeout_Value (Item.Read_Timeout_MS)));
      end if;
   exception
      when others =>
         null;
   end Apply_Socket_Read_Timeout;

   procedure Configure_Server_Alive
     (Item             : in out Driver;
      Interval_Seconds : Natural;
      Count_Max        : Natural)
   is
      Interval_MS : Natural := 0;
   begin
      Item.Server_Alive_Missed := 0;
      Item.Server_Alive_Awaiting_Reply := False;
      Item.Server_Alive_Count_Max := Count_Max;
      Item.Server_Alive_Interval_MS := 0;

      if Interval_Seconds = 0 then
         return;
      elsif Interval_Seconds > Natural'Last / 1000 then
         Interval_MS := Natural'Last;
      else
         Interval_MS := Interval_Seconds * 1000;
      end if;

      Item.Server_Alive_Interval_MS := Interval_MS;
      if not Item.Caller_Read_Timeout_Configured then
         Item.Read_Timeout_Configured := True;
         Item.Read_Timeout_MS := Interval_MS;
         Apply_Socket_Read_Timeout (Item);
         if Item.Mode = Jump_Channel_Mode
           and then Item.Outer_Driver /= null
           and then not Item.Outer_Driver.Caller_Read_Timeout_Configured
         then
            Item.Outer_Driver.Read_Timeout_Configured := True;
            Item.Outer_Driver.Read_Timeout_MS := Interval_MS;
            Apply_Socket_Read_Timeout (Item.Outer_Driver.all);
         end if;
      end if;
   exception
      when others =>
         Item.Server_Alive_Interval_MS := 0;
         Item.Server_Alive_Missed := 0;
         Item.Server_Alive_Awaiting_Reply := False;
   end Configure_Server_Alive;

   procedure Reset_After_Close_Preserving_Proxy_Diagnostic
     (Item : out Driver)
   is
      Diagnostic : constant SSH_Lib.Sessions.Proxy_Command_Diagnostic :=
        Item.Proxy_Command_Diagnostic_Item;
   begin
      Reset (Item);
      Item.Proxy_Command_Diagnostic_Item := Diagnostic;
   exception
      when others =>
         Reset (Item);
   end Reset_After_Close_Preserving_Proxy_Diagnostic;

   procedure Note_Proxy_Status
     (Item   : in out Driver;
      Stage  : String;
      Status : CryptoLib.Errors.Status)
   is
   begin
      Item.Proxy_Command_Diagnostic_Item.Last_IO_Status := Status;
      Item.Proxy_Command_Diagnostic_Item.Lifecycle_Stage :=
        To_Unbounded_String (Stage);
      Item.Proxy_Command_Diagnostic_Item.Child_Open :=
        Item.Proxy_Process_Open;
   exception
      when others =>
         null;
   end Note_Proxy_Status;

   procedure Close_Owned_Outer_Quietly (Item : in out Driver) is
      Owned_Outer : Driver_Access := null;
   begin
      if Item.Owns_Outer_Driver and then Item.Outer_Driver /= null then
         --  Detach before closing/freeing so exception containment cannot
         --  recurse through the same pointer or free it twice.
         Owned_Outer := Item.Outer_Driver;
         Item.Outer_Driver := null;
         Item.Owns_Outer_Driver := False;
         Close (Owned_Outer.all);
         Free_Driver (Owned_Outer);
      end if;
   exception
      when others =>
         if Owned_Outer /= null then
            begin
               Free_Driver (Owned_Outer);
            exception
               when others =>
                  null;
            end;
         end if;
         Item.Outer_Driver := null;
         Item.Owns_Outer_Driver := False;
   end Close_Owned_Outer_Quietly;

   procedure Close (Item : in out Driver) is
      Close_Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   begin
      if Item.Mode = Proxy_Command_Mode and then Item.Proxy_Process_Open then
         Item.Proxy_Command_Diagnostic_Item.Close_Attempted := True;
         Item.Proxy_Command_Diagnostic_Item.Lifecycle_Stage :=
           To_Unbounded_String ("closing");
         begin
            declare
               Child_Status : Integer := 0;
            begin
               GNAT.Expect.Close (Item.Proxy_Process, Child_Status);
               Item.Proxy_Command_Diagnostic_Item.Exit_Status_Known := True;
               Item.Proxy_Command_Diagnostic_Item.Exit_Status := Child_Status;
            end;
            Item.Proxy_Command_Diagnostic_Item.Close_Completed := True;
            Item.Proxy_Command_Diagnostic_Item.Close_Status := Ok;
            Item.Proxy_Command_Diagnostic_Item.Child_Open := False;
            Item.Proxy_Command_Diagnostic_Item.Lifecycle_Stage :=
              To_Unbounded_String ("closed");
         exception
            when others =>
               Item.Proxy_Command_Diagnostic_Item.Exit_Status_Known := False;
               Item.Proxy_Command_Diagnostic_Item.Close_Completed := False;
               Item.Proxy_Command_Diagnostic_Item.Close_Status := Connection_Failed;
               Item.Proxy_Command_Diagnostic_Item.Lifecycle_Stage :=
                 To_Unbounded_String ("close_failed");
         end;
         Item.Proxy_Process_Open := False;
      elsif Item.Connected and then Item.Mode = Socket_Mode then
         GNAT.Sockets.Close_Socket (Item.Socket_Item);
      elsif Item.Mode = Jump_Channel_Mode then
         if Item.Connected
           and then Item.Outer_Driver /= null
           and then Item.Jump_Remote_Channel /= 0
         then
            Close_Payload :=
              SSH_Lib.Protocol.Channels.Encode_Channel_Close
                (Item.Jump_Remote_Channel);
            if not SSH_Lib.Protocol.Buffers.Is_Empty (Close_Payload) then
               declare
                  Ignored_Status : constant Status :=
                    Send_Protected_Packet
                      (Item.Outer_Driver.all,
                       SSH_Lib.Protocol.Buffers.To_Array (Close_Payload));
               begin
                  null;
               end;
            end if;
         end if;

         --  Ownership is independent of the inner tunnel's Connected flag.
         --  A partially-open or failure-cleanup path may still own the outer
         --  jump transport and must release it exactly once.
         Close_Owned_Outer_Quietly (Item);
      end if;
      Reset_After_Close_Preserving_Proxy_Diagnostic (Item);
   exception
      when others =>
         Close_Owned_Outer_Quietly (Item);
         Reset_After_Close_Preserving_Proxy_Diagnostic (Item);
   end Close;

   function Is_Connected (Item : Driver) return Boolean is
   begin
      return Item.Connected;
   exception
      when others =>
         return False;
   end Is_Connected;

   procedure Set_Strict_Kex (Item : in out Driver) is
   begin
      Item.Strict_Kex := True;
   end Set_Strict_Kex;

   function Is_Strict_Kex (Item : Driver) return Boolean is
   begin
      return Item.Strict_Kex;
   end Is_Strict_Kex;

   function Connect
     (Item               : in out Driver;
      Host               : String;
      Port               : Natural;
      Connect_Timeout_MS : Natural := 0;
      Read_Timeout_MS    : Natural := 0;
      Write_Timeout_MS   : Natural := 0;
      Address_Family     : String := "";
      Bind_Address       : String := "";
      TCP_Keep_Alive     : Boolean := True;
      IP_QoS             : String := "";
      Bind_Interface     : String := "") return Status
   is
      type Address_Family_Mode is
        (Address_Family_Any,
         Address_Family_Inet,
         Address_Family_Inet6,
         Address_Family_Invalid);

      Family_Mode : constant Address_Family_Mode :=
        (if Address_Family'Length = 0
         or else Ada.Characters.Handling.To_Lower (Address_Family) = "any"
         then Address_Family_Any
         elsif Ada.Characters.Handling.To_Lower (Address_Family) = "inet"
         then Address_Family_Inet
         elsif Ada.Characters.Handling.To_Lower (Address_Family) = "inet6"
         then Address_Family_Inet6
         else Address_Family_Invalid);
      Started_At  : constant Ada.Calendar.Time := Ada.Calendar.Clock;
      Linux_IP_TOS      : constant Interfaces.C.int := 1;
      Linux_IPV6_TCLASS : constant Interfaces.C.int := 67;
      Linux_SOL_SOCKET  : constant Interfaces.C.int := 1;
      Linux_SO_BINDTODEVICE : constant Interfaces.C.int := 25;
      Linux_IFNAMSIZ : constant Natural := 16;

      function Connect_Deadline_Expired return Boolean is
      begin
         return
           Connect_Timeout_MS > 0
           and then
             Ada.Calendar.Clock - Started_At
             > Duration (Connect_Timeout_MS) / 1000.0;
      exception
         when others =>
            return False;
      end Connect_Deadline_Expired;

      function Timeout_Value (Milliseconds : Natural) return Duration is
      begin
         if Milliseconds = 0 then
            return 0.0;
         end if;
         return Duration (Milliseconds) / 1000.0;
      end Timeout_Value;

      procedure Apply_IO_Timeouts is
      begin
         if Read_Timeout_MS > 0 then
            GNAT.Sockets.Set_Socket_Option
              (Item.Socket_Item,
               GNAT.Sockets.Socket_Level,
               (Name    => GNAT.Sockets.Receive_Timeout,
                Timeout => Timeout_Value (Read_Timeout_MS)));
         end if;

         if Write_Timeout_MS > 0 then
            GNAT.Sockets.Set_Socket_Option
              (Item.Socket_Item,
               GNAT.Sockets.Socket_Level,
               (Name    => GNAT.Sockets.Send_Timeout,
                Timeout => Timeout_Value (Write_Timeout_MS)));
         end if;
      exception
         when others =>
            null;
      end Apply_IO_Timeouts;

      procedure Apply_TCP_Keep_Alive is
      begin
         GNAT.Sockets.Set_Socket_Option
           (Item.Socket_Item,
            GNAT.Sockets.Socket_Level,
            (Name    => GNAT.Sockets.Keep_Alive,
             Enabled => TCP_Keep_Alive));
      exception
         when others =>
            null;
      end Apply_TCP_Keep_Alive;

      function Bind_Interface_Valid return Boolean is
      begin
         if Bind_Interface'Length = 0 then
            return True;
         elsif Bind_Interface'Length >= Linux_IFNAMSIZ then
            return False;
         end if;

         for Ch of Bind_Interface loop
            if Ch <= ' ' or else Ch = '/' or else Ch = Character'Val (127) then
               return False;
            end if;
         end loop;
         return True;
      exception
         when others =>
            return False;
      end Bind_Interface_Valid;

      function Apply_Bind_Interface return Status is
      begin
         if Bind_Interface'Length = 0 then
            return Ok;
         end if;

         declare
            Name_C : aliased Interfaces.C.char_array :=
              Interfaces.C.To_C (Bind_Interface);
            Result : constant Interfaces.C.int :=
              C_Setsockopt
                (Interfaces.C.int
                   (GNAT.Sockets.To_C (Item.Socket_Item)),
                 Linux_SOL_SOCKET,
                 Linux_SO_BINDTODEVICE,
                 Name_C'Address,
                 Interfaces.C.int (Name_C'Length));
         begin
            if Result = 0 then
               return Ok;
            end if;
            return Connection_Failed;
         end;
      exception
         when others =>
            return Connection_Failed;
      end Apply_Bind_Interface;

      function First_QoS_Token return String is
         Clean : constant String := Ada.Strings.Fixed.Trim
           (IP_QoS, Ada.Strings.Both);
         Stop_Index : Natural;
      begin
         if Clean'Length = 0 then
            return "";
         end if;
         Stop_Index := Clean'First;
         while Stop_Index <= Clean'Last
           and then Clean (Stop_Index) /= ' '
         loop
            Stop_Index := Stop_Index + 1;
         end loop;
         return Ada.Characters.Handling.To_Lower
           (Clean (Clean'First .. Stop_Index - 1));
      exception
         when others =>
            return "";
      end First_QoS_Token;

      function QoS_Value (Token : String; Value : out Natural) return Boolean is
      begin
         if Token'Length = 0 or else Token = "none" or else Token = "cs0" then
            Value := 0;
         elsif Token = "lowdelay" then
            Value := 16#10#;
         elsif Token = "throughput" then
            Value := 16#08#;
         elsif Token = "reliability" then
            Value := 16#04#;
         elsif Token = "cs1" then
            Value := 16#20#;
         elsif Token = "cs2" then
            Value := 16#40#;
         elsif Token = "cs3" then
            Value := 16#60#;
         elsif Token = "cs4" then
            Value := 16#80#;
         elsif Token = "cs5" then
            Value := 16#A0#;
         elsif Token = "cs6" then
            Value := 16#C0#;
         elsif Token = "cs7" then
            Value := 16#E0#;
         elsif Token = "af11" then
            Value := 16#28#;
         elsif Token = "af12" then
            Value := 16#30#;
         elsif Token = "af13" then
            Value := 16#38#;
         elsif Token = "af21" then
            Value := 16#48#;
         elsif Token = "af22" then
            Value := 16#50#;
         elsif Token = "af23" then
            Value := 16#58#;
         elsif Token = "af31" then
            Value := 16#68#;
         elsif Token = "af32" then
            Value := 16#70#;
         elsif Token = "af33" then
            Value := 16#78#;
         elsif Token = "af41" then
            Value := 16#88#;
         elsif Token = "af42" then
            Value := 16#90#;
         elsif Token = "af43" then
            Value := 16#98#;
         elsif Token = "ef" then
            Value := 16#B8#;
         else
            return False;
         end if;
         return True;
      end QoS_Value;

      function IP_QoS_Valid return Boolean is
         Value : Natural := 0;
      begin
         return QoS_Value (First_QoS_Token, Value);
      end IP_QoS_Valid;

      procedure Apply_IP_QoS (Family : GNAT.Sockets.Family_Inet_4_6) is
         Token : constant String := First_QoS_Token;
         Value : Natural := 0;
      begin
         if Token'Length = 0 or else not QoS_Value (Token, Value) then
            return;
         end if;

         if Family = GNAT.Sockets.Family_Inet then
            GNAT.Sockets.Set_Socket_Option
              (Item.Socket_Item,
               GNAT.Sockets.IP_Protocol_For_IP_Level,
               (Name    => GNAT.Sockets.Generic_Option,
                Optname => Linux_IP_TOS,
                Optval  => Interfaces.C.int (Value)));
         else
            GNAT.Sockets.Set_Socket_Option
              (Item.Socket_Item,
               GNAT.Sockets.IP_Protocol_For_IPv6_Level,
               (Name    => GNAT.Sockets.Generic_Option,
                Optname => Linux_IPV6_TCLASS,
                Optval  => Interfaces.C.int (Value)));
         end if;
      exception
         when others =>
            null;
      end Apply_IP_QoS;

      function Bind_Configured_Address
        (Remote_Family : GNAT.Sockets.Family_Inet_4_6) return Status
      is
      begin
         if Bind_Address'Length = 0 then
            return Ok;
         end if;

         declare
            Host_Entry : constant GNAT.Sockets.Host_Entry_Type :=
              GNAT.Sockets.Get_Host_By_Name (Bind_Address);
            Bind_Value : GNAT.Sockets.Sock_Addr_Type (Remote_Family);
         begin
            for Index in 1 .. GNAT.Sockets.Addresses_Length (Host_Entry) loop
               declare
                  Candidate : constant GNAT.Sockets.Inet_Addr_Type :=
                    GNAT.Sockets.Addresses (Host_Entry, Index);
               begin
                  if Candidate.Family = Remote_Family then
                     Bind_Value.Addr := Candidate;
                     Bind_Value.Port := 0;
                     GNAT.Sockets.Bind_Socket
                       (Item.Socket_Item, Bind_Value);
                     return Ok;
                  end if;
               end;
            end loop;
         end;

         return Connection_Failed;
      exception
         when others =>
            return Connection_Failed;
      end Bind_Configured_Address;

      function Try_Address
        (Address : GNAT.Sockets.Inet_Addr_Type) return Status
      is
         Address_Value : GNAT.Sockets.Sock_Addr_Type (Address.Family);
         Status_Value  : Status;
      begin
         if Connect_Deadline_Expired then
            return Timeout;
         end if;

         GNAT.Sockets.Create_Socket
           (Item.Socket_Item,
            Address.Family,
            GNAT.Sockets.Socket_Stream);
         Apply_TCP_Keep_Alive;
         Status_Value := Apply_Bind_Interface;
         if Status_Value /= Ok then
            Close_Socket_Quietly (Item.Socket_Item);
            return Status_Value;
         end if;
         Apply_IP_QoS (Address.Family);
         Apply_IO_Timeouts;

         Status_Value := Bind_Configured_Address (Address.Family);
         if Status_Value /= Ok then
            Close_Socket_Quietly (Item.Socket_Item);
            return Status_Value;
         end if;

         Address_Value.Addr := Address;
         Address_Value.Port := GNAT.Sockets.Port_Type (Port);
         GNAT.Sockets.Connect_Socket (Item.Socket_Item, Address_Value);
         if Connect_Deadline_Expired then
            Close_Socket_Quietly (Item.Socket_Item);
            return Timeout;
         end if;
         Apply_IO_Timeouts;
         return Ok;
      exception
         when GNAT.Sockets.Socket_Error =>
            Close_Socket_Quietly (Item.Socket_Item);
            return Connection_Failed;
         when others =>
            Close_Socket_Quietly (Item.Socket_Item);
            return Connection_Failed;
      end Try_Address;

      function Connect_First_Address_For_Family
        (Host_Entry : GNAT.Sockets.Host_Entry_Type;
         Family     : GNAT.Sockets.Family_Inet_4_6;
         Found      : out Boolean) return Status
      is
         Status_Value : Status;
      begin
         Found := False;
         for Index in 1 .. GNAT.Sockets.Addresses_Length (Host_Entry) loop
            declare
               Candidate : constant GNAT.Sockets.Inet_Addr_Type :=
                 GNAT.Sockets.Addresses (Host_Entry, Index);
            begin
               if Candidate.Family = Family then
                  Found := True;
                  Status_Value := Try_Address (Candidate);
                  if Status_Value = Ok then
                     Item.Connected := True;
                  else
                     Close (Item);
                  end if;
                  return Status_Value;
               end if;
            end;
         end loop;
         return Connection_Failed;
      exception
         when others =>
            Found := False;
            Close (Item);
            return Connection_Failed;
      end Connect_First_Address_For_Family;
   begin
      Close (Item);
      Item.Read_Timeout_Configured := Read_Timeout_MS > 0;
      Item.Caller_Read_Timeout_Configured := Read_Timeout_MS > 0;
      Item.Write_Timeout_Configured := Write_Timeout_MS > 0;
      Item.Read_Timeout_MS := Read_Timeout_MS;
      Item.Write_Timeout_MS := Write_Timeout_MS;
      if Connect_Deadline_Expired then
         return Timeout;
      elsif Family_Mode = Address_Family_Invalid then
         return Invalid_Command;
      elsif not Bind_Interface_Valid then
         return Invalid_Command;
      elsif not IP_QoS_Valid then
         return Invalid_Command;
      end if;

      begin
         declare
            Host_Entry : constant GNAT.Sockets.Host_Entry_Type :=
              GNAT.Sockets.Get_Host_By_Name (Host);
            Found_Address        : Boolean := False;
            Status_Value         : Status := Connection_Failed;
         begin
            case Family_Mode is
               when Address_Family_Any =>
                  Status_Value :=
                    Connect_First_Address_For_Family
                      (Host_Entry, GNAT.Sockets.Family_Inet, Found_Address);
                  if Found_Address then
                     return Status_Value;
                  end if;
                  Status_Value :=
                    Connect_First_Address_For_Family
                      (Host_Entry, GNAT.Sockets.Family_Inet6, Found_Address);
                  if Found_Address then
                     return Status_Value;
                  end if;
               when Address_Family_Inet =>
                  Status_Value :=
                    Connect_First_Address_For_Family
                      (Host_Entry, GNAT.Sockets.Family_Inet, Found_Address);
                  if Found_Address then
                     return Status_Value;
                  end if;
               when Address_Family_Inet6 =>
                  Status_Value :=
                    Connect_First_Address_For_Family
                      (Host_Entry, GNAT.Sockets.Family_Inet6, Found_Address);
                  if Found_Address then
                     return Status_Value;
                  end if;
               when Address_Family_Invalid =>
                  return Invalid_Command;
            end case;
         end;
         Close (Item);
         return Connection_Failed;
      exception
         when GNAT.Sockets.Socket_Error =>
            Close_Socket_Quietly (Item.Socket_Item);
            Close (Item);
            return Connection_Failed;
         when others =>
            Close_Socket_Quietly (Item.Socket_Item);
            Close (Item);
            return Connection_Failed;
      end;
   exception
      when others =>
         Close (Item);
         return Internal_Error;
   end Connect;

   function Connect_Through_Mux_Proxy
     (Item             : in out Driver;
      Control_Path     : String;
      Read_Timeout_MS  : Natural := 0;
      Write_Timeout_MS : Natural := 0) return Status
   is
      Client       : SSH_Lib.Mux.Mux_Client;
      Response     : SSH_Lib.Mux.Mux_Message;
      Peer_Version : Interfaces.Unsigned_32 := 0;
      Detached     : GNAT.Sockets.Socket_Type;
      Status_Value : Status;

      function Timeout_Value (Milliseconds : Natural) return Duration is
      begin
         if Milliseconds = 0 then
            return 0.0;
         end if;
         return Duration (Milliseconds) / 1000.0;
      end Timeout_Value;

      procedure Apply_IO_Timeouts is
      begin
         if Read_Timeout_MS > 0 then
            GNAT.Sockets.Set_Socket_Option
              (Item.Socket_Item,
               GNAT.Sockets.Socket_Level,
               (Name    => GNAT.Sockets.Receive_Timeout,
                Timeout => Timeout_Value (Read_Timeout_MS)));
         end if;

         if Write_Timeout_MS > 0 then
            GNAT.Sockets.Set_Socket_Option
              (Item.Socket_Item,
               GNAT.Sockets.Socket_Level,
               (Name    => GNAT.Sockets.Send_Timeout,
                Timeout => Timeout_Value (Write_Timeout_MS)));
         end if;
      exception
         when others =>
            null;
      end Apply_IO_Timeouts;
   begin
      Close (Item);
      if Control_Path'Length = 0 then
         return Connection_Failed;
      end if;

      Status_Value := SSH_Lib.Mux.Connect_Control (Control_Path, Client);
      if Status_Value /= Ok then
         SSH_Lib.Mux.Close (Client);
         return Status_Value;
      end if;

      Status_Value := SSH_Lib.Mux.Exchange_Hello (Client, Peer_Version);
      if Status_Value /= Ok then
         SSH_Lib.Mux.Close (Client);
         return Status_Value;
      end if;

      Status_Value := SSH_Lib.Mux.Request
        (Client,
         SSH_Lib.Mux.Mux_Proxy,
         1,
         Ada.Streams.Stream_Element_Array'(1 .. 0 => 0),
         Response);
      if Status_Value /= Ok then
         SSH_Lib.Mux.Close (Client);
         return Status_Value;
      elsif Response.Kind /= SSH_Lib.Mux.Mux_Proxy_Response
        or else Response.Request_Id /= 1
        or else Response.Payload_Length /= 0
      then
         SSH_Lib.Mux.Close (Client);
         return Invalid_Command;
      end if;

      Status_Value := SSH_Lib.Mux.Detach_Control_Socket (Client, Detached);
      if Status_Value /= Ok then
         SSH_Lib.Mux.Close (Client);
         return Status_Value;
      end if;

      Item.Mode := Socket_Mode;
      Item.Socket_Item := Detached;
      Item.Connected := True;
      Item.Read_Timeout_Configured := Read_Timeout_MS > 0;
      Item.Caller_Read_Timeout_Configured := Read_Timeout_MS > 0;
      Item.Write_Timeout_Configured := Write_Timeout_MS > 0;
      Item.Read_Timeout_MS := Read_Timeout_MS;
      Item.Write_Timeout_MS := Write_Timeout_MS;
      Apply_IO_Timeouts;
      return Ok;
   exception
      when others =>
         SSH_Lib.Mux.Close (Client);
         Close (Item);
         return Internal_Error;
   end Connect_Through_Mux_Proxy;

   function Connect_Through_Jump
     (Item             : in out Driver;
      Outer            : Driver_Access;
      Local_Channel    : Unsigned_32;
      Remote_Channel   : Unsigned_32;
      Own_Outer        : Boolean := False;
      Read_Timeout_MS  : Natural := 0;
      Write_Timeout_MS : Natural := 0) return Status is
   begin
      Reset (Item);
      if Outer = null
        or else not Outer.Connected
        or else Local_Channel = Remote_Channel
      then
         return Connection_Failed;
      end if;

      Item.Mode := Jump_Channel_Mode;
      Item.Outer_Driver := Outer;
      Item.Owns_Outer_Driver := Own_Outer;
      Item.Jump_Local_Channel := Local_Channel;
      Item.Jump_Remote_Channel := Remote_Channel;
      Item.Connected := True;
      Item.Read_Timeout_Configured := Read_Timeout_MS > 0;
      Item.Caller_Read_Timeout_Configured := Read_Timeout_MS > 0;
      Item.Write_Timeout_Configured := Write_Timeout_MS > 0;
      Item.Read_Timeout_MS := Read_Timeout_MS;
      Item.Write_Timeout_MS := Write_Timeout_MS;
      return Ok;
   exception
      when others =>
         Reset (Item);
         return Internal_Error;
   end Connect_Through_Jump;

   function Decimal_Image (Value : Natural) return String is
   begin
      return Ada.Strings.Fixed.Trim (Natural'Image (Value), Ada.Strings.Both);
   end Decimal_Image;

   function Expanded_Proxy_Command
     (Command_Text : String;
      Host         : String;
      Port         : Natural;
      User         : String) return String
   is
      Result : Unbounded_String;
      Index  : Positive := Command_Text'First;
   begin
      while Index <= Command_Text'Last loop
         if Command_Text (Index) = '%'
           and then Index < Command_Text'Last
         then
            case Command_Text (Index + 1) is
               when '%' =>
                  Append (Result, "%");
               when 'h' | 'n' =>
                  Append (Result, Host);
               when 'p' =>
                  Append (Result, Decimal_Image (Port));
               when 'r' =>
                  Append (Result, User);
               when others =>
                  Append (Result, "%");
                  Append (Result, Command_Text (Index + 1));
            end case;
            Index := Index + 2;
         else
            Append (Result, Command_Text (Index));
            Index := Index + 1;
         end if;
      end loop;
      return To_String (Result);
   exception
      when others =>
         return "";
   end Expanded_Proxy_Command;

   function Wait_For_Proxy_FD
     (FD         : GNAT.OS_Lib.File_Descriptor;
      For_Write  : Boolean;
      Timeout_MS : Natural) return Status
   is
      Event : constant Interfaces.C.short :=
        (if For_Write then Poll_Output_Event else Poll_Input_Event);
      Poll_Item : aliased Poll_FD :=
        (FD      => Interfaces.C.int (FD),
         Events  => Event,
         Revents => 0);
      Poll_Timeout : Interfaces.C.int;
      Result       : Interfaces.C.int;
   begin
      if FD = GNAT.OS_Lib.Invalid_FD then
         if For_Write then
            return Write_Failed;
         end if;
         return Read_Failed;
      end if;

      if Timeout_MS = 0 then
         Poll_Timeout := -1;
      else
         Poll_Timeout := Interfaces.C.int (Timeout_MS);
      end if;

      Result := C_Poll (Poll_Item'Access, 1, Poll_Timeout);
      if Result > 0 then
         return Ok;
      elsif Result = 0 then
         return Timeout;
      elsif For_Write then
         return Write_Failed;
      else
         return Read_Failed;
      end if;
   exception
      when others =>
         if For_Write then
            return Write_Failed;
         end if;
         return Read_Failed;
   end Wait_For_Proxy_FD;

   function Expand_Proxy_Command_For_Test
     (Command_Text : String;
      Host         : String;
      Port         : Natural;
      User         : String) return String is
   begin
      return Expanded_Proxy_Command (Command_Text, Host, Port, User);
   end Expand_Proxy_Command_For_Test;

   function Last_Proxy_Command_Diagnostics
     (Item : Driver) return SSH_Lib.Sessions.Proxy_Command_Diagnostic is
   begin
      return Item.Proxy_Command_Diagnostic_Item;
   exception
      when others =>
         return (others => <>);
   end Last_Proxy_Command_Diagnostics;

   function Connect_Through_Proxy_Command
     (Item               : in out Driver;
      Command_Text       : String;
      Host               : String;
      Port               : Natural;
      User               : String;
      Connect_Timeout_MS : Natural := 0;
      Read_Timeout_MS    : Natural := 0;
      Write_Timeout_MS   : Natural := 0) return Status
   is
      Effective_Read_Timeout_MS  : constant Natural :=
        (if Read_Timeout_MS > 0 then Read_Timeout_MS else Connect_Timeout_MS);
      Effective_Write_Timeout_MS : constant Natural :=
        (if Write_Timeout_MS > 0 then Write_Timeout_MS else Connect_Timeout_MS);
      Shell_Name   : constant String :=
        (if GNAT.OS_Lib.Directory_Separator = '\' then "cmd.exe" else "sh");
      Shell_Switch : constant String :=
        (if GNAT.OS_Lib.Directory_Separator = '\' then "/C" else "-c");
      Shell_Path   : GNAT.OS_Lib.String_Access :=
        GNAT.OS_Lib.Locate_Exec_On_Path (Shell_Name);
      Command_Line : constant String :=
        Expanded_Proxy_Command (Command_Text, Host, Port, User);
      Arg_1        : aliased String := Shell_Switch;
      Arg_2        : aliased String := Command_Line;
      Args         : constant GNAT.OS_Lib.Argument_List (1 .. 2) :=
        [Arg_1'Unchecked_Access, Arg_2'Unchecked_Access];
   begin
      Close (Item);
      Item.Proxy_Command_Diagnostic_Item.Configured := True;
      Item.Proxy_Command_Diagnostic_Item.Shell_Name :=
        To_Unbounded_String (Shell_Name);
      Item.Proxy_Command_Diagnostic_Item.Lifecycle_Stage :=
        To_Unbounded_String ("configured");

      if Command_Line'Length = 0 then
         Item.Proxy_Command_Diagnostic_Item.Spawn_Status := Invalid_Command;
         Item.Proxy_Command_Diagnostic_Item.Lifecycle_Stage :=
           To_Unbounded_String ("invalid_command");
         return Invalid_Command;
      end if;

      if Shell_Path = null then
         Item.Proxy_Command_Diagnostic_Item.Spawn_Status := Unsupported_Feature;
         Item.Proxy_Command_Diagnostic_Item.Lifecycle_Stage :=
           To_Unbounded_String ("missing_shell");
         return Unsupported_Feature;
      end if;

      GNAT.Expect.Non_Blocking_Spawn
        (Item.Proxy_Process,
         Shell_Path.all,
         Args,
         Buffer_Size => 0,
         Err_To_Out  => False);

      Item.Mode := Proxy_Command_Mode;
      Item.Proxy_Process_Open := True;
      Item.Proxy_Command_Diagnostic_Item.Child_Started := True;
      Item.Proxy_Command_Diagnostic_Item.Child_Open := True;
      Item.Proxy_Command_Diagnostic_Item.Spawn_Status := Ok;
      Item.Proxy_Command_Diagnostic_Item.Lifecycle_Stage :=
        To_Unbounded_String ("spawned");
      Item.Connected := True;
      Item.Read_Timeout_Configured := Effective_Read_Timeout_MS > 0;
      Item.Caller_Read_Timeout_Configured := Effective_Read_Timeout_MS > 0;
      Item.Write_Timeout_Configured := Effective_Write_Timeout_MS > 0;
      Item.Read_Timeout_MS := Effective_Read_Timeout_MS;
      Item.Write_Timeout_MS := Effective_Write_Timeout_MS;
      GNAT.OS_Lib.Free (Shell_Path);
      return Ok;
   exception
      when GNAT.Expect.Invalid_Process =>
         Item.Proxy_Command_Diagnostic_Item.Spawn_Status := Connection_Failed;
         Item.Proxy_Command_Diagnostic_Item.Lifecycle_Stage :=
           To_Unbounded_String ("spawn_failed");
         if Shell_Path /= null then
            GNAT.OS_Lib.Free (Shell_Path);
         end if;
         Close (Item);
         return Connection_Failed;
      when others =>
         Item.Proxy_Command_Diagnostic_Item.Spawn_Status := Internal_Error;
         Item.Proxy_Command_Diagnostic_Item.Lifecycle_Stage :=
           To_Unbounded_String ("spawn_exception");
         if Shell_Path /= null then
            GNAT.OS_Lib.Free (Shell_Path);
         end if;
         Close (Item);
         return Internal_Error;
   end Connect_Through_Proxy_Command;

   function Send_Jump_Channel_Data
     (Item : in out Driver; Data : Stream_Element_Array) return Status
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : Status;
   begin
      if Item.Outer_Driver = null or else not Item.Connected then
         return Connection_Failed;
      end if;

      Payload :=
        SSH_Lib.Protocol.Channels.Encode_Channel_Data
          (Item.Jump_Remote_Channel, Data);
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload) then
         return Write_Failed;
      end if;

      Status_Value :=
        Send_Protected_Packet
          (Item.Outer_Driver.all, SSH_Lib.Protocol.Buffers.To_Array (Payload));
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Send_Jump_Channel_Data;

   function Send_Server_Alive_Probe (Item : in out Driver) return Status is
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : Status;
   begin
      if Item.Server_Alive_Interval_MS = 0
        or else Item.Caller_Read_Timeout_Configured
      then
         return Timeout;
      elsif Item.Server_Alive_Missed >= Item.Server_Alive_Count_Max then
         return Timeout;
      end if;

      Payload := SSH_Lib.Protocol.Global_Requests.Encode_Keepalive_Request;
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload) then
         return Write_Failed;
      end if;

      Status_Value :=
        Send_Protected_Packet
          (Item, SSH_Lib.Protocol.Buffers.To_Array (Payload));
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Item.Server_Alive_Missed := Item.Server_Alive_Missed + 1;
      Item.Server_Alive_Awaiting_Reply := True;
      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Send_Server_Alive_Probe;

   function Drain_Jump_Buffer
     (Item : in out Driver; Data : out Stream_Element_Array) return Boolean
   is
      Current_Data : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Item.Jump_Read_Buffer);
      Needed       : constant Natural := Data'Length;
      Remaining    : Natural;
   begin
      if Needed = 0 then
         return True;
      end if;

      if Current_Data'Length < Needed then
         return False;
      end if;

      for Offset_Value in 0 .. Needed - 1 loop
         Data (Data'First + Stream_Element_Offset (Offset_Value)) :=
           Current_Data
             (Current_Data'First + Stream_Element_Offset (Offset_Value));
      end loop;

      Remaining := Current_Data'Length - Needed;
      if Remaining = 0 then
         SSH_Lib.Protocol.Buffers.Clear (Item.Jump_Read_Buffer);
      else
         declare
            Remainder_Data :
              Stream_Element_Array (1 .. Stream_Element_Offset (Remaining));
         begin
            for Offset_Value in 0 .. Remaining - 1 loop
               Remainder_Data
                 (Remainder_Data'First
                  + Stream_Element_Offset (Offset_Value)) :=
                 Current_Data
                   (Current_Data'First
                    + Stream_Element_Offset (Needed + Offset_Value));
            end loop;
            declare
               Store_Status : constant Status :=
                 SSH_Lib.Protocol.Buffers.Set
                   (Item.Jump_Read_Buffer, Remainder_Data);
            begin
               return Store_Status = Ok;
            end;
         end;
      end if;

      return True;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Item.Jump_Read_Buffer);
         return False;
   end Drain_Jump_Buffer;

   function Read_From_Jump_Channel
     (Item : in out Driver; Data : out Stream_Element_Array) return Status
   is
      Payload      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Event_Item   : SSH_Lib.Protocol.Channels.Channel_Data_Event;
      Adjust_Item  : SSH_Lib.Protocol.Channels.Channel_Window_Adjust_Event;
      Status_Value : Status;
   begin
      if Data'Length = 0 then
         return Ok;
      end if;

      if Drain_Jump_Buffer (Item, Data) then
         return Ok;
      end if;

      if Item.Outer_Driver = null or else not Item.Connected then
         return Connection_Failed;
      end if;

      for Attempt_Count in 1 .. 64 loop
         Status_Value :=
           Read_Protected_Packet (Item.Outer_Driver.all, Payload);
         if Status_Value /= Ok then
            if Status_Value = Timeout then
               Status_Value := Send_Server_Alive_Probe (Item);
               if Status_Value = Ok then
                  goto Continue_Jump_Read;
               end if;
            end if;
            return Status_Value;
         end if;

         declare
            Payload_Data : constant Stream_Element_Array :=
              SSH_Lib.Protocol.Buffers.To_Array (Payload);
         begin
            if Payload_Data'Length = 0 then
               return Read_Failed;
            elsif Payload_Data (Payload_Data'First)
              = SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_DATA
            then
               Status_Value :=
                 SSH_Lib.Protocol.Channels.Parse_Channel_Data
                   (Payload_Data, Item.Jump_Local_Channel, Event_Item);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;

               declare
                  Event_Data : constant Stream_Element_Array :=
                    SSH_Lib.Protocol.Buffers.To_Array (Event_Item.Data);
               begin
                  Status_Value :=
                    SSH_Lib.Protocol.Buffers.Append
                      (Item.Jump_Read_Buffer, Event_Data);
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;

                  declare
                     Adjust_Payload :
                       constant SSH_Lib.Protocol.Buffers.Packet_Buffer :=
                         SSH_Lib.Protocol.Channels.Encode_Channel_Window_Adjust
                           (Item.Jump_Remote_Channel,
                            Unsigned_32 (Event_Data'Length));
                  begin
                     if not SSH_Lib.Protocol.Buffers.Is_Empty (Adjust_Payload)
                     then
                        Status_Value :=
                          Send_Protected_Packet
                            (Item.Outer_Driver.all,
                             SSH_Lib.Protocol.Buffers.To_Array
                               (Adjust_Payload));
                        if Status_Value /= Ok then
                           return Status_Value;
                        end if;
                     end if;
                  end;
               end;

               if Drain_Jump_Buffer (Item, Data) then
                  return Ok;
               end if;
            elsif Payload_Data (Payload_Data'First)
              = SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_WINDOW_ADJUST
            then
               Status_Value :=
                 SSH_Lib.Protocol.Channels.Parse_Channel_Window_Adjust
                   (Payload_Data, Item.Jump_Local_Channel, Adjust_Item);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;
            elsif Payload_Data (Payload_Data'First)
              = SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_EOF
              or else
                Payload_Data (Payload_Data'First)
                = SSH_Lib.Protocol.Channels.SSH_MSG_CHANNEL_CLOSE
            then
               return Read_Failed;
            elsif Payload_Data (Payload_Data'First)
              = SSH_Lib.Protocol.Global_Requests.SSH_MSG_GLOBAL_REQUEST
            then
               declare
                  Request_Item  :
                    SSH_Lib.Protocol.Global_Requests.Global_Request;
                  Reply_Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
               begin
                  Status_Value :=
                    SSH_Lib.Protocol.Global_Requests.Parse_Global_Request
                      (Payload_Data, Request_Item);
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;

                  if Request_Item.Want_Reply then
                     Reply_Payload :=
                       SSH_Lib.Protocol.Global_Requests.Encode_Request_Failure;
                     if SSH_Lib.Protocol.Buffers.Is_Empty (Reply_Payload) then
                        return Write_Failed;
                     end if;

                     Status_Value :=
                       Send_Protected_Packet
                         (Item.Outer_Driver.all,
                          SSH_Lib.Protocol.Buffers.To_Array (Reply_Payload));
                     if Status_Value /= Ok then
                        return Status_Value;
                     end if;
                  end if;
               end;
            elsif SSH_Lib.Protocol.Transport_Messages.Is_Ignorable_During_Wait
                    (Payload_Data)
            then
               null;
            else
               return
                 SSH_Lib.Protocol.Transport_Messages.Failure_Status
                   (Payload_Data, Read_Failed);
            end if;
         end;
         <<Continue_Jump_Read>>
         null;
      end loop;

      return Timeout;
   exception
      when others =>
         return Internal_Error;
   end Read_From_Jump_Channel;

   function Send_All
     (Item : in out Driver; Data : Stream_Element_Array) return Status
   is
      First_Index : Stream_Element_Offset := Data'First;
      Last_Index  : Stream_Element_Offset;
   begin
      if not Item.Connected then
         return Connection_Failed;
      elsif Item.Mode = Jump_Channel_Mode then
         return Send_Jump_Channel_Data (Item, Data);
      elsif Item.Mode = Proxy_Command_Mode then
         declare
            Input_FD : constant GNAT.OS_Lib.File_Descriptor :=
              GNAT.Expect.Get_Input_Fd (Item.Proxy_Process);
            Written  : Integer;
         begin
            while First_Index <= Data'Last loop
               declare
                  Ready_Status : constant Status :=
                    Wait_For_Proxy_FD
                      (Input_FD, True, Item.Write_Timeout_MS);
                  Remaining    : constant Stream_Element_Offset :=
                    Data'Last - First_Index + 1;
                  Chunk_Length : constant Stream_Element_Offset :=
                    Stream_Element_Offset'Min (Remaining, Max_Proxy_IO_Chunk);
               begin
                  if Ready_Status /= Ok then
                     Note_Proxy_Status (Item, "write_wait", Ready_Status);
                     return Ready_Status;
                  end if;

                  Written :=
                    GNAT.OS_Lib.Write
                      (Input_FD,
                       Data (First_Index)'Address,
                       Integer (Chunk_Length));
                  if Written <= 0 then
                     Note_Proxy_Status (Item, "write", Write_Failed);
                     return Write_Failed;
                  end if;
                  Note_Proxy_Status (Item, "write", Ok);
                  First_Index := First_Index + Stream_Element_Offset (Written);
               end;
            end loop;
            return Ok;
         end;
      end if;

      while First_Index <= Data'Last loop
         GNAT.Sockets.Send_Socket
           (Item.Socket_Item, Data (First_Index .. Data'Last), Last_Index);
         if Last_Index < First_Index then
            return Write_Failed;
         end if;
         First_Index := Last_Index + 1;
      end loop;
      return Ok;
   exception
      when GNAT.Sockets.Socket_Error =>
         if Item.Write_Timeout_Configured then
            return Timeout;
         end if;
         return Write_Failed;
      when others =>
         return Internal_Error;
   end Send_All;

   function Read_Exact
     (Item : in out Driver; Data : out Stream_Element_Array) return Status
   is
      Next_Index : Stream_Element_Offset := Data'First;
      Last_Index : Stream_Element_Offset;
   begin
      if not Item.Connected then
         return Connection_Failed;
      elsif Item.Mode = Jump_Channel_Mode then
         return Read_From_Jump_Channel (Item, Data);
      elsif Item.Mode = Proxy_Command_Mode then
         declare
            Output_FD : constant GNAT.OS_Lib.File_Descriptor :=
              GNAT.Expect.Get_Output_Fd (Item.Proxy_Process);
            Count     : Integer;
         begin
            while Next_Index <= Data'Last loop
               declare
                  Ready_Status : constant Status :=
                    Wait_For_Proxy_FD
                      (Output_FD, False, Item.Read_Timeout_MS);
                  Remaining    : constant Stream_Element_Offset :=
                    Data'Last - Next_Index + 1;
                  Chunk_Length : constant Stream_Element_Offset :=
                    Stream_Element_Offset'Min (Remaining, Max_Proxy_IO_Chunk);
               begin
                  if Ready_Status /= Ok then
                     Note_Proxy_Status (Item, "read_wait", Ready_Status);
                     return Ready_Status;
                  end if;

                  Count :=
                    GNAT.OS_Lib.Read
                      (Output_FD,
                       Data (Next_Index)'Address,
                       Integer (Chunk_Length));
                  if Count = 0 then
                     Note_Proxy_Status (Item, "read", End_Of_Stream);
                     return End_Of_Stream;
                  elsif Count < 0 then
                     Note_Proxy_Status (Item, "read", Read_Failed);
                     return Read_Failed;
                  end if;
                  Note_Proxy_Status (Item, "read", Ok);
                  Next_Index := Next_Index + Stream_Element_Offset (Count);
               end;
            end loop;
            return Ok;
         end;
      end if;

      if Data'Length = 0 then
         return Ok;
      end if;

      while Next_Index <= Data'Last loop
         GNAT.Sockets.Receive_Socket
           (Item.Socket_Item, Data (Next_Index .. Data'Last), Last_Index);
         if Last_Index < Next_Index then
            return Read_Failed;
         end if;
         Next_Index := Last_Index + 1;
      end loop;

      return Ok;
   exception
      when GNAT.Sockets.Socket_Error =>
         if Item.Read_Timeout_Configured then
            return Timeout;
         end if;
         return Read_Failed;
      when others =>
         return Internal_Error;
   end Read_Exact;

   function Send_Identification (Item : in out Driver) return Status is
   begin
      return
        Send_All
          (Item, SSH_Lib.Protocol.Identification.Local_Identification_Line);
   end Send_Identification;

   function Read_Identification (Item : in out Driver) return Status is
      Accumulated_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Read_Buffer        : Stream_Element_Array (1 .. 256);
      Byte_Buffer        : Stream_Element_Array (1 .. 1);
      Last_Index         : Stream_Element_Offset;
      Parsed_Text        : Unbounded_String;
      Consumed_Index     : Stream_Element_Offset;
      Status_Value       : Status;

      function Parse_Accumulated return Status is
         Current_Data : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Accumulated_Buffer);
      begin
         Status_Value :=
           SSH_Lib.Protocol.Identification.Parse_Remote_Identification
             (Current_Data, Parsed_Text, Consumed_Index);
         if Status_Value = Ok then
            Item.Remote_Identification_Text := Parsed_Text;
         end if;
         return Status_Value;
      exception
         when others =>
            return Internal_Error;
      end Parse_Accumulated;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Accumulated_Buffer);

      if Item.Mode = Jump_Channel_Mode or else Item.Mode = Proxy_Command_Mode then
         --  The inner SSH identification is carried over an outer
         --  direct-tcpip channel.  Read it byte-for-byte through the generic
         --  transport path rather than directly from Socket_Item; there may be no
         --  inner socket in this mode.  This also avoids over-reading beyond
         --  the SSH identification line and accidentally swallowing the first
         --  inner cleartext packet if a server sends it immediately.
         for Byte_Count in 1 .. Max_Identification_Bytes loop
            Status_Value := Read_Exact (Item, Byte_Buffer);
            if Status_Value /= Ok then
               return Status_Value;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Buffers.Append
                (Accumulated_Buffer, Byte_Buffer);
            if Status_Value /= Ok then
               return Status_Value;
            end if;

            Status_Value := Parse_Accumulated;
            if Status_Value = Ok then
               return Ok;
            elsif Status_Value /= Timeout then
               return Status_Value;
            end if;
         end loop;

         return Timeout;
      end if;

      for Attempt_Count in 1 .. Max_Identification_Reads loop
         if not Item.Connected then
            return Connection_Failed;
         end if;

         GNAT.Sockets.Receive_Socket
           (Item.Socket_Item, Read_Buffer, Last_Index);
         if Last_Index < Read_Buffer'First then
            return Read_Failed;
         end if;

         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append
             (Accumulated_Buffer,
              Read_Buffer (Read_Buffer'First .. Last_Index));
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         Status_Value := Parse_Accumulated;
         if Status_Value = Ok then
            return Ok;
         elsif Status_Value /= Timeout then
            return Status_Value;
         end if;
      end loop;

      return Timeout;
   exception
      when GNAT.Sockets.Socket_Error =>
         if Item.Read_Timeout_Configured then
            return Timeout;
         end if;
         return Read_Failed;
      when others =>
         return Internal_Error;
   end Read_Identification;

   function Send_Cleartext_Packet
     (Item : in out Driver; Payload : Stream_Element_Array) return Status
   is
      Packet_Value : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_Clear_Out);
      Status_Value :=
        SSH_Lib.Protocol.Packets.Encode_Cleartext_Packet
          (Item.Clear_State, Payload, Packet_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Buffers.Set
          (Item.Last_Clear_Out,
           SSH_Lib.Protocol.Buffers.To_Array (Packet_Value));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      return Send_All (Item, SSH_Lib.Protocol.Buffers.To_Array (Packet_Value));
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Item.Last_Clear_Out);
         return Internal_Error;
   end Send_Cleartext_Packet;

   function Read_Cleartext_Packet
     (Item    : in out Driver;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer) return Status
   is
      Header_Data         : Stream_Element_Array (1 .. 4);
      Packet_Length_Value : Unsigned_32;
      Next_Cursor         : Stream_Element_Offset;
      Wire_Packet         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value        : Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Payload);
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_Clear_In);

      Status_Value := Read_Exact (Item, Header_Data);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Header_Data, Header_Data'First, Packet_Length_Value, Next_Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Packet_Length_Value
        < Unsigned_32 (1 + SSH_Lib.Protocol.Packets.Minimum_Padding_Size)
        or else
          Packet_Length_Value
          > Unsigned_32 (SSH_Lib.Protocol.Packets.Maximum_Packet_Length)
        or else
          (Natural (Packet_Length_Value) + 4)
          mod SSH_Lib.Protocol.Packets.Cleartext_Block_Size
          /= 0
      then
         return Handshake_Failed;
      end if;

      Status_Value := SSH_Lib.Protocol.Buffers.Set (Wire_Packet, Header_Data);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      declare
         Body_Data :
           Stream_Element_Array
             (1 .. Stream_Element_Offset (Packet_Length_Value));
      begin
         Status_Value := Read_Exact (Item, Body_Data);
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append (Wire_Packet, Body_Data);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end;

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Set
          (Item.Last_Clear_In,
           SSH_Lib.Protocol.Buffers.To_Array (Wire_Packet));
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return
        SSH_Lib.Protocol.Packets.Decode_Cleartext_Packet
          (Item.Clear_State,
           SSH_Lib.Protocol.Buffers.To_Array (Wire_Packet),
           Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         SSH_Lib.Protocol.Buffers.Clear (Item.Last_Clear_In);
         return Internal_Error;
   end Read_Cleartext_Packet;

   function Send_Key_Exchange_Packet
     (Item : in out Driver; Payload : Stream_Element_Array) return Status is
   begin
      if Item.Protected_Installed then
         return Send_Protected_Packet (Item, Payload);
      end if;
      return Send_Cleartext_Packet (Item, Payload);
   exception
      when others =>
         return Internal_Error;
   end Send_Key_Exchange_Packet;

   function Read_Key_Exchange_Packet
     (Item    : in out Driver;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer) return Status is
   begin
      if Item.Protected_Installed then
         return Read_Protected_Packet (Item, Payload);
      end if;
      return Read_Cleartext_Packet (Item, Payload);
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Internal_Error;
   end Read_Key_Exchange_Packet;

   function Install_Protected_Keys
     (Item : in out Driver; Mac_Key : Stream_Element_Array) return Status is
   begin
      SSH_Lib.Protocol.Protected_Packets.Reset (Item.Protected_State, Mac_Key);
      Item.Protected_Installed := True;
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_Protected_Out);
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_Protected_In);
      return Ok;
   exception
      when others =>
         Item.Protected_Installed := False;
         return Internal_Error;
   end Install_Protected_Keys;

   function Install_Protected_Keys
     (Item              : in out Driver;
      Cipher_Name       : String;
      Outbound_Mac_Key  : Stream_Element_Array;
      Inbound_Mac_Key   : Stream_Element_Array;
      Outbound_Key_Data : Stream_Element_Array;
      Outbound_IV_Data  : Stream_Element_Array;
      Inbound_Key_Data  : Stream_Element_Array;
      Inbound_IV_Data   : Stream_Element_Array) return Status is
   begin
      return
        Install_Protected_Keys
          (Item,
           Cipher_Name,
           Cipher_Name,
           "hmac-sha2-256",
           "hmac-sha2-256",
           Outbound_Mac_Key,
           Inbound_Mac_Key,
           Outbound_Key_Data,
           Outbound_IV_Data,
           Inbound_Key_Data,
           Inbound_IV_Data);
   end Install_Protected_Keys;

   function Install_Protected_Keys
     (Item                 : in out Driver;
      Outbound_Cipher_Name : String;
      Inbound_Cipher_Name  : String;
      Outbound_Mac_Name    : String;
      Inbound_Mac_Name     : String;
      Outbound_Mac_Key     : Stream_Element_Array;
      Inbound_Mac_Key      : Stream_Element_Array;
      Outbound_Key_Data    : Stream_Element_Array;
      Outbound_IV_Data     : Stream_Element_Array;
      Inbound_Key_Data     : Stream_Element_Array;
      Inbound_IV_Data      : Stream_Element_Array) return Status is
   begin
      return
        Install_Protected_Keys
          (Item,
           Outbound_Cipher_Name,
           Inbound_Cipher_Name,
           Outbound_Mac_Name,
           Inbound_Mac_Name,
           "none",
           "none",
           Outbound_Mac_Key,
           Inbound_Mac_Key,
           Outbound_Key_Data,
           Outbound_IV_Data,
           Inbound_Key_Data,
           Inbound_IV_Data);
   end Install_Protected_Keys;

   function Install_Protected_Keys
     (Item                 : in out Driver;
      Outbound_Cipher_Name : String;
      Inbound_Cipher_Name  : String;
      Outbound_Mac_Name    : String;
      Inbound_Mac_Name     : String;
      Outbound_Compression : String;
      Inbound_Compression  : String;
      Outbound_Mac_Key     : Stream_Element_Array;
      Inbound_Mac_Key      : Stream_Element_Array;
      Outbound_Key_Data    : Stream_Element_Array;
      Outbound_IV_Data     : Stream_Element_Array;
      Inbound_Key_Data     : Stream_Element_Array;
      Inbound_IV_Data      : Stream_Element_Array) return Status is
   begin
      SSH_Lib.Protocol.Protected_Packets.Reset_With_Ciphers
        (Item.Protected_State,
         Outbound_Cipher_Name,
         Inbound_Cipher_Name,
         Outbound_Mac_Name,
         Inbound_Mac_Name,
         Outbound_Compression,
         Inbound_Compression,
         Outbound_Mac_Key,
         Inbound_Mac_Key,
         Outbound_Key_Data,
         Outbound_IV_Data,
         Inbound_Key_Data,
         Inbound_IV_Data);
      if SSH_Lib.Protocol.Protected_Packets.Is_Dirty (Item.Protected_State)
      then
         Item.Protected_Installed := False;
         return
           SSH_Lib.Protocol.Protected_Packets.Last_Failure
             (Item.Protected_State);
      end if;
      --  Terrapin strict-kex resets the packet sequence to zero after NEWKEYS;
      --  otherwise the encrypted stream continues the cleartext handshake count.
      if Item.Strict_Kex then
         SSH_Lib.Protocol.Protected_Packets.Set_Sequences_For_Test
           (Item.Protected_State, Inbound_Value => 0, Outbound_Value => 0);
      else
         SSH_Lib.Protocol.Protected_Packets.Set_Sequences_For_Test
           (Item.Protected_State,
            Inbound_Value  =>
              SSH_Lib.Protocol.Packets.Inbound_Sequence (Item.Clear_State),
            Outbound_Value =>
              SSH_Lib.Protocol.Packets.Outbound_Sequence (Item.Clear_State));
      end if;
      Item.Protected_Installed := True;
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_Protected_Out);
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_Protected_In);
      return Ok;
   exception
      when others =>
         Item.Protected_Installed := False;
         return Internal_Error;
   end Install_Protected_Keys;

   function Activate_Delayed_Compression (Item : in out Driver) return Status
   is
      Status_Value : Status;
   begin
      if not Item.Protected_Installed then
         return Handshake_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Protected_Packets.Activate_Delayed_Compression
          (Item.Protected_State);
      if Status_Value /= Ok then
         Item.Protected_Installed := False;
      end if;
      return Status_Value;
   exception
      when others =>
         Item.Protected_Installed := False;
         return Internal_Error;
   end Activate_Delayed_Compression;

   function Send_Protected_Packet
     (Item : in out Driver; Payload : Stream_Element_Array) return Status
   is
      Packet_Value : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_Protected_Out);
      if not Item.Protected_Installed then
         return Handshake_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Protected_Packets.Encode_Protected_Packet
          (Item.Protected_State, Payload, Packet_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Set
          (Item.Last_Protected_Out,
           SSH_Lib.Protocol.Buffers.To_Array (Packet_Value));
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return Send_All (Item, SSH_Lib.Protocol.Buffers.To_Array (Packet_Value));
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Item.Last_Protected_Out);
         return Internal_Error;
   end Send_Protected_Packet;

   function Read_Protected_Packet
     (Item    : in out Driver;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer) return Status
   is
      Header_Data         : Stream_Element_Array (1 .. 4);
      Plain_Header_Data   : Stream_Element_Array (1 .. 4);
      Packet_Length_Value : Unsigned_32;
      Next_Cursor         : Stream_Element_Offset;
      Wire_Packet         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value        : Status;
   begin
      <<Restart_Protected_Read>>
      SSH_Lib.Protocol.Buffers.Clear (Payload);
      SSH_Lib.Protocol.Buffers.Clear (Item.Last_Protected_In);
      if not Item.Protected_Installed then
         return Handshake_Failed;
      end if;

      if SSH_Lib.Protocol.Protected_Packets.Inbound_Header_Requires_Block
           (Item.Protected_State)
      then
         declare
            Block_Size : constant Natural :=
              SSH_Lib.Protocol.Protected_Packets.Inbound_Block_Size
                (Item.Protected_State);
            First_Block :
              Stream_Element_Array (1 .. Stream_Element_Offset (Block_Size));
            Plain_First_Block :
              Stream_Element_Array (1 .. Stream_Element_Offset (Block_Size));
         begin
            Status_Value := Read_Exact (Item, First_Block);
            if Status_Value /= Ok then
               if Status_Value = Timeout then
                  Status_Value := Send_Server_Alive_Probe (Item);
                  if Status_Value = Ok then
                     goto Restart_Protected_Read;
                  end if;
               end if;
               return Status_Value;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Protected_Packets.Decode_Protected_First_Block_Header
                (Item.Protected_State, First_Block, Plain_First_Block);
            if Status_Value /= Ok then
               return Status_Value;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Numbers.Decode_Uint32
                (Plain_First_Block,
                 Plain_First_Block'First,
                 Packet_Length_Value,
                 Next_Cursor);
            if Status_Value /= Ok then
               return Status_Value;
            end if;

            if Packet_Length_Value
              < Unsigned_32 (1 + SSH_Lib.Protocol.Packets.Minimum_Padding_Size)
              or else
                Packet_Length_Value
                > Unsigned_32 (SSH_Lib.Protocol.Packets.Maximum_Packet_Length)
              or else Natural (Packet_Length_Value) + 4 < Block_Size
              or else (Natural (Packet_Length_Value) + 4) mod Block_Size /= 0
            then
               SSH_Lib.Protocol.Protected_Packets.Mark_Dirty
                 (Item.Protected_State, Handshake_Failed);
               return Handshake_Failed;
            end if;

            Status_Value := SSH_Lib.Protocol.Buffers.Set (Wire_Packet, First_Block);
            if Status_Value /= Ok then
               return Status_Value;
            end if;

            declare
               Rest_And_Mac :
                 Stream_Element_Array
                   (1
                    ..
                      Stream_Element_Offset
                        (Natural (Packet_Length_Value)
                         + 4
                         - Block_Size
                         + SSH_Lib.Protocol.Protected_Packets.Inbound_Mac_Size
                             (Item.Protected_State)));
            begin
               Status_Value := Read_Exact (Item, Rest_And_Mac);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;

               Status_Value :=
                 SSH_Lib.Protocol.Buffers.Append (Wire_Packet, Rest_And_Mac);
               if Status_Value /= Ok then
                  return Status_Value;
               end if;

               Status_Value :=
                 SSH_Lib.Protocol.Buffers.Set
                   (Item.Last_Protected_In,
                    SSH_Lib.Protocol.Buffers.To_Array (Wire_Packet));
               if Status_Value /= Ok then
                  return Status_Value;
               end if;

               Status_Value :=
                 SSH_Lib.Protocol.Protected_Packets
                   .Decode_Protected_Packet_After_First_Block
                      (Item.Protected_State,
                       Plain_First_Block,
                       Rest_And_Mac,
                       Payload);
               if Status_Value = Ok then
                  declare
                     Payload_Data : constant Stream_Element_Array :=
                       SSH_Lib.Protocol.Buffers.To_Array (Payload);
                  begin
                     Item.Server_Alive_Missed := 0;
                     if Item.Server_Alive_Awaiting_Reply
                       and then SSH_Lib.Protocol.Global_Requests
                         .Is_Keepalive_Success (Payload_Data)
                     then
                        Item.Server_Alive_Awaiting_Reply := False;
                        goto Restart_Protected_Read;
                     end if;
                  end;
               end if;
               return Status_Value;
            end;
         end;
      end if;

      Status_Value := Read_Exact (Item, Header_Data);
      if Status_Value /= Ok then
         if Status_Value = Timeout then
            Status_Value := Send_Server_Alive_Probe (Item);
            if Status_Value = Ok then
               goto Restart_Protected_Read;
            end if;
         end if;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Protected_Packets.Decode_Protected_Header
          (Item.Protected_State, Header_Data, Plain_Header_Data);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_Uint32
          (Plain_Header_Data,
           Plain_Header_Data'First,
           Packet_Length_Value,
           Next_Cursor);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Packet_Length_Value
        < Unsigned_32 (1 + SSH_Lib.Protocol.Packets.Minimum_Padding_Size)
        or else
          Packet_Length_Value
          > Unsigned_32 (SSH_Lib.Protocol.Packets.Maximum_Packet_Length)
        or else
          (Natural (Packet_Length_Value)
           + (if SSH_Lib.Protocol.Protected_Packets.Inbound_Length_In_Alignment
                   (Item.Protected_State)
              then 4 else 0))
          mod
            SSH_Lib.Protocol.Protected_Packets.Inbound_Block_Size
              (Item.Protected_State)
          /= 0
      then
         SSH_Lib.Protocol.Protected_Packets.Mark_Dirty
           (Item.Protected_State, Handshake_Failed);
         return Handshake_Failed;
      end if;

      Status_Value := SSH_Lib.Protocol.Buffers.Set (Wire_Packet, Header_Data);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      declare
         Body_And_Mac :
           Stream_Element_Array
             (1
              ..
                Stream_Element_Offset
                  (Natural (Packet_Length_Value)
                   + SSH_Lib.Protocol.Protected_Packets.Inbound_Mac_Size
                       (Item.Protected_State)));
      begin
         Status_Value := Read_Exact (Item, Body_And_Mac);
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         Status_Value :=
           SSH_Lib.Protocol.Buffers.Append (Wire_Packet, Body_And_Mac);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end;

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Set
          (Item.Last_Protected_In,
           SSH_Lib.Protocol.Buffers.To_Array (Wire_Packet));
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      declare
         Wire_Array : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Wire_Packet);
      begin
         Status_Value :=
           SSH_Lib
             .Protocol
             .Protected_Packets
             .Decode_Protected_Packet_After_Header
                (Item.Protected_State,
                 Plain_Header_Data,
                 Wire_Array (Wire_Array'First + 4 .. Wire_Array'Last),
                 Payload);
         if Status_Value = Ok then
            declare
               Payload_Data : constant Stream_Element_Array :=
                 SSH_Lib.Protocol.Buffers.To_Array (Payload);
            begin
               Item.Server_Alive_Missed := 0;
               if Item.Server_Alive_Awaiting_Reply
                 and then SSH_Lib.Protocol.Global_Requests
                   .Is_Keepalive_Success (Payload_Data)
               then
                  Item.Server_Alive_Awaiting_Reply := False;
                  goto Restart_Protected_Read;
               end if;
            end;
         end if;
         return Status_Value;
      end;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         SSH_Lib.Protocol.Buffers.Clear (Item.Last_Protected_In);
         return Internal_Error;
   end Read_Protected_Packet;

   function Local_Identification (Item : Driver) return String is
   begin
      if Length (Item.Local_Identification_Text) = 0 then
         return SSH_Lib.Protocol.Identification.Local_Identification;
      end if;
      return To_String (Item.Local_Identification_Text);
   end Local_Identification;

   function Remote_Identification (Item : Driver) return String is
   begin
      return To_String (Item.Remote_Identification_Text);
   end Remote_Identification;

   function Last_Cleartext_Outbound (Item : Driver) return Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Item.Last_Clear_Out);
   end Last_Cleartext_Outbound;

   function Last_Cleartext_Inbound (Item : Driver) return Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Item.Last_Clear_In);
   end Last_Cleartext_Inbound;

   function Last_Protected_Outbound (Item : Driver) return Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Item.Last_Protected_Out);
   end Last_Protected_Outbound;

   function Last_Protected_Inbound (Item : Driver) return Stream_Element_Array
   is
   begin
      return SSH_Lib.Protocol.Buffers.To_Array (Item.Last_Protected_In);
   end Last_Protected_Inbound;
end SSH_Lib.Sessions.Live_Transcript;
