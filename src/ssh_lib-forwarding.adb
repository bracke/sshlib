with System.Address_To_Access_Conversions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with SSH_Lib.Internal;
with SSH_Lib.Platform.Environment;

package body SSH_Lib.Forwarding is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;
   use type System.Address;

   package Session_Address_Conversions is new
     System.Address_To_Access_Conversions (SSH_Lib.Sessions.Session);
   use type Session_Address_Conversions.Object_Pointer;

   package Service_Address_Conversions is new
     System.Address_To_Access_Conversions (Forward_Service);
   use type Service_Address_Conversions.Object_Pointer;

   package Managed_Service_Address_Conversions is new
     System.Address_To_Access_Conversions (Managed_Forward_Service);
   use type Managed_Service_Address_Conversions.Object_Pointer;

   Maximum_Backlog : constant Natural := 128;
   Max_SOCKS5_Request_Length : constant Stream_Element_Offset := 262;
   Maximum_Pump_Chunk_Size : constant Natural := 65_536;
   X11_TCP_Base_Port : constant Natural := 6000;
   X11_Max_Display_Number : constant Natural := 65_535 - X11_TCP_Base_Port;
   X11_Max_Screen_Number : constant Natural := 65_535;

   function Managed_Remote_Target_Host
     (Service : Managed_Forward_Service) return String;

   function Managed_Remote_Bind_Host
     (Service : Managed_Forward_Service) return String;

   function Open_TCP_Connection
     (Host       : String;
      Port       : Natural;
      Connection : out Local_Forward_Connection)
      return Status;

   procedure Reset_Managed_Service_Runtime
     (Service : in out Managed_Forward_Service) is
   begin
      Service.Running := False;
      Service.Stop_Requested := False;
      Service.Last_Status := Ok;
      Service.Accepted_Count := 0;
      Service.Completed_Count := 0;
      Service.Active_Count := 0;
      Service.Failed_Count := 0;
      Service.Max_Concurrent_Count := 0;
      Service.Max_Accepted_Count := 0;
      Service.Max_Pump_Iterations_Value := 64;
      Service.Max_Chunk_Size_Value := 4096;
      Service.Remote_Bind_Host_Text := [others => Character'Val (0)];
      Service.Remote_Bind_Host_Length := 0;
      Service.Remote_Bind_Port_Value := 0;
      Service.Remote_Bound_Port_Value := 0;
      Service.Remote_Target_Host_Text := [others => Character'Val (0)];
      Service.Remote_Target_Host_Length := 0;
      Service.Remote_Target_Port_Value := 0;
      Service.Workers := [others => null];
   exception
      when others =>
         null;
   end Reset_Managed_Service_Runtime;

   procedure Reset_Service_Runtime (Service : in out Forward_Service) is
   begin
      Service.Running := False;
      Service.Stop_Requested := False;
      Service.Last_Status := Ok;
      Service.Accepted_Count := 0;
      Service.Max_Accepted_Count := 0;
   exception
      when others =>
         null;
   end Reset_Service_Runtime;

   task body Forward_Service_Task is
      Service_Ptr           : Service_Address_Conversions.Object_Pointer :=
        null;
      Session_Ptr           : Session_Address_Conversions.Object_Pointer :=
        null;
      Service_Address_Value : System.Address := System.Null_Address;
      Session_Address_Value : System.Address := System.Null_Address;
      Status_Value          : Status := Ok;
   begin
      accept Start
        (Service_Address : System.Address;
         Session_Address : System.Address)
      do
         Service_Address_Value := Service_Address;
         Session_Address_Value := Session_Address;
      end Start;

      if Service_Address_Value /= System.Null_Address then
         Service_Ptr :=
           Service_Address_Conversions.To_Pointer (Service_Address_Value);
      end if;
      if Session_Address_Value /= System.Null_Address then
         Session_Ptr :=
           Session_Address_Conversions.To_Pointer (Session_Address_Value);
      end if;

      if Service_Ptr /= null and then Session_Ptr /= null then
         Service_Ptr.Running := True;
         Service_Ptr.Last_Status := Ok;

         loop
            exit when Service_Ptr.Stop_Requested;

            declare
               Connection : Local_Forward_Connection;
               Channel    : SSH_Lib.Channels.Channel;
               Target     : SOCKS5_Target;
            begin
               case Service_Ptr.Mode is
                  when Local_Forward_Service =>
                     Status_Value :=
                       Accept_Local_Forward
                         (Session_Ptr.all,
                          Service_Ptr.Listener,
                          Connection,
                          Channel);
                     if Status_Value = Ok then
                        Service_Ptr.Accepted_Count :=
                          Service_Ptr.Accepted_Count + 1;
                        if Service_Ptr.Max_Accepted_Count > 0
                          and then Service_Ptr.Accepted_Count
                            >= Service_Ptr.Max_Accepted_Count
                        then
                           Service_Ptr.Stop_Requested := True;
                        end if;
                     end if;
                     if Service_Ptr.Local_Handler /= null then
                        Service_Ptr.Local_Handler
                          (Connection, Channel, Status_Value);
                     end if;

                  when Dynamic_Forward_Service =>
                     Status_Value :=
                       Accept_Dynamic_Forward
                         (Session_Ptr.all,
                          Service_Ptr.Listener,
                          Connection,
                          Channel,
                          Target);
                     if Status_Value = Ok then
                        Service_Ptr.Accepted_Count :=
                          Service_Ptr.Accepted_Count + 1;
                        if Service_Ptr.Max_Accepted_Count > 0
                          and then Service_Ptr.Accepted_Count
                            >= Service_Ptr.Max_Accepted_Count
                        then
                           Service_Ptr.Stop_Requested := True;
                        end if;
                     end if;
                     if Service_Ptr.Dynamic_Handler /= null then
                        Service_Ptr.Dynamic_Handler
                          (Connection, Channel, Target, Status_Value);
                     end if;

                  when Remote_Forward_Service =>
                     Status_Value := Invalid_Command;
               end case;

               if Status_Value /= Ok then
                  if not Service_Ptr.Stop_Requested then
                     Service_Ptr.Last_Status := Status_Value;
                  end if;
                  exit;
               end if;

               declare
                  Ignored_Channel_Close : constant Status :=
                    SSH_Lib.Channels.Close (Channel);
                  Ignored_Connection_Close : constant Status := Close (Connection);
               begin
                  null;
               end;
            end;
         end loop;

         declare
            Ignored_Status : constant Status := Close (Service_Ptr.Listener);
         begin
            null;
         end;
         Service_Ptr.Running := False;
         Service_Ptr.Stop_Requested := False;
      end if;
   exception
      when others =>
         if Service_Ptr /= null then
            Service_Ptr.Last_Status := Internal_Error;
            Service_Ptr.Running := False;
            Service_Ptr.Stop_Requested := False;
            declare
               Ignored_Status : constant Status := Close (Service_Ptr.Listener);
            begin
               null;
            end;
         end if;
   end Forward_Service_Task;

   task body Managed_Forward_Worker is
      Service_Ptr           : Managed_Service_Address_Conversions.Object_Pointer :=
        null;
      Session_Ptr           : Session_Address_Conversions.Object_Pointer :=
        null;
      Service_Address_Value : System.Address := System.Null_Address;
      Session_Address_Value : System.Address := System.Null_Address;
      Status_Value          : Status := Ok;
   begin
      accept Start
        (Service_Address : System.Address;
         Session_Address : System.Address)
      do
         Service_Address_Value := Service_Address;
         Session_Address_Value := Session_Address;
      end Start;

      if Service_Address_Value /= System.Null_Address then
         Service_Ptr :=
           Managed_Service_Address_Conversions.To_Pointer
             (Service_Address_Value);
      end if;
      if Session_Address_Value /= System.Null_Address then
         Session_Ptr :=
           Session_Address_Conversions.To_Pointer (Session_Address_Value);
      end if;

      if Service_Ptr /= null and then Session_Ptr /= null then
         loop
            exit when Service_Ptr.Stop_Requested;
            exit when Service_Ptr.Max_Accepted_Count > 0
              and then Service_Ptr.Accepted_Count
                >= Service_Ptr.Max_Accepted_Count;

            declare
               Connection : Local_Forward_Connection;
               Channel    : SSH_Lib.Channels.Channel;
               Target     : SOCKS5_Target;
               Local_Bytes : Natural := 0;
               Channel_Bytes : Natural := 0;
            begin
               case Service_Ptr.Mode is
                  when Local_Forward_Service =>
                     Status_Value :=
                       Accept_Local_Forward
                         (Session_Ptr.all,
                          Service_Ptr.Listener,
                          Connection,
                          Channel);

                  when Dynamic_Forward_Service =>
                     Status_Value :=
                       Accept_Dynamic_Forward
                         (Session_Ptr.all,
                          Service_Ptr.Listener,
                          Connection,
                          Channel,
                          Target);

                  when Remote_Forward_Service =>
                     Status_Value :=
                       SSH_Lib.Channels.Accept_Forwarded_TCPIP
                         (Session_Ptr.all,
                          Channel);
                     if Status_Value = Ok then
                        Status_Value :=
                          Open_TCP_Connection
                            (Managed_Remote_Target_Host (Service_Ptr.all),
                             Service_Ptr.Remote_Target_Port_Value,
                             Connection);
                        if Status_Value /= Ok then
                           declare
                              Ignored_Channel_Close : constant Status :=
                                SSH_Lib.Channels.Close (Channel);
                           begin
                              null;
                           end;
                        end if;
                     end if;
               end case;

               if Status_Value /= Ok then
                  if not Service_Ptr.Stop_Requested then
                     Service_Ptr.Last_Status := Status_Value;
                     Service_Ptr.Failed_Count := Service_Ptr.Failed_Count + 1;
                  end if;
                  exit;
               end if;

               Service_Ptr.Accepted_Count := Service_Ptr.Accepted_Count + 1;
               Service_Ptr.Active_Count := Service_Ptr.Active_Count + 1;

               loop
                  exit when Service_Ptr.Stop_Requested;
                  Status_Value :=
                    Pump_Bounded
                      (Connection,
                       Channel,
                       Local_Bytes,
                       Channel_Bytes,
                       Service_Ptr.Max_Pump_Iterations_Value,
                       Service_Ptr.Max_Chunk_Size_Value);
                  exit when Status_Value /= Ok and then Status_Value /= Timeout;
               end loop;

               if Status_Value /= Ok
                 and then Status_Value /= Timeout
                 and then not Service_Ptr.Stop_Requested
               then
                  Service_Ptr.Last_Status := Status_Value;
                  Service_Ptr.Failed_Count := Service_Ptr.Failed_Count + 1;
               end if;

               if Service_Ptr.Active_Count > 0 then
                  Service_Ptr.Active_Count := Service_Ptr.Active_Count - 1;
               end if;
               Service_Ptr.Completed_Count := Service_Ptr.Completed_Count + 1;

               declare
                  Ignored_Channel_Close : constant Status :=
                    SSH_Lib.Channels.Close (Channel);
                  Ignored_Connection_Close : constant Status := Close (Connection);
               begin
                  null;
               end;
            end;
         end loop;

         if Service_Ptr.Mode = Remote_Forward_Service
           and then Service_Ptr.Remote_Bound_Port_Value > 0
         then
            declare
               Ignored_Cancel : constant Status :=
                 SSH_Lib.Sessions.Cancel_Remote_Forward
                   (Session_Ptr.all,
                    Managed_Remote_Bind_Host (Service_Ptr.all),
                    Service_Ptr.Remote_Bound_Port_Value);
            begin
               null;
            end;
         end if;
      end if;
   exception
      when others =>
         if Service_Ptr /= null then
            Service_Ptr.Last_Status := Internal_Error;
            Service_Ptr.Failed_Count := Service_Ptr.Failed_Count + 1;
            if Service_Ptr.Active_Count > 0 then
               Service_Ptr.Active_Count := Service_Ptr.Active_Count - 1;
            end if;
         end if;
   end Managed_Forward_Worker;

   procedure Reset_Listener (Listener : out Local_Forward_Listener) is
   begin
      Listener.Opened := False;
      Listener.Bound_Port_Value := 0;
      Listener.Target_Host_Text := [others => Character'Val (0)];
      Listener.Target_Host_Length := 0;
      Listener.Target_Port_Value := 0;
   exception
      when others =>
         null;
   end Reset_Listener;

   procedure Reset_Connection (Connection : out Local_Forward_Connection) is
   begin
      Connection.Connected := False;
   exception
      when others =>
         null;
   end Reset_Connection;

   procedure Reset_X11_Display_Target (Target : out X11_Display_Target) is
   begin
      Target.Valid := False;
      Target.Kind := X11_Unix_Domain;
      Target.Host_Text := [others => Character'Val (0)];
      Target.Host_Length := 0;
      Target.Socket_Path := [others => Character'Val (0)];
      Target.Path_Length := 0;
      Target.Port_Value := 0;
      Target.Display_Num := 0;
      Target.Screen_Num := 0;
   exception
      when others =>
         null;
   end Reset_X11_Display_Target;

   function Listener_Target_Host
     (Listener : Local_Forward_Listener) return String is
   begin
      if Listener.Target_Host_Length = 0 then
         return "";
      end if;
      return Listener.Target_Host_Text (1 .. Listener.Target_Host_Length);
   end Listener_Target_Host;

   function Managed_Remote_Target_Host
     (Service : Managed_Forward_Service) return String is
   begin
      if Service.Remote_Target_Host_Length = 0 then
         return "";
      end if;
      return Service.Remote_Target_Host_Text
        (1 .. Service.Remote_Target_Host_Length);
   end Managed_Remote_Target_Host;

   function Managed_Remote_Bind_Host
     (Service : Managed_Forward_Service) return String is
   begin
      if Service.Remote_Bind_Host_Length = 0 then
         return "";
      end if;
      return Service.Remote_Bind_Host_Text
        (1 .. Service.Remote_Bind_Host_Length);
   end Managed_Remote_Bind_Host;

   function Port_Status_Allow_Zero
     (Value : Natural) return Status is
   begin
      if Value > 65_535 then
         return Invalid_Port;
      end if;
      return Ok;
   end Port_Status_Allow_Zero;

   function Open_TCP_Connection
     (Host       : String;
      Port       : Natural;
      Connection : out Local_Forward_Connection)
      return Status
   is
      Address_Value : GNAT.Sockets.Sock_Addr_Type;
      Status_Value  : Status;
   begin
      Reset_Connection (Connection);
      if not SSH_Lib.Internal.Valid_Host (Host) then
         return Invalid_Host;
      end if;
      Status_Value := SSH_Lib.Internal.Validate_Port (Port);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      declare
         Host_Entry : constant GNAT.Sockets.Host_Entry_Type :=
           GNAT.Sockets.Get_Host_By_Name (Host);
      begin
         GNAT.Sockets.Create_Socket
           (Connection.Socket,
            GNAT.Sockets.Family_Inet,
            GNAT.Sockets.Socket_Stream);
         Address_Value.Addr := GNAT.Sockets.Addresses (Host_Entry, 1);
         Address_Value.Port := GNAT.Sockets.Port_Type (Port);
         GNAT.Sockets.Connect_Socket (Connection.Socket, Address_Value);
         Connection.Connected := True;
      end;
      return Ok;
   exception
      when GNAT.Sockets.Socket_Error =>
         declare
            Ignored_Status : constant Status := Close (Connection);
         begin
            null;
         end;
         return Connection_Failed;
      when Constraint_Error =>
         declare
            Ignored_Status : constant Status := Close (Connection);
         begin
            null;
         end;
         return Invalid_Host;
      when others =>
         declare
            Ignored_Status : constant Status := Close (Connection);
         begin
            null;
         end;
         return Internal_Error;
   end Open_TCP_Connection;

   function Socket_Port_To_Natural
     (Value : GNAT.Sockets.Port_Type) return Natural is
   begin
      return Natural (Value);
   exception
      when others =>
         return 0;
   end Socket_Port_To_Natural;

   function Peer_Address_Text
     (Address_Value : GNAT.Sockets.Sock_Addr_Type) return String is
   begin
      return GNAT.Sockets.Image (Address_Value.Addr);
   exception
      when others =>
         return "127.0.0.1";
   end Peer_Address_Text;

   function Peer_Port_Value
     (Address_Value : GNAT.Sockets.Sock_Addr_Type) return Natural is
   begin
      return Socket_Port_To_Natural (Address_Value.Port);
   exception
      when others =>
         return 0;
   end Peer_Port_Value;

   procedure Reset_SOCKS5_Target (Target : out SOCKS5_Target) is
   begin
      Target.Host_Text := [others => Character'Val (0)];
      Target.Host_Length := 0;
      Target.Port_Value := 0;
   exception
      when others =>
         null;
   end Reset_SOCKS5_Target;

   function SOCKS5_Host (Target : SOCKS5_Target) return String is
   begin
      if Target.Host_Length = 0 then
         return "";
      end if;
      return Target.Host_Text (1 .. Target.Host_Length);
   exception
      when others =>
         return "";
   end SOCKS5_Host;

   function SOCKS5_Port (Target : SOCKS5_Target) return Natural is
   begin
      return Target.Port_Value;
   exception
      when others =>
         return 0;
   end SOCKS5_Port;

   function X11_Display_Kind
     (Target : X11_Display_Target)
      return X11_Display_Transport is
   begin
      return Target.Kind;
   exception
      when others =>
         return X11_Unix_Domain;
   end X11_Display_Kind;

   function X11_Display_Host (Target : X11_Display_Target) return String is
   begin
      if Target.Host_Length = 0 then
         return "";
      end if;
      return Target.Host_Text (1 .. Target.Host_Length);
   exception
      when others =>
         return "";
   end X11_Display_Host;

   function X11_Display_Port (Target : X11_Display_Target) return Natural is
   begin
      return Target.Port_Value;
   exception
      when others =>
         return 0;
   end X11_Display_Port;

   function X11_Display_Socket_Path
     (Target : X11_Display_Target) return String is
   begin
      if Target.Path_Length = 0 then
         return "";
      end if;
      return Target.Socket_Path (1 .. Target.Path_Length);
   exception
      when others =>
         return "";
   end X11_Display_Socket_Path;

   function X11_Display_Number (Target : X11_Display_Target) return Natural is
   begin
      return Target.Display_Num;
   exception
      when others =>
         return 0;
   end X11_Display_Number;

   function X11_Display_Screen (Target : X11_Display_Target) return Natural is
   begin
      return Target.Screen_Num;
   exception
      when others =>
         return 0;
   end X11_Display_Screen;

   function Decimal_Image (Value : Natural) return String is
      Text : constant String := Natural'Image (Value);
   begin
      return Text (Text'First + 1 .. Text'Last);
   end Decimal_Image;

   function Parse_Natural_Bounded
     (Text  : String;
      Limit : Natural;
      Value : out Natural)
      return Status
   is
      Accumulator : Natural := 0;
   begin
      Value := 0;
      if Text'Length = 0 then
         return Invalid_Host;
      end if;

      for Ch of Text loop
         if Ch not in '0' .. '9' then
            return Invalid_Host;
         end if;
         if Accumulator > (Limit - (Character'Pos (Ch) - Character'Pos ('0'))) / 10
         then
            return Invalid_Port;
         end if;
         Accumulator :=
           Accumulator * 10 + Character'Pos (Ch) - Character'Pos ('0');
      end loop;

      Value := Accumulator;
      return Ok;
   exception
      when Constraint_Error =>
         Value := 0;
         return Invalid_Port;
      when others =>
         Value := 0;
         return Internal_Error;
   end Parse_Natural_Bounded;

   function Store_X11_Display_Target
     (Target         : out X11_Display_Target;
      Kind           : X11_Display_Transport;
      Host           : String;
      Socket_Path    : String;
      Display_Number : Natural;
      Screen_Number  : Natural)
      return Status
   is
   begin
      Reset_X11_Display_Target (Target);
      if Display_Number > X11_Max_Display_Number then
         return Invalid_Port;
      elsif Screen_Number > X11_Max_Screen_Number then
         return Invalid_Port;
      end if;

      Target.Kind := Kind;
      Target.Display_Num := Display_Number;
      Target.Screen_Num := Screen_Number;
      Target.Port_Value := X11_TCP_Base_Port + Display_Number;

      case Kind is
         when X11_TCP =>
            if not SSH_Lib.Internal.Valid_Host (Host)
              or else Host'Length = 0
              or else Host'Length > Target.Host_Text'Length
            then
               Reset_X11_Display_Target (Target);
               return Invalid_Host;
            end if;
            Target.Host_Length := Host'Length;
            Target.Host_Text (1 .. Host'Length) := Host;

         when X11_Unix_Domain =>
            if Socket_Path'Length = 0
              or else Socket_Path'Length > Target.Socket_Path'Length
            then
               Reset_X11_Display_Target (Target);
               return Invalid_Host;
            end if;
            Target.Path_Length := Socket_Path'Length;
            Target.Socket_Path (1 .. Socket_Path'Length) := Socket_Path;
      end case;

      Target.Valid := True;
      return Ok;
   exception
      when others =>
         Reset_X11_Display_Target (Target);
         return Internal_Error;
   end Store_X11_Display_Target;

   function Parse_X11_Display
     (Display : String;
      Target  : out X11_Display_Target)
      return Status
   is
      Colon_Index : constant Natural := Ada.Strings.Fixed.Index (Display, ":");
      Dot_Index   : Natural := 0;
      Display_Number : Natural := 0;
      Screen_Number  : Natural := 0;
      Status_Value   : Status;
   begin
      Reset_X11_Display_Target (Target);
      if Display'Length = 0
        or else Colon_Index = 0
        or else Colon_Index = Display'Last
      then
         return Invalid_Host;
      end if;

      declare
         Host_Part : constant String :=
           Display (Display'First .. Colon_Index - 1);
         Remainder : constant String :=
           Display (Colon_Index + 1 .. Display'Last);
      begin
         Dot_Index := Ada.Strings.Fixed.Index (Remainder, ".");
         if Dot_Index = 0 then
            Status_Value :=
              Parse_Natural_Bounded
                (Remainder, X11_Max_Display_Number, Display_Number);
         elsif Dot_Index = Remainder'First
           or else Dot_Index = Remainder'Last
         then
            return Invalid_Host;
         else
            Status_Value :=
              Parse_Natural_Bounded
                (Remainder (Remainder'First .. Dot_Index - 1),
                 X11_Max_Display_Number,
                 Display_Number);
            if Status_Value /= Ok then
               return Status_Value;
            end if;
            Status_Value :=
              Parse_Natural_Bounded
                (Remainder (Dot_Index + 1 .. Remainder'Last),
                 X11_Max_Screen_Number,
                 Screen_Number);
         end if;

         if Status_Value /= Ok then
            return Status_Value;
         end if;

         if Host_Part'Length = 0 or else Host_Part = "unix" then
            return Store_X11_Display_Target
              (Target,
               X11_Unix_Domain,
               "",
               "/tmp/.X11-unix/X" & Decimal_Image (Display_Number),
               Display_Number,
               Screen_Number);
         else
            return Store_X11_Display_Target
              (Target,
               X11_TCP,
               Host_Part,
               "",
               Display_Number,
               Screen_Number);
         end if;
      end;
   exception
      when Constraint_Error =>
         Reset_X11_Display_Target (Target);
         return Invalid_Host;
      when others =>
         Reset_X11_Display_Target (Target);
         return Internal_Error;
   end Parse_X11_Display;

   function Parse_X11_Display_From_Environment
     (Target : out X11_Display_Target)
      return Status
   is
      Display_Value : constant String :=
        To_String (SSH_Lib.Platform.Environment.Getenv ("DISPLAY"));
   begin
      return Parse_X11_Display (Display_Value, Target);
   exception
      when others =>
         Reset_X11_Display_Target (Target);
         return Internal_Error;
   end Parse_X11_Display_From_Environment;

   function IPv4_Text
     (A, B, C, D : Stream_Element) return String is
   begin
      return Decimal_Image (Natural (A)) & "."
        & Decimal_Image (Natural (B)) & "."
        & Decimal_Image (Natural (C)) & "."
        & Decimal_Image (Natural (D));
   end IPv4_Text;

   function Store_Target
     (Target : out SOCKS5_Target;
      Host   : String;
      Port   : Natural)
      return Status
   is
   begin
      Reset_SOCKS5_Target (Target);
      if not SSH_Lib.Internal.Valid_Host (Host)
        or else Host'Length > Target.Host_Text'Length
      then
         return Invalid_Host;
      end if;
      declare
         Status_Value : constant Status :=
           SSH_Lib.Internal.Validate_Port (Port);
      begin
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end;
      Target.Host_Length := Host'Length;
      Target.Host_Text (1 .. Host'Length) := Host;
      Target.Port_Value := Port;
      return Ok;
   exception
      when others =>
         Reset_SOCKS5_Target (Target);
         return Internal_Error;
   end Store_Target;

   function U16_At
     (Data  : Stream_Element_Array;
      First : Stream_Element_Offset)
      return Natural
   is
   begin
      return Natural (Data (First)) * 256 + Natural (Data (First + 1));
   end U16_At;

   function Parse_SOCKS5_CONNECT_Request
     (Request : Stream_Element_Array;
      Target  : out SOCKS5_Target)
      return Status
   is
      Cursor      : constant Stream_Element_Offset := Request'First;
      Address_Len : Natural;
      Port_Value  : Natural;
   begin
      Reset_SOCKS5_Target (Target);
      if Request'Length < 7
        or else Request (Cursor) /= 16#05#
        or else Request (Cursor + 1) /= 16#01#
        or else Request (Cursor + 2) /= 16#00#
      then
         return Unsupported_Feature;
      end if;

      case Request (Cursor + 3) is
         when 16#01# =>
            if Request'Length /= 10 then
               return Unsupported_Feature;
            end if;
            Port_Value := U16_At (Request, Cursor + 8);
            return Store_Target
              (Target,
               IPv4_Text
                 (Request (Cursor + 4),
                  Request (Cursor + 5),
                  Request (Cursor + 6),
                  Request (Cursor + 7)),
               Port_Value);

         when 16#03# =>
            Address_Len := Natural (Request (Cursor + 4));
            if Address_Len = 0
              or else Address_Len > Target.Host_Text'Length
              or else Request'Length /= Stream_Element_Offset (7 + Address_Len)
            then
               return Invalid_Host;
            end if;
            declare
               Host_Text : String (1 .. Address_Len);
               Host_First : constant Stream_Element_Offset := Cursor + 5;
            begin
               for Index in Host_Text'Range loop
                  Host_Text (Index) :=
                    Character'Val
                      (Request
                         (Host_First
                          + Stream_Element_Offset (Index - Host_Text'First)));
               end loop;
               Port_Value :=
                 U16_At (Request, Host_First + Stream_Element_Offset (Address_Len));
               return Store_Target (Target, Host_Text, Port_Value);
            end;

         when others =>
            return Unsupported_Feature;
      end case;
   exception
      when Constraint_Error =>
         Reset_SOCKS5_Target (Target);
         return Unsupported_Feature;
      when others =>
         Reset_SOCKS5_Target (Target);
         return Internal_Error;
   end Parse_SOCKS5_CONNECT_Request;

   function Read_Exact_Local
     (Connection : Local_Forward_Connection;
      Buffer     : out Stream_Element_Array)
      return Status
   is
      First_Index : Stream_Element_Offset := Buffer'First;
      Last_Index  : Stream_Element_Offset;
   begin
      while First_Index <= Buffer'Last loop
         GNAT.Sockets.Receive_Socket
           (Connection.Socket,
            Buffer (First_Index .. Buffer'Last),
            Last_Index);
         if Last_Index < First_Index then
            return Read_Failed;
         end if;
         First_Index := Last_Index + 1;
      end loop;
      return Ok;
   exception
      when GNAT.Sockets.Socket_Error =>
         return Read_Failed;
      when others =>
         return Internal_Error;
   end Read_Exact_Local;

   function Read_SOCKS5_CONNECT_Request
     (Connection : in out Local_Forward_Connection;
      Target     : out SOCKS5_Target)
      return Status
   is
      Greeting_Header : Stream_Element_Array (1 .. 2);
      Methods         : Stream_Element_Array (1 .. 255);
      Reply           : constant Stream_Element_Array (1 .. 2) :=
        [1 => 16#05#, 2 => 16#00#];
      Reject_Reply    : constant Stream_Element_Array (1 .. 2) :=
        [1 => 16#05#, 2 => 16#FF#];
      Header          : Stream_Element_Array (1 .. 4);
      Has_No_Auth     : Boolean := False;
      Status_Value    : Status;
   begin
      Reset_SOCKS5_Target (Target);
      if not Connection.Connected then
         return Read_Failed;
      end if;

      Status_Value := Read_Exact_Local (Connection, Greeting_Header);
      if Status_Value /= Ok then
         return Status_Value;
      elsif Greeting_Header (1) /= 16#05#
        or else Greeting_Header (2) = 0
      then
         declare
            Ignored_Status : constant Status := Write_Local (Connection, Reject_Reply);
         begin
            null;
         end;
         return Unsupported_Feature;
      end if;

      declare
         Count : constant Stream_Element_Offset :=
           Stream_Element_Offset (Greeting_Header (2));
      begin
         Status_Value := Read_Exact_Local (Connection, Methods (1 .. Count));
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         for Index in 1 .. Count loop
            if Methods (Index) = 16#00# then
               Has_No_Auth := True;
            end if;
         end loop;
      end;

      if not Has_No_Auth then
         declare
            Ignored_Status : constant Status := Write_Local (Connection, Reject_Reply);
         begin
            null;
         end;
         return Unsupported_Feature;
      end if;

      Status_Value := Write_Local (Connection, Reply);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value := Read_Exact_Local (Connection, Header);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      declare
         Request_Data : Stream_Element_Array (1 .. Max_SOCKS5_Request_Length);
         Last_Index   : Stream_Element_Offset := 4;
         Read_First   : Stream_Element_Offset := 5;
      begin
         Request_Data (1 .. 4) := Header;
         case Header (4) is
            when 16#01# =>
               Last_Index := 10;
            when 16#03# =>
               declare
                  Len_Byte : Stream_Element_Array (1 .. 1);
               begin
                  Status_Value := Read_Exact_Local (Connection, Len_Byte);
                  if Status_Value /= Ok then
                     return Status_Value;
                  end if;
                  Request_Data (5) := Len_Byte (1);
                  Last_Index := Stream_Element_Offset (7 + Natural (Len_Byte (1)));
                  Read_First := 6;
               end;
            when others =>
               return Unsupported_Feature;
         end case;

         if Last_Index > Request_Data'Last then
            return Invalid_Host;
         elsif Last_Index >= Read_First then
            Status_Value :=
              Read_Exact_Local
                (Connection, Request_Data (Read_First .. Last_Index));
            if Status_Value /= Ok then
               return Status_Value;
            end if;
         end if;

         return Parse_SOCKS5_CONNECT_Request
           (Request_Data (1 .. Last_Index), Target);
      end;
   exception
      when others =>
         Reset_SOCKS5_Target (Target);
         return Internal_Error;
   end Read_SOCKS5_CONNECT_Request;

   function Send_SOCKS5_Reply
     (Connection   : in out Local_Forward_Connection;
      Reply_Status : Status;
      Bind_Address : String := "0.0.0.0";
      Bind_Port    : Natural := 0)
      return Status
   is
      Reply_Code : constant Stream_Element :=
        (if Reply_Status = Ok then 16#00# else 16#01#);
      Port_Check : Status;
   begin
      if not Connection.Connected then
         return Write_Failed;
      elsif not SSH_Lib.Internal.Valid_Host (Bind_Address) then
         return Invalid_Host;
      end if;
      Port_Check := Port_Status_Allow_Zero (Bind_Port);
      if Port_Check /= Ok then
         return Port_Check;
      end if;

      declare
         Reply : Stream_Element_Array (1 .. 10);
         Port_High : constant Natural := Bind_Port / 256;
         Port_Low  : constant Natural := Bind_Port mod 256;
      begin
         Reply (1) := 16#05#;
         Reply (2) := Reply_Code;
         Reply (3) := 16#00#;
         Reply (4) := 16#01#;
         begin
            declare
               Addr : constant GNAT.Sockets.Inet_Addr_Type :=
                 GNAT.Sockets.Inet_Addr (Bind_Address);
               Text : constant String := GNAT.Sockets.Image (Addr);
               Part_Start : Natural := Text'First;
               Octet_Index : Stream_Element_Offset := 5;
            begin
               for Index in Text'Range loop
                  if Text (Index) = '.' then
                     Reply (Octet_Index) :=
                       Stream_Element'Value (Text (Part_Start .. Index - 1));
                     Octet_Index := Octet_Index + 1;
                     Part_Start := Index + 1;
                  end if;
               end loop;
               Reply (Octet_Index) :=
                 Stream_Element'Value (Text (Part_Start .. Text'Last));
            end;
         exception
            when others =>
               Reply (5 .. 8) := [others => 0];
         end;
         Reply (9) := Stream_Element (Port_High);
         Reply (10) := Stream_Element (Port_Low);
         return Write_Local (Connection, Reply);
      end;
   exception
      when others =>
         return Internal_Error;
   end Send_SOCKS5_Reply;

   function Open_Local_Forward_Listener
     (Bind_Address : String;
      Bind_Port    : Natural;
      Target_Host  : String;
      Target_Port  : Natural;
      Listener     : out Local_Forward_Listener;
      Backlog      : Natural := 16)
      return Status
   is
      Status_Value  : Status;
   begin
      if not SSH_Lib.Internal.Valid_Host (Target_Host)
        or else Target_Host'Length > 255
      then
         return Invalid_Host;
      end if;

      Status_Value := SSH_Lib.Internal.Validate_Port (Target_Port);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Open_Dynamic_Forward_Listener
          (Bind_Address, Bind_Port, Listener, Backlog);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Listener.Target_Host_Length := Target_Host'Length;
      Listener.Target_Host_Text (1 .. Target_Host'Length) := Target_Host;
      Listener.Target_Port_Value := Target_Port;
      return Ok;
   exception
      when GNAT.Sockets.Socket_Error =>
         declare
            Ignored_Status : constant Status := Close (Listener);
         begin
            null;
         end;
         return Connection_Failed;
      when Constraint_Error =>
         declare
            Ignored_Status : constant Status := Close (Listener);
         begin
            null;
         end;
         return Invalid_Host;
      when others =>
         declare
            Ignored_Status : constant Status := Close (Listener);
         begin
            null;
         end;
         return Internal_Error;
   end Open_Local_Forward_Listener;

   function Open_Dynamic_Forward_Listener
     (Bind_Address : String;
      Bind_Port    : Natural;
      Listener     : out Local_Forward_Listener;
      Backlog      : Natural := 16)
      return Status
   is
      Address_Value : GNAT.Sockets.Sock_Addr_Type;
      Bound_Address : GNAT.Sockets.Sock_Addr_Type;
      Listen_Count  : constant Natural :=
        Natural'Min (Natural'Max (Backlog, 1), Maximum_Backlog);
      Status_Value  : Status;
   begin
      Reset_Listener (Listener);

      if not SSH_Lib.Internal.Valid_Host (Bind_Address)
        or else Bind_Address'Length = 0
      then
         return Invalid_Host;
      end if;

      Status_Value := Port_Status_Allow_Zero (Bind_Port);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      GNAT.Sockets.Create_Socket (Listener.Socket);
      Address_Value.Addr := GNAT.Sockets.Inet_Addr (Bind_Address);
      Address_Value.Port := GNAT.Sockets.Port_Type (Bind_Port);
      GNAT.Sockets.Bind_Socket (Listener.Socket, Address_Value);
      GNAT.Sockets.Listen_Socket
        (Listener.Socket, Positive (Listen_Count));
      Bound_Address := GNAT.Sockets.Get_Socket_Name (Listener.Socket);

      Listener.Opened := True;
      Listener.Bound_Port_Value := Socket_Port_To_Natural (Bound_Address.Port);
      return Ok;
   exception
      when GNAT.Sockets.Socket_Error =>
         declare
            Ignored_Status : constant Status := Close (Listener);
         begin
            null;
         end;
         return Connection_Failed;
      when Constraint_Error =>
         declare
            Ignored_Status : constant Status := Close (Listener);
         begin
            null;
         end;
         return Invalid_Host;
      when others =>
         declare
            Ignored_Status : constant Status := Close (Listener);
         begin
            null;
         end;
         return Internal_Error;
   end Open_Dynamic_Forward_Listener;

   function Bound_Port (Listener : Local_Forward_Listener) return Natural is
   begin
      if Listener.Opened then
         return Listener.Bound_Port_Value;
      end if;
      return 0;
   exception
      when others =>
         return 0;
   end Bound_Port;

   function Accept_Local_Forward
     (Session    : in out SSH_Lib.Sessions.Session;
      Listener   : in out Local_Forward_Listener;
      Connection : out Local_Forward_Connection;
      Channel    : in out SSH_Lib.Channels.Channel)
      return Status
   is
      Peer_Address : GNAT.Sockets.Sock_Addr_Type;
      Status_Value : Status;
   begin
      Reset_Connection (Connection);
      if not Listener.Opened then
         return Connection_Failed;
      end if;

      GNAT.Sockets.Accept_Socket
        (Listener.Socket, Connection.Socket, Peer_Address);
      Connection.Connected := True;

      Status_Value :=
        SSH_Lib.Channels.Open_Direct_TCPIP
          (Session,
           Listener_Target_Host (Listener),
           Listener.Target_Port_Value,
           Channel,
           Peer_Address_Text (Peer_Address),
           Peer_Port_Value (Peer_Address));
      if Status_Value /= Ok then
         declare
            Ignored_Status : constant Status := Close (Connection);
         begin
            null;
         end;
      end if;
      return Status_Value;
   exception
      when GNAT.Sockets.Socket_Error =>
         Reset_Connection (Connection);
         return Connection_Failed;
      when others =>
         Reset_Connection (Connection);
         return Internal_Error;
   end Accept_Local_Forward;

   function Accept_Dynamic_Forward
     (Session    : in out SSH_Lib.Sessions.Session;
      Listener   : in out Local_Forward_Listener;
      Connection : out Local_Forward_Connection;
      Channel    : in out SSH_Lib.Channels.Channel;
      Target     : out SOCKS5_Target)
      return Status
   is
      Peer_Address : GNAT.Sockets.Sock_Addr_Type;
      Status_Value : Status;
   begin
      Reset_Connection (Connection);
      Reset_SOCKS5_Target (Target);
      if not Listener.Opened then
         return Connection_Failed;
      end if;

      GNAT.Sockets.Accept_Socket
        (Listener.Socket, Connection.Socket, Peer_Address);
      Connection.Connected := True;

      Status_Value := Read_SOCKS5_CONNECT_Request (Connection, Target);
      if Status_Value /= Ok then
         declare
            Ignored_Reply : constant Status :=
              Send_SOCKS5_Reply (Connection, Status_Value);
            Ignored_Close : constant Status := Close (Connection);
         begin
            null;
         end;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Channels.Open_Direct_TCPIP
          (Session,
           SOCKS5_Host (Target),
           SOCKS5_Port (Target),
           Channel,
           Peer_Address_Text (Peer_Address),
           Peer_Port_Value (Peer_Address));
      declare
         Reply_Status : constant Status :=
           Send_SOCKS5_Reply (Connection, Status_Value);
      begin
         if Status_Value /= Ok then
            declare
               Ignored_Close : constant Status := Close (Connection);
            begin
               null;
            end;
            return Status_Value;
         elsif Reply_Status /= Ok then
            declare
               Ignored_Channel_Close : constant Status :=
                 SSH_Lib.Channels.Close (Channel);
               Ignored_Close : constant Status := Close (Connection);
            begin
               null;
            end;
            return Reply_Status;
         end if;
      end;
      return Ok;
   exception
      when GNAT.Sockets.Socket_Error =>
         Reset_Connection (Connection);
         Reset_SOCKS5_Target (Target);
         return Connection_Failed;
      when others =>
         Reset_Connection (Connection);
      Reset_SOCKS5_Target (Target);
      return Internal_Error;
   end Accept_Dynamic_Forward;

   function Open_X11_Display
     (Target     : X11_Display_Target;
      Connection : out Local_Forward_Connection)
      return Status
   is
      Address_Value : GNAT.Sockets.Sock_Addr_Type;
   begin
      Reset_Connection (Connection);
      if not Target.Valid then
         return Invalid_Host;
      end if;

      case Target.Kind is
         when X11_Unix_Domain =>
            GNAT.Sockets.Create_Socket
              (Connection.Socket,
               GNAT.Sockets.Family_Unix,
               GNAT.Sockets.Socket_Stream);
            Address_Value :=
              GNAT.Sockets.Unix_Socket_Address
                (X11_Display_Socket_Path (Target));

         when X11_TCP =>
            declare
               Host_Entry : constant GNAT.Sockets.Host_Entry_Type :=
                 GNAT.Sockets.Get_Host_By_Name (X11_Display_Host (Target));
            begin
               GNAT.Sockets.Create_Socket
                 (Connection.Socket,
                  GNAT.Sockets.Family_Inet,
                  GNAT.Sockets.Socket_Stream);
               Address_Value.Addr := GNAT.Sockets.Addresses (Host_Entry, 1);
               Address_Value.Port :=
                 GNAT.Sockets.Port_Type (X11_Display_Port (Target));
            end;
      end case;

      GNAT.Sockets.Connect_Socket (Connection.Socket, Address_Value);
      Connection.Connected := True;
      return Ok;
   exception
      when GNAT.Sockets.Socket_Error =>
         declare
            Ignored_Status : constant Status := Close (Connection);
         begin
            null;
         end;
         return Connection_Failed;
      when Constraint_Error =>
         declare
            Ignored_Status : constant Status := Close (Connection);
         begin
            null;
         end;
         return Invalid_Host;
      when others =>
         declare
            Ignored_Status : constant Status := Close (Connection);
         begin
            null;
         end;
         return Connection_Failed;
   end Open_X11_Display;

   function Open_X11_Display
     (Display    : String;
      Connection : out Local_Forward_Connection)
      return Status
   is
      Target : X11_Display_Target;
      Status_Value : Status;
   begin
      Reset_Connection (Connection);
      Status_Value := Parse_X11_Display (Display, Target);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      return Open_X11_Display (Target, Connection);
   exception
      when others =>
         declare
            Ignored_Status : constant Status := Close (Connection);
         begin
            null;
         end;
         return Internal_Error;
   end Open_X11_Display;

   function Read_Local
     (Connection : in out Local_Forward_Connection;
      Buffer     : out Stream_Element_Array;
      Last       : out Stream_Element_Offset)
      return Status
   is
   begin
      Last := Buffer'First - 1;
      if not Connection.Connected then
         return Read_Failed;
      elsif Buffer'Length = 0 then
         return Ok;
      end if;

      GNAT.Sockets.Receive_Socket (Connection.Socket, Buffer, Last);
      if Last < Buffer'First then
         declare
            Ignored_Status : constant Status := Close (Connection);
         begin
            null;
         end;
         return Read_Failed;
      end if;
      return Ok;
   exception
      when GNAT.Sockets.Socket_Error =>
         Last := Buffer'First - 1;
         declare
            Ignored_Status : constant Status := Close (Connection);
         begin
            null;
         end;
         return Read_Failed;
      when others =>
         Last := Buffer'First - 1;
         declare
            Ignored_Status : constant Status := Close (Connection);
         begin
            null;
         end;
         return Internal_Error;
   end Read_Local;

   function Write_Local
     (Connection : in out Local_Forward_Connection;
      Data       : Stream_Element_Array)
      return Status
   is
      First_Index : Stream_Element_Offset := Data'First;
      Last_Index  : Stream_Element_Offset;
   begin
      if not Connection.Connected then
         return Write_Failed;
      elsif Data'Length = 0 then
         return Ok;
      end if;

      while First_Index <= Data'Last loop
         GNAT.Sockets.Send_Socket
           (Connection.Socket,
            Data (First_Index .. Data'Last),
            Last_Index);
         if Last_Index < First_Index then
            declare
               Ignored_Status : constant Status := Close (Connection);
            begin
               null;
            end;
            return Write_Failed;
         end if;
         First_Index := Last_Index + 1;
      end loop;
      return Ok;
   exception
      when GNAT.Sockets.Socket_Error =>
         declare
            Ignored_Status : constant Status := Close (Connection);
         begin
            null;
         end;
         return Write_Failed;
      when others =>
         declare
            Ignored_Status : constant Status := Close (Connection);
         begin
            null;
         end;
         return Internal_Error;
   end Write_Local;

   function Pump_Once
     (Connection     : in out Local_Forward_Connection;
      Channel        : in out SSH_Lib.Channels.Channel;
      Direction      : Pump_Direction;
      Bytes_Moved    : out Natural;
      Max_Chunk_Size : Natural := 4096)
      return Status
   is
      Last_Index   : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Bytes_Moved := 0;
      if Max_Chunk_Size = 0
        or else Max_Chunk_Size > Maximum_Pump_Chunk_Size
      then
         return Invalid_Command;
      end if;

      declare
         Buffer : Stream_Element_Array
           (1 .. Stream_Element_Offset (Max_Chunk_Size));
      begin
         case Direction is
            when Local_To_Channel =>
               Status_Value := Read_Local (Connection, Buffer, Last_Index);
               if Status_Value /= Ok then
                  return Status_Value;
               elsif Last_Index < Buffer'First then
                  return Timeout;
               end if;

               Status_Value :=
                 SSH_Lib.Channels.Write
                   (Channel, Buffer (Buffer'First .. Last_Index));
               if Status_Value = Ok then
                  Bytes_Moved :=
                    Natural (Last_Index - Buffer'First + 1);
               end if;
               return Status_Value;

            when Channel_To_Local =>
               Status_Value :=
                 SSH_Lib.Channels.Read_Some
                   (Channel, Buffer, Last_Index);
               if Status_Value /= Ok then
                  return Status_Value;
               elsif Last_Index < Buffer'First then
                  return Timeout;
               end if;

               Status_Value :=
                 Write_Local
                   (Connection, Buffer (Buffer'First .. Last_Index));
               if Status_Value = Ok then
                  Bytes_Moved :=
                    Natural (Last_Index - Buffer'First + 1);
               end if;
               return Status_Value;
         end case;
      end;
   exception
      when others =>
         Bytes_Moved := 0;
         return Internal_Error;
   end Pump_Once;

   function Pump_Bounded
     (Connection               : in out Local_Forward_Connection;
      Channel                  : in out SSH_Lib.Channels.Channel;
      Local_To_Channel_Bytes   : out Natural;
      Channel_To_Local_Bytes   : out Natural;
      Max_Iterations           : Natural := 64;
      Max_Chunk_Size           : Natural := 4096)
      return Status
   is
      Moved              : Natural := 0;
      Saw_Progress       : Boolean := False;
      Saw_Timeout        : Boolean := False;
      Status_Value       : Status;
   begin
      Local_To_Channel_Bytes := 0;
      Channel_To_Local_Bytes := 0;

      if Max_Iterations = 0
        or else Max_Chunk_Size = 0
        or else Max_Chunk_Size > Maximum_Pump_Chunk_Size
      then
         return Invalid_Command;
      end if;

      for Iteration in 1 .. Max_Iterations loop
         Status_Value :=
           Pump_Once
             (Connection,
              Channel,
              Local_To_Channel,
              Moved,
              Max_Chunk_Size);
         if Status_Value = Ok then
            Local_To_Channel_Bytes := Local_To_Channel_Bytes + Moved;
            Saw_Progress := Saw_Progress or else Moved > 0;
         elsif Status_Value = Timeout then
            Saw_Timeout := True;
         else
            return Status_Value;
         end if;

         Status_Value :=
           Pump_Once
             (Connection,
              Channel,
              Channel_To_Local,
              Moved,
              Max_Chunk_Size);
         if Status_Value = Ok then
            Channel_To_Local_Bytes := Channel_To_Local_Bytes + Moved;
            Saw_Progress := Saw_Progress or else Moved > 0;
         elsif Status_Value = Timeout then
            Saw_Timeout := True;
         else
            return Status_Value;
         end if;
      end loop;

      if Saw_Progress then
         return Ok;
      elsif Saw_Timeout then
         return Timeout;
      end if;
      return Ok;
   exception
      when Constraint_Error =>
         Local_To_Channel_Bytes := 0;
         Channel_To_Local_Bytes := 0;
         return Internal_Error;
      when others =>
         Local_To_Channel_Bytes := 0;
         Channel_To_Local_Bytes := 0;
         return Internal_Error;
   end Pump_Bounded;

   function Start_Local_Forward_Service
     (Session      : in out SSH_Lib.Sessions.Session;
      Bind_Address : String;
      Bind_Port    : Natural;
      Target_Host  : String;
      Target_Port  : Natural;
      Handler      : Local_Forward_Handler;
      Service      : in out Forward_Service;
      Backlog      : Natural := 16;
      Max_Accepted : Natural := 0)
      return Status
   is
      Status_Value : Status;
   begin
      if Handler = null then
         return Invalid_Command;
      elsif Service.Running or else Service.Stop_Requested then
         return Invalid_Command;
      end if;

      Reset_Service_Runtime (Service);
      Status_Value :=
        Open_Local_Forward_Listener
          (Bind_Address,
           Bind_Port,
           Target_Host,
           Target_Port,
           Service.Listener,
           Backlog);
      if Status_Value /= Ok then
         Service.Last_Status := Status_Value;
         return Status_Value;
      end if;

      Service.Mode := Local_Forward_Service;
      Service.Local_Handler := Handler;
      Service.Dynamic_Handler := null;
      Service.Max_Accepted_Count := Max_Accepted;
      Service.Task_Item := new Forward_Service_Task;
      Service.Task_Item.Start (Service'Address, Session'Address);
      return Ok;
   exception
      when others =>
         declare
            Ignored_Status : constant Status := Close (Service.Listener);
         begin
            null;
         end;
         Service.Running := False;
         Service.Stop_Requested := False;
         Service.Last_Status := Internal_Error;
         Service.Task_Item := null;
         return Internal_Error;
   end Start_Local_Forward_Service;

   function Start_Dynamic_Forward_Service
     (Session      : in out SSH_Lib.Sessions.Session;
      Bind_Address : String;
      Bind_Port    : Natural;
      Handler      : Dynamic_Forward_Handler;
      Service      : in out Forward_Service;
      Backlog      : Natural := 16;
      Max_Accepted : Natural := 0)
      return Status
   is
      Status_Value : Status;
   begin
      if Handler = null then
         return Invalid_Command;
      elsif Service.Running or else Service.Stop_Requested then
         return Invalid_Command;
      end if;

      Reset_Service_Runtime (Service);
      Status_Value :=
        Open_Dynamic_Forward_Listener
          (Bind_Address,
           Bind_Port,
           Service.Listener,
           Backlog);
      if Status_Value /= Ok then
         Service.Last_Status := Status_Value;
         return Status_Value;
      end if;

      Service.Mode := Dynamic_Forward_Service;
      Service.Local_Handler := null;
      Service.Dynamic_Handler := Handler;
      Service.Max_Accepted_Count := Max_Accepted;
      Service.Task_Item := new Forward_Service_Task;
      Service.Task_Item.Start (Service'Address, Session'Address);
      return Ok;
   exception
      when others =>
         declare
            Ignored_Status : constant Status := Close (Service.Listener);
         begin
            null;
         end;
         Service.Running := False;
         Service.Stop_Requested := False;
         Service.Last_Status := Internal_Error;
         Service.Task_Item := null;
         return Internal_Error;
   end Start_Dynamic_Forward_Service;

   function Start_Managed_Local_Forward_Service
     (Session             : in out SSH_Lib.Sessions.Session;
      Bind_Address        : String;
      Bind_Port           : Natural;
      Target_Host         : String;
      Target_Port         : Natural;
      Service             : in out Managed_Forward_Service;
      Backlog             : Natural := 16;
      Max_Concurrent      : Natural := 4;
      Max_Accepted        : Natural := 0;
      Max_Pump_Iterations : Natural := 64;
      Max_Chunk_Size      : Natural := 4096)
      return Status
   is
      Status_Value : Status;
      Worker_Count : Natural;
   begin
      if Service.Running or else Service.Stop_Requested then
         return Invalid_Command;
      elsif Max_Concurrent = 0
        or else Max_Concurrent > Maximum_Managed_Forward_Workers
        or else Max_Pump_Iterations = 0
        or else Max_Chunk_Size = 0
        or else Max_Chunk_Size > Maximum_Pump_Chunk_Size
      then
         return Invalid_Command;
      end if;

      Reset_Managed_Service_Runtime (Service);
      Status_Value :=
        Open_Local_Forward_Listener
          (Bind_Address,
           Bind_Port,
           Target_Host,
           Target_Port,
           Service.Listener,
           Backlog);
      if Status_Value /= Ok then
         Service.Last_Status := Status_Value;
         return Status_Value;
      end if;

      Service.Mode := Local_Forward_Service;
      Service.Max_Concurrent_Count := Max_Concurrent;
      Service.Max_Accepted_Count := Max_Accepted;
      Service.Max_Pump_Iterations_Value := Max_Pump_Iterations;
      Service.Max_Chunk_Size_Value := Max_Chunk_Size;
      Service.Running := True;
      Worker_Count := Max_Concurrent;

      for Index_Value in 1 .. Worker_Count loop
         Service.Workers (Index_Value) := new Managed_Forward_Worker;
         Service.Workers (Index_Value).Start (Service'Address, Session'Address);
      end loop;
      return Ok;
   exception
      when others =>
         declare
            Ignored_Status : constant Status := Close (Service.Listener);
         begin
            null;
         end;
         Service.Running := False;
         Service.Stop_Requested := False;
         Service.Last_Status := Internal_Error;
         return Internal_Error;
   end Start_Managed_Local_Forward_Service;

   function Start_Managed_Dynamic_Forward_Service
     (Session             : in out SSH_Lib.Sessions.Session;
      Bind_Address        : String;
      Bind_Port           : Natural;
      Service             : in out Managed_Forward_Service;
      Backlog             : Natural := 16;
      Max_Concurrent      : Natural := 4;
      Max_Accepted        : Natural := 0;
      Max_Pump_Iterations : Natural := 64;
      Max_Chunk_Size      : Natural := 4096)
      return Status
   is
      Status_Value : Status;
      Worker_Count : Natural;
   begin
      if Service.Running or else Service.Stop_Requested then
         return Invalid_Command;
      elsif Max_Concurrent = 0
        or else Max_Concurrent > Maximum_Managed_Forward_Workers
        or else Max_Pump_Iterations = 0
        or else Max_Chunk_Size = 0
        or else Max_Chunk_Size > Maximum_Pump_Chunk_Size
      then
         return Invalid_Command;
      end if;

      Reset_Managed_Service_Runtime (Service);
      Status_Value :=
        Open_Dynamic_Forward_Listener
          (Bind_Address,
           Bind_Port,
           Service.Listener,
           Backlog);
      if Status_Value /= Ok then
         Service.Last_Status := Status_Value;
         return Status_Value;
      end if;

      Service.Mode := Dynamic_Forward_Service;
      Service.Max_Concurrent_Count := Max_Concurrent;
      Service.Max_Accepted_Count := Max_Accepted;
      Service.Max_Pump_Iterations_Value := Max_Pump_Iterations;
      Service.Max_Chunk_Size_Value := Max_Chunk_Size;
      Service.Running := True;
      Worker_Count := Max_Concurrent;

      for Index_Value in 1 .. Worker_Count loop
         Service.Workers (Index_Value) := new Managed_Forward_Worker;
         Service.Workers (Index_Value).Start (Service'Address, Session'Address);
      end loop;
      return Ok;
   exception
      when others =>
         declare
            Ignored_Status : constant Status := Close (Service.Listener);
         begin
            null;
         end;
         Service.Running := False;
         Service.Stop_Requested := False;
         Service.Last_Status := Internal_Error;
         return Internal_Error;
   end Start_Managed_Dynamic_Forward_Service;

   function Start_Managed_Remote_Forward_Service
     (Session             : in out SSH_Lib.Sessions.Session;
      Bind_Address        : String;
      Bind_Port           : Natural;
      Target_Host         : String;
      Target_Port         : Natural;
      Service             : in out Managed_Forward_Service;
      Max_Accepted        : Natural := 0;
      Max_Pump_Iterations : Natural := 64;
      Max_Chunk_Size      : Natural := 4096)
      return Status
   is
      Status_Value     : Status;
      Bound_Port_Value : Natural := 0;
   begin
      if Service.Running or else Service.Stop_Requested then
         return Invalid_Command;
      elsif not SSH_Lib.Internal.Valid_Host (Bind_Address)
        or else Bind_Address'Length > 255
      then
         return Invalid_Host;
      elsif not SSH_Lib.Internal.Valid_Host (Target_Host)
        or else Target_Host'Length > 255
      then
         return Invalid_Host;
      elsif Max_Pump_Iterations = 0
        or else Max_Chunk_Size = 0
        or else Max_Chunk_Size > Maximum_Pump_Chunk_Size
      then
         return Invalid_Command;
      end if;

      Status_Value := Port_Status_Allow_Zero (Bind_Port);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := SSH_Lib.Internal.Validate_Port (Target_Port);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Reset_Managed_Service_Runtime (Service);
      Status_Value :=
        SSH_Lib.Sessions.Request_Remote_Forward
          (Session,
           Bind_Address,
           Bind_Port,
           Bound_Port_Value);
      if Status_Value /= Ok then
         Service.Last_Status := Status_Value;
         return Status_Value;
      end if;

      Service.Mode := Remote_Forward_Service;
      Service.Remote_Bind_Host_Length := Bind_Address'Length;
      Service.Remote_Bind_Host_Text (1 .. Bind_Address'Length) := Bind_Address;
      Service.Remote_Bind_Port_Value := Bind_Port;
      Service.Remote_Bound_Port_Value := Bound_Port_Value;
      Service.Remote_Target_Host_Length := Target_Host'Length;
      Service.Remote_Target_Host_Text (1 .. Target_Host'Length) := Target_Host;
      Service.Remote_Target_Port_Value := Target_Port;
      Service.Max_Concurrent_Count := 1;
      Service.Max_Accepted_Count := Max_Accepted;
      Service.Max_Pump_Iterations_Value := Max_Pump_Iterations;
      Service.Max_Chunk_Size_Value := Max_Chunk_Size;
      Service.Running := True;
      Service.Workers (1) := new Managed_Forward_Worker;
      Service.Workers (1).Start (Service'Address, Session'Address);
      return Ok;
   exception
      when others =>
         if Bound_Port_Value > 0 then
            declare
               Ignored_Cancel : constant Status :=
                 SSH_Lib.Sessions.Cancel_Remote_Forward
                   (Session, Bind_Address, Bound_Port_Value);
            begin
               null;
            end;
         end if;
         Service.Running := False;
         Service.Stop_Requested := False;
         Service.Last_Status := Internal_Error;
         return Internal_Error;
   end Start_Managed_Remote_Forward_Service;

   function Forward_Service_Running (Service : Forward_Service) return Boolean is
   begin
      return Service.Running
        and then not Service.Stop_Requested
        and then Service.Task_Item /= null
        and then Service.Last_Status = Ok;
   exception
      when others =>
         return False;
   end Forward_Service_Running;

   function Forward_Service_Status (Service : Forward_Service) return Status is
   begin
      return Service.Last_Status;
   exception
      when others =>
         return Internal_Error;
   end Forward_Service_Status;

   function Forward_Service_Accepted_Count
     (Service : Forward_Service) return Natural is
   begin
      return Service.Accepted_Count;
   exception
      when others =>
         return 0;
   end Forward_Service_Accepted_Count;

   function Forward_Service_Max_Accepted
     (Service : Forward_Service) return Natural is
   begin
      return Service.Max_Accepted_Count;
   exception
      when others =>
         return 0;
   end Forward_Service_Max_Accepted;

   function Forward_Service_Bound_Port
     (Service : Forward_Service) return Natural is
   begin
      return Bound_Port (Service.Listener);
   exception
      when others =>
         return 0;
   end Forward_Service_Bound_Port;

   function Forward_Service_Kind
     (Service : Forward_Service) return Forward_Service_Mode is
   begin
      return Service.Mode;
   exception
      when others =>
         return Local_Forward_Service;
   end Forward_Service_Kind;

   function Managed_Forward_Service_Running
     (Service : Managed_Forward_Service) return Boolean is
   begin
      return Service.Running
        and then not Service.Stop_Requested
        and then Service.Last_Status = Ok;
   exception
      when others =>
         return False;
   end Managed_Forward_Service_Running;

   function Managed_Forward_Service_Status
     (Service : Managed_Forward_Service) return Status is
   begin
      return Service.Last_Status;
   exception
      when others =>
         return Internal_Error;
   end Managed_Forward_Service_Status;

   function Managed_Forward_Service_Accepted_Count
     (Service : Managed_Forward_Service) return Natural is
   begin
      return Service.Accepted_Count;
   exception
      when others =>
         return 0;
   end Managed_Forward_Service_Accepted_Count;

   function Managed_Forward_Service_Completed_Count
     (Service : Managed_Forward_Service) return Natural is
   begin
      return Service.Completed_Count;
   exception
      when others =>
         return 0;
   end Managed_Forward_Service_Completed_Count;

   function Managed_Forward_Service_Active_Count
     (Service : Managed_Forward_Service) return Natural is
   begin
      return Service.Active_Count;
   exception
      when others =>
         return 0;
   end Managed_Forward_Service_Active_Count;

   function Managed_Forward_Service_Failed_Count
     (Service : Managed_Forward_Service) return Natural is
   begin
      return Service.Failed_Count;
   exception
      when others =>
         return 0;
   end Managed_Forward_Service_Failed_Count;

   function Managed_Forward_Service_Max_Concurrent
     (Service : Managed_Forward_Service) return Natural is
   begin
      return Service.Max_Concurrent_Count;
   exception
      when others =>
         return 0;
   end Managed_Forward_Service_Max_Concurrent;

   function Managed_Forward_Service_Max_Accepted
     (Service : Managed_Forward_Service) return Natural is
   begin
      return Service.Max_Accepted_Count;
   exception
      when others =>
         return 0;
   end Managed_Forward_Service_Max_Accepted;

   function Managed_Forward_Service_Bound_Port
     (Service : Managed_Forward_Service) return Natural is
   begin
      if Service.Mode = Remote_Forward_Service then
         return Service.Remote_Bound_Port_Value;
      end if;
      return Bound_Port (Service.Listener);
   exception
      when others =>
         return 0;
   end Managed_Forward_Service_Bound_Port;

   function Managed_Forward_Service_Kind
     (Service : Managed_Forward_Service) return Forward_Service_Mode is
   begin
      return Service.Mode;
   exception
      when others =>
         return Local_Forward_Service;
   end Managed_Forward_Service_Kind;

   function Stop (Service : in out Forward_Service)
      return Status
   is
      Stored_Status : constant Status := Service.Last_Status;
   begin
      Service.Stop_Requested := True;
      declare
         Ignored_Status : constant Status := Close (Service.Listener);
      begin
         null;
      end;

      delay 0.250;
      Service.Running := False;
      Service.Stop_Requested := False;
      Service.Task_Item := null;
      if Stored_Status = Timeout or else Stored_Status = Connection_Failed then
         Service.Last_Status := Ok;
      end if;
      return Ok;
   exception
      when others =>
         Service.Running := False;
         Service.Stop_Requested := False;
         Service.Task_Item := null;
         Service.Last_Status := Internal_Error;
         return Internal_Error;
   end Stop;

   function Stop (Service : in out Managed_Forward_Service)
      return Status
   is
      Stored_Status : constant Status := Service.Last_Status;
   begin
      Service.Stop_Requested := True;
      declare
         Ignored_Status : constant Status := Close (Service.Listener);
      begin
         null;
      end;

      delay 0.250;
      Service.Running := False;
      Service.Stop_Requested := False;
      Service.Active_Count := 0;
      Service.Workers := [others => null];
      if Stored_Status = Timeout or else Stored_Status = Connection_Failed then
         Service.Last_Status := Ok;
      end if;
      return Ok;
   exception
      when others =>
         Service.Running := False;
         Service.Stop_Requested := False;
         Service.Active_Count := 0;
         Service.Workers := [others => null];
         Service.Last_Status := Internal_Error;
         return Internal_Error;
   end Stop;

   function Close (Connection : in out Local_Forward_Connection)
      return Status
   is
   begin
      if Connection.Connected then
         begin
            GNAT.Sockets.Close_Socket (Connection.Socket);
         exception
            when others =>
               null;
         end;
      end if;
      Reset_Connection (Connection);
      return Ok;
   exception
      when others =>
         Reset_Connection (Connection);
         return Ok;
   end Close;

   function Close (Listener : in out Local_Forward_Listener)
      return Status
   is
   begin
      if Listener.Opened then
         begin
            GNAT.Sockets.Close_Socket (Listener.Socket);
         exception
            when others =>
               null;
         end;
      end if;
      Reset_Listener (Listener);
      return Ok;
   exception
      when others =>
         Reset_Listener (Listener);
         return Ok;
   end Close;
end SSH_Lib.Forwarding;
