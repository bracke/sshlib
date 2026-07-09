with SSH_Lib.Sessions.Close_Pipeline;
with SSH_Lib.Sessions.Channel_IO;
with SSH_Lib.Sessions.Open_Pipeline;
with SSH_Lib.Sessions.Open_Guards;
with SSH_Lib.Sessions.Open_Runtime;
with SSH_Lib.Sessions.Live_Transport;
with SSH_Lib.Sessions.State;
with SSH_Lib.Protocol.Failure_State;
with SSH_Lib.Protocol.Global_Requests;

package body SSH_Lib.Sessions is
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;

   function Options_For_Storage (Options : Session_Options) return Session_Options is
      Result : Session_Options := Options;
   begin
      --  Session_Options may contain an explicit password for live
      --  userauth.  Open passes the caller-provided Options down the
      --  authentication pipeline, but the session object itself must not keep
      --  that secret after validation/handshake setup.  Store only the
      --  non-secret routing and policy fields needed by later channel code.
      SSH_Lib.Sessions.Close_Pipeline.Scrub_Credentials (Result);
      return Result;
   exception
      when others =>
         Result := Options;
         SSH_Lib.Sessions.Close_Pipeline.Scrub_Credentials (Result);
         return Result;
   end Options_For_Storage;

   procedure Reset_For_Open (Item : out Session; Options : Session_Options) is
   begin
      Item.Stored_Options := Options_For_Storage (Options);
      SSH_Lib.Sessions.Close_Pipeline.Reset_To_Closed (Item, Ok);
   end Reset_For_Open;

   procedure Record_Failure
     (Item         : in out Session;
      Status_Value : Status) is
   begin
      SSH_Lib.Sessions.Close_Pipeline.Reset_To_Closed (Item, Status_Value);
   end Record_Failure;

   function Fail
     (Item         : in out Session;
      Status_Value : Status)
      return Status
   is
   begin
      Record_Failure (Item, Status_Value);
      return Status_Value;
   end Fail;

   function Complete_Open_Pipeline
     (Options : Session_Options;
      Item    : in out Session)
      return Status
   is
      Status_Value : Status;
   begin
      Status_Value := SSH_Lib.Sessions.Open_Runtime.Run (Options, Item);
      if Status_Value /= Ok then
         return Fail (Item, Status_Value);
      end if;
      return Ok;
   exception
      when others =>
         return Fail (Item, Internal_Error);
   end Complete_Open_Pipeline;

   function Open
     (Options : Session_Options;
      Item    : out Session)
      return CryptoLib.Errors.Status
   is
      Status_Value : Status;
   begin
      Reset_For_Open (Item, Options);

      Status_Value := SSH_Lib.Sessions.Open_Pipeline.Validate_Options (Options);
      if Status_Value /= Ok then
         return Fail (Item, Status_Value);
      end if;

      Status_Value := Complete_Open_Pipeline (Options, Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      --  This gate remains active even after the live encrypted transport,
      --  host-key trust, protected userauth, and channel-retention paths are
      --  wired.  It prevents a partially-opened session from being published
      --  if any success predicate regresses.
      if not SSH_Lib.Sessions.Open_Guards.Success_Gates_Complete (Item) then
         return Fail
           (Item,
            SSH_Lib.Sessions.Open_Guards.Status_For_Incomplete_Gates (Item));
      end if;

      Item.Current_State := Opened;
      Item.Session_Open := True;
      Item.Session_Closed := False;
      Item.Failure_Status := Ok;
      return Ok;
   exception
      when others =>
         Record_Failure (Item, Internal_Error);
         return Internal_Error;
   end Open;

   function Last_Proxy_Command_Diagnostics
     (Item : Session) return Proxy_Command_Diagnostic is
   begin
      return Item.Last_Proxy_Command_Diagnostic;
   exception
      when others =>
         return (others => <>);
   end Last_Proxy_Command_Diagnostics;

   function Rekey
     (Item : in out Session)
      return CryptoLib.Errors.Status
   is
      Status_Value : Status;
   begin
      Status_Value := SSH_Lib.Sessions.Live_Transport.Rekey (Item);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
      end if;
      return Status_Value;
   exception
      when others =>
         Item.Session_Dirty := True;
         Item.Failure_Status := Internal_Error;
         return Internal_Error;
   end Rekey;

   function Read_Global_Response
     (Item    : in out Session;
      Payload : out Packet_Buffer)
      return Status
   is
   begin
      Clear (Payload);
      if Item.Session_Dirty then
         return
           SSH_Lib.Protocol.Failure_State.Dirty_Session_Operation_Status
             (Channel_Request_Failed);
      elsif not Item.Test_Has_Global_Response then
         Item.Session_Dirty := True;
         Item.Failure_Status := Channel_Request_Failed;
         return Channel_Request_Failed;
      end if;

      return Set (Payload, To_Array (Item.Test_Global_Response));
   exception
      when others =>
         Clear (Payload);
         Item.Session_Dirty := True;
         Item.Failure_Status := Internal_Error;
         return Internal_Error;
   end Read_Global_Response;

   function Request_Remote_Forward
     (Item         : in out Session;
      Bind_Address : String;
      Bind_Port    : Natural;
      Bound_Port   : out Natural)
      return CryptoLib.Errors.Status
   is
      Request_Payload  : Packet_Buffer;
      Response_Payload : Packet_Buffer;
      Status_Value     : Status;
   begin
      Bound_Port := 0;
      if Bind_Port > 65_535 then
         return Invalid_Port;
      elsif not SSH_Lib.Sessions.State.Is_Authenticated_Open (Item) then
         return Channel_Open_Failed;
      elsif Item.Session_Dirty then
         return
           SSH_Lib.Protocol.Failure_State.Dirty_Session_Operation_Status
             (Channel_Request_Failed);
      elsif Item.Stored_Options.Write_Timeout_MS = 0 then
         Item.Failure_Status := Timeout;
         return Timeout;
      end if;

      Request_Payload :=
        SSH_Lib.Protocol.Global_Requests.Encode_TCPIP_Forward_Request
          (Bind_Address, Bind_Port);
      if Is_Empty (Request_Payload) then
         return Invalid_Host;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_IO.Send_Channel_Payload
          (Item, Request_Payload);
      if Status_Value /= Ok then
         if Status_Value /= Timeout then
            Item.Session_Dirty := True;
            Item.Failure_Status := Status_Value;
         end if;
         return Status_Value;
      end if;

      Status_Value := Read_Global_Response (Item, Response_Payload);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return
        SSH_Lib.Protocol.Global_Requests.Parse_TCPIP_Forward_Reply
          (To_Array (Response_Payload), Bind_Port, Bound_Port);
   exception
      when others =>
         Bound_Port := 0;
         Item.Session_Dirty := True;
         Item.Failure_Status := Internal_Error;
         return Internal_Error;
   end Request_Remote_Forward;

   function Cancel_Remote_Forward
     (Item         : in out Session;
      Bind_Address : String;
      Bind_Port    : Natural)
      return CryptoLib.Errors.Status
   is
      Request_Payload  : Packet_Buffer;
      Response_Payload : Packet_Buffer;
      Bound_Port       : Natural := 0;
      Status_Value     : Status;
   begin
      if Bind_Port = 0 or else Bind_Port > 65_535 then
         return Invalid_Port;
      elsif not SSH_Lib.Sessions.State.Is_Authenticated_Open (Item) then
         return Channel_Open_Failed;
      elsif Item.Session_Dirty then
         return
           SSH_Lib.Protocol.Failure_State.Dirty_Session_Operation_Status
             (Channel_Request_Failed);
      elsif Item.Stored_Options.Write_Timeout_MS = 0 then
         Item.Failure_Status := Timeout;
         return Timeout;
      end if;

      Request_Payload :=
        SSH_Lib.Protocol.Global_Requests.Encode_Cancel_TCPIP_Forward_Request
          (Bind_Address, Bind_Port);
      if Is_Empty (Request_Payload) then
         return Invalid_Host;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_IO.Send_Channel_Payload
          (Item, Request_Payload);
      if Status_Value /= Ok then
         if Status_Value /= Timeout then
            Item.Session_Dirty := True;
            Item.Failure_Status := Status_Value;
         end if;
         return Status_Value;
      end if;

      Status_Value := Read_Global_Response (Item, Response_Payload);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Global_Requests.Parse_TCPIP_Forward_Reply
          (To_Array (Response_Payload), Bind_Port, Bound_Port);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return Ok;
   exception
      when others =>
         Item.Session_Dirty := True;
         Item.Failure_Status := Internal_Error;
         return Internal_Error;
   end Cancel_Remote_Forward;

   function Close
     (Item : in out Session)
      return CryptoLib.Errors.Status
   is
   begin
      --  Close is deliberately idempotent and performs best-effort cleanup of
      --  all lifecycle/authentication flags plus session-owned channel table
      --  bookkeeping.  Individual Channel objects are private value handles;
      --  they become stale when this reset advances the session generation.
      SSH_Lib.Sessions.Close_Pipeline.Reset_To_Closed (Item, Ok);
      return Ok;
   exception
      when others =>
         Item.Current_State := Closed;
         Item.Session_Open := False;
         Item.Session_Closed := True;
         SSH_Lib.Sessions.Close_Pipeline.Scrub_Credentials
           (Item.Stored_Options);
         return Ok;
   end Close;

end SSH_Lib.Sessions;
