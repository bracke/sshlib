with Ada.Calendar;
with Ada.Strings.Unbounded;
with Interfaces;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Protected_Packets;
with System;

package SSH_Lib.Sessions is
   type Session is limited private;

   type Credential_Callback_Result is record
      Provided : Boolean := False;
      Secret   : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   type Password_Callback_Access is
     access function
       (Host : String; User : String) return Credential_Callback_Result;

   type Identity_Passphrase_Callback_Access is
     access function
       (Host : String; User : String; Identity_File : String)
        return Credential_Callback_Result;

   type Password_Change_Callback_Access is
     access function
       (Host : String; User : String; Instruction : String)
        return Credential_Callback_Result;

   Max_Keyboard_Interactive_Prompts : constant Positive := 8;
   subtype Keyboard_Interactive_Prompt_Index is Positive
     range 1 .. Max_Keyboard_Interactive_Prompts;

   type Keyboard_Interactive_Prompt is record
      Text : Ada.Strings.Unbounded.Unbounded_String;
      Echo : Boolean := False;
   end record;

   type Keyboard_Interactive_Prompt_Array is
     array (Keyboard_Interactive_Prompt_Index) of Keyboard_Interactive_Prompt;

   type Keyboard_Interactive_Challenge is record
      Name         : Ada.Strings.Unbounded.Unbounded_String;
      Instruction  : Ada.Strings.Unbounded.Unbounded_String;
      Language_Tag : Ada.Strings.Unbounded.Unbounded_String;
      Prompt_Count : Natural range 0 .. Max_Keyboard_Interactive_Prompts := 0;
      Prompts      : Keyboard_Interactive_Prompt_Array;
   end record;

   type Keyboard_Interactive_Response_Array is
     array (Keyboard_Interactive_Prompt_Index)
     of Ada.Strings.Unbounded.Unbounded_String;

   type Keyboard_Interactive_Callback_Result is record
      Provided       : Boolean := False;
      Response_Count : Natural range 0 .. Max_Keyboard_Interactive_Prompts := 0;
      Responses      : Keyboard_Interactive_Response_Array;
   end record;

   type Keyboard_Interactive_Callback_Access is
     access function
       (Host      : String;
        User      : String;
        Challenge : Keyboard_Interactive_Challenge)
        return Keyboard_Interactive_Callback_Result;


   type Proxy_Command_Diagnostic is record
      Configured      : Boolean := False;
      Child_Started   : Boolean := False;
      Child_Open      : Boolean := False;
      Close_Attempted   : Boolean := False;
      Close_Completed   : Boolean := False;
      Exit_Status_Known : Boolean := False;
      Exit_Status       : Integer := 0;
      Shell_Name        : Ada.Strings.Unbounded.Unbounded_String;
      Lifecycle_Stage : Ada.Strings.Unbounded.Unbounded_String;
      Spawn_Status    : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Last_IO_Status  : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
      Close_Status    : CryptoLib.Errors.Status := CryptoLib.Errors.Ok;
   end record;

   type Session_Options is record
      Host                                        :
        Ada.Strings.Unbounded.Unbounded_String;
      Port                                        : Natural := 22;
      User                                        :
        Ada.Strings.Unbounded.Unbounded_String;
      Connect_Timeout_MS                          : Natural := 30_000;
      Read_Timeout_MS                             : Natural := 30_000;
      Write_Timeout_MS                            : Natural := 30_000;
      Verify_Known_Host                           : Boolean := True;
      Known_Hosts_File                            :
        Ada.Strings.Unbounded.Unbounded_String;
      User_Known_Hosts_File                       :
        Ada.Strings.Unbounded.Unbounded_String;
      Global_Known_Hosts_File                     :
        Ada.Strings.Unbounded.Unbounded_String;
      Host_Key_Alias                              :
        Ada.Strings.Unbounded.Unbounded_String;
      Revoked_Host_Keys_File                      :
        Ada.Strings.Unbounded.Unbounded_String;
      Identity_File                               :
        Ada.Strings.Unbounded.Unbounded_String;
      --  Optional OpenSSH public user certificate path.  When empty,
      --  identity-file authentication probes the OpenSSH sibling convention
      --  <Identity_File>-cert.pub.  This path is data-only and is never
      --  executed as a ProxyCommand-style subprocess.
      Certificate_File                            :
        Ada.Strings.Unbounded.Unbounded_String;
      Identity_Agent                              :
        Ada.Strings.Unbounded.Unbounded_String;
      Preferred_Authentications                   :
        Ada.Strings.Unbounded.Unbounded_String;
      Pubkey_Accepted_Algorithms                  :
        Ada.Strings.Unbounded.Unbounded_String;
      Host_Key_Algorithms                         :
        Ada.Strings.Unbounded.Unbounded_String;
      Kex_Algorithms                              :
        Ada.Strings.Unbounded.Unbounded_String;
      Cipher_Algorithms                           :
        Ada.Strings.Unbounded.Unbounded_String;
      Mac_Algorithms                              :
        Ada.Strings.Unbounded.Unbounded_String;
      Compression_Algorithms                      :
        Ada.Strings.Unbounded.Unbounded_String;
      Canonicalize_Hostname                       : Boolean := False;
      Certificate_Authority_File                  :
        Ada.Strings.Unbounded.Unbounded_String;
      Trusted_User_CA_Keys_File                   :
        Ada.Strings.Unbounded.Unbounded_String;
      Allowed_Certificate_Critical_Options        :
        Ada.Strings.Unbounded.Unbounded_String;
      Reject_Unknown_Certificate_Critical_Options : Boolean := False;
      Use_Agent                                   : Boolean := True;
      Strict_Host_Key                             : Boolean := True;
      Proxy_Jump                                  :
        Ada.Strings.Unbounded.Unbounded_String;
      Proxy_Command                               :
        Ada.Strings.Unbounded.Unbounded_String;
      Control_Master                              :
        Ada.Strings.Unbounded.Unbounded_String;
      Control_Path                                :
        Ada.Strings.Unbounded.Unbounded_String;
      Control_Persist                             :
        Ada.Strings.Unbounded.Unbounded_String;
      Local_Forwards                              :
        Ada.Strings.Unbounded.Unbounded_String;
      Remote_Forwards                             :
        Ada.Strings.Unbounded.Unbounded_String;
      Dynamic_Forwards                            :
        Ada.Strings.Unbounded.Unbounded_String;
      Send_Env                                    :
        Ada.Strings.Unbounded.Unbounded_String;
      Set_Env                                     :
        Ada.Strings.Unbounded.Unbounded_String;
      Use_Password                                : Boolean := False;
      Password                                    :
        Ada.Strings.Unbounded.Unbounded_String;
      Use_Identity_Passphrase                     : Boolean := False;
      Identity_Passphrase                         :
        Ada.Strings.Unbounded.Unbounded_String;

      --  Optional non-interactive credential callbacks.  The core library
      --  never prompts on its own and never stores returned secrets in the
      --  Session object.  Explicit Password / Identity_Passphrase values
      --  take precedence; callbacks are consulted only when the corresponding
      --  explicit value is absent and the method is otherwise enabled.
      Password_Callback            : Password_Callback_Access := null;
      Identity_Passphrase_Callback : Identity_Passphrase_Callback_Access :=
        null;
      Password_Change_Callback     : Password_Change_Callback_Access := null;
      Keyboard_Interactive_Callback : Keyboard_Interactive_Callback_Access :=
        null;

      --  Automatic rekeying is enabled by default for live transports.
      --  A zero threshold disables the corresponding trigger.  Inbound and
      --  outbound protected packets are counted, but client-initiated automatic
      --  rekey is started only before the next outbound channel/control packet.
      --  Reads do not start a client rekey while peer channel data may already
      --  be pending on the protected transport.  Rekey_After_Seconds is an
      --  elapsed-time trigger measured from successful NEWKEYS installation.
      Automatic_Rekey     : Boolean := True;
      Rekey_After_Packets : Natural := 1_000_000;
      Rekey_After_Bytes   : Interfaces.Unsigned_64 := 1_073_741_824;
      Rekey_After_Seconds : Natural := 3_600;

      --  RFC 4419 Diffie-Hellman group-exchange request bounds.  These
      --  values are used only when diffie-hellman-group-exchange-sha256 or
      --  diffie-hellman-group-exchange-sha1 is negotiated.  Invalid ranges
      --  fail closed during the KEX request encoding.
      Gex_Minimum_Bits   : Natural := 2_048;
      Gex_Preferred_Bits : Natural := 4_096;
      Gex_Maximum_Bits   : Natural := 8_192;

      --  Optional channel background reader.  Disabled by default so the
      --  Version transport can keep its simple caller-driven Read_Some loop,
      --  but available for clients that want channel-control packets drained
      --  asynchronously after Open_Exec.
      Enable_Background_Channel_Reader : Boolean := False;
   end record;

   function Open
     (Options : Session_Options; Item : out Session)
      return CryptoLib.Errors.Status;

   function Close (Item : in out Session) return CryptoLib.Errors.Status;

   function Rekey (Item : in out Session) return CryptoLib.Errors.Status;

   function Request_Remote_Forward
     (Item         : in out Session;
      Bind_Address : String;
      Bind_Port    : Natural;
      Bound_Port   : out Natural)
      return CryptoLib.Errors.Status;

   function Cancel_Remote_Forward
     (Item         : in out Session;
      Bind_Address : String;
      Bind_Port    : Natural)
      return CryptoLib.Errors.Status;

   function Last_Proxy_Command_Diagnostics
     (Item : Session) return Proxy_Command_Diagnostic;

private
   Max_Channel_Table_Slots : constant Natural := 64;

   type Channel_Id_Slot_Array is
     array (Positive range 1 .. Max_Channel_Table_Slots)
     of Interfaces.Unsigned_32;

   type Channel_Id_Used_Array is
     array (Positive range 1 .. Max_Channel_Table_Slots) of Boolean;

   type Session_State is (Closed, Opened);

   type Authentication_Method is
     (No_Authentication_Method,
      Agent_Authentication,
      Identity_File_Authentication,
      Password_Authentication,
      Keyboard_Interactive_Authentication,
      None_Authentication);

   type Session is limited record
      Current_State  : Session_State := Closed;
      Stored_Options : Session_Options;

      --  Phase 10 lifecycle flags.  These are intentionally private: the
      --  public contract remains Status-returning Open/Close, while later
      --  channel code can rely on this state to reject partially opened
      --  sessions.
      Transport_Connected            : Boolean := False;
      Identification_Complete        : Boolean := False;
      Kexinit_Exchanged              : Boolean := False;
      Algorithms_Negotiated          : Boolean := False;
      Kex_Complete                   : Boolean := False;
      Keys_Derived                   : Boolean := False;
      Newkeys_Sent                   : Boolean := False;
      Newkeys_Received               : Boolean := False;
      Encrypted_Outbound_Active      : Boolean := False;
      Encrypted_Inbound_Active       : Boolean := False;
      Host_Key_Signature_Verified    : Boolean := False;
      Known_Host_Trusted             : Boolean := False;
      Known_Host_Bypassed_Explicitly : Boolean := False;
      Userauth_Service_Accepted      : Boolean := False;
      User_Authenticated             : Boolean := False;
      Session_Open                   : Boolean := False;
      Session_Closed                 : Boolean := True;
      Failure_Status                 : CryptoLib.Errors.Status :=
        CryptoLib.Errors.Ok;
      Session_Dirty                  : Boolean := False;
      Last_Operation_Cancelled       : Boolean := False;
      Last_Proxy_Command_Diagnostic  : Proxy_Command_Diagnostic;

      Authenticated_User_Name    : Ada.Strings.Unbounded.Unbounded_String;
      Authentication_Method_Used : Authentication_Method :=
        No_Authentication_Method;

      Channel_Next_Local_Id  : Interfaces.Unsigned_32 := 0;
      Channel_Active_Count   : Natural := 0;
      Channel_Max_Open_Count : Natural := 32;
      Channel_Generation     : Interfaces.Unsigned_32 := 1;
      Channel_Id_Slots       : Channel_Id_Slot_Array := [others => 0];
      Channel_Id_Used        : Channel_Id_Used_Array := [others => False];

      Test_Channel_Open_Response : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Test_Channel_Exec_Response : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Test_Global_Response       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Test_Inbound_Forwarded_Open : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Test_Has_Open_Response     : Boolean := False;
      Test_Has_Exec_Response     : Boolean := False;
      Test_Has_Global_Response   : Boolean := False;
      Test_Has_Inbound_Forwarded_Open : Boolean := False;
      Test_Last_Channel_Open     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Test_Last_Exec_Request     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Test_Next_Channel_Stdout   : SSH_Lib.Protocol.Buffers.Packet_Buffer;

      --  Phase 19/30 live channel boundary state.  The public Channel API is
      --  session-less after Open_Exec, so session-owned open/exec traffic is
      --  emitted here, while Channel handles retain their own stream encoder
      --  state for later data/EOF/close packets.  The test support can enable
      --  this deterministic protected-packet boundary without public network
      --  access; real transport integration must use the same send/read hooks.
      Live_Channel_IO_Enabled     : Boolean := False;
      Live_Transcript_Address     : System.Address := System.Null_Address;
      Live_Transcript_Attached    : Boolean := False;
      Live_Session_Identifier     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Live_Rekey_Count            : Natural := 0;
      Live_Packets_Since_Rekey    : Interfaces.Unsigned_64 := 0;
      Live_Bytes_Since_Rekey      : Interfaces.Unsigned_64 := 0;
      Live_Rekey_Started          : Ada.Calendar.Time := Ada.Calendar.Clock;
      Live_Rekey_In_Progress      : Boolean := False;
      Live_Open_Protected_State   :
        SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Live_Last_Protected_Channel : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Live_Last_Plain_Channel     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Live_Pending_Window_Adjust_Known : Boolean := False;
      Live_Pending_Window_Adjust_Id    : Interfaces.Unsigned_32 := 0;
      Live_Pending_Window_Adjust_Bytes : Interfaces.Unsigned_32 := 0;

      --  Phase 19/43 userauth runtime boundary state.  This mirrors the
      --  protected channel boundary but is scoped to USERAUTH_REQUEST and
      --  USERAUTH_SUCCESS/FAILURE traffic before the session becomes public
      --  open.  It gives the production userauth driver a deterministic,
      --  packet-protected send/read surface without exposing authentication
      --  internals in the public API.
      Live_Userauth_IO_Enabled              : Boolean := False;
      Live_Userauth_Protected_State         :
        SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Live_Last_Protected_Userauth          :
        SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Live_Last_Plain_Userauth              :
        SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Live_Last_Protected_Userauth_Response :
        SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Live_Last_Plain_Userauth_Response     :
        SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Live_Last_Protected_Service           :
        SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Live_Last_Plain_Service               :
        SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Live_Last_Protected_Service_Response  :
        SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Live_Last_Plain_Service_Response      :
        SSH_Lib.Protocol.Buffers.Packet_Buffer;

      --  Deterministic ssh-agent transcript state for agent-backed publickey
      --  authentication.  These buffers keep the agent boundary auditable: an
      --  agent-authenticated open must have built an SSH_AGENTC_SIGN_REQUEST,
      --  parsed an SSH_AGENT_SIGN_RESPONSE, and only then emitted the SSH
      --  USERAUTH_REQUEST over the protected transport boundary.
      Live_Last_Agent_Sign_Request  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Live_Last_Agent_Sign_Response : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Test_Userauth_Response        : SSH_Lib.Protocol.Buffers.Packet_Buffer;

      Test_Write_Fails                 : Boolean := False;
      Test_Read_Open_Fails             : Boolean := False;
      Test_Read_Exec_Fails             : Boolean := False;
      Test_Open_Timeout                : Boolean := False;
      Test_Exec_Timeout                : Boolean := False;
      Test_Open_Cancelled              : Boolean := False;
      Test_Exec_Cancelled              : Boolean := False;
      Test_Partial_Channel_Write_Fails : Boolean := False;
      Test_Exec_Write_Timeout          : Boolean := False;
   end record;
end SSH_Lib.Sessions;
