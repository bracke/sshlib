with SSH_Lib.Agent.Protocol;
with SSH_Lib.Agent.Transport;

package body SSH_Lib.Agent.Client is
   use Ada.Streams;
   use CryptoLib.Errors;

   function Request_Identities
     (Socket_Path : String;
      Identities  : out SSH_Lib.Agent.Identity_List)
      return Status
   is
      Connection   : SSH_Lib.Agent.Transport.Agent_Connection;
      Reply_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : Status;
   begin
      SSH_Lib.Agent.Clear (Identities);
      Status_Value := SSH_Lib.Agent.Transport.Connect (Socket_Path, Connection);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      declare
         Request : constant Stream_Element_Array :=
           SSH_Lib.Agent.Protocol.Encode_Request_Identities;
      begin
         Status_Value := SSH_Lib.Agent.Transport.Send_Message (Connection, Request);
      end;
      if Status_Value = Ok then
         Status_Value := SSH_Lib.Agent.Transport.Receive_Message (Connection, Reply_Buffer);
      end if;
      if Status_Value = Ok then
         Status_Value := SSH_Lib.Agent.Protocol.Parse_Identities_Answer
           (SSH_Lib.Protocol.Buffers.To_Array (Reply_Buffer), Identities);
      end if;
      SSH_Lib.Protocol.Buffers.Clear (Reply_Buffer);
      declare
         Close_Status : constant Status := SSH_Lib.Agent.Transport.Close (Connection);
      begin
         if Status_Value = Ok and then Close_Status /= Ok then
            return Close_Status;
         end if;
      end;
      return Status_Value;
   exception
      when others =>
         SSH_Lib.Agent.Clear (Identities);
         SSH_Lib.Protocol.Buffers.Clear (Reply_Buffer);
         return Internal_Error;
   end Request_Identities;

   function Request_Identities
     (Socket_Path : String;
      Timeout_MS  : Natural;
      Identities  : out SSH_Lib.Agent.Identity_List)
      return Status
   is
      Connection   : SSH_Lib.Agent.Transport.Agent_Connection;
      Reply_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : Status;
   begin
      SSH_Lib.Agent.Clear (Identities);
      if Timeout_MS = 0 then
         return Timeout;
      end if;
      Status_Value := SSH_Lib.Agent.Transport.Connect (Socket_Path, Timeout_MS, Connection);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      declare
         Request : constant Stream_Element_Array :=
           SSH_Lib.Agent.Protocol.Encode_Request_Identities;
      begin
         Status_Value := SSH_Lib.Agent.Transport.Send_Message (Connection, Request, Timeout_MS);
      end;
      if Status_Value = Ok then
         Status_Value := SSH_Lib.Agent.Transport.Receive_Message
           (Connection, Reply_Buffer, Timeout_MS);
      end if;
      if Status_Value = Ok then
         Status_Value := SSH_Lib.Agent.Protocol.Parse_Identities_Answer
           (SSH_Lib.Protocol.Buffers.To_Array (Reply_Buffer), Identities);
      end if;
      SSH_Lib.Protocol.Buffers.Clear (Reply_Buffer);
      declare
         Close_Status : constant Status := SSH_Lib.Agent.Transport.Close (Connection);
      begin
         if Status_Value = Ok and then Close_Status /= Ok then
            return Close_Status;
         end if;
      end;
      return Status_Value;
   exception
      when others =>
         SSH_Lib.Agent.Clear (Identities);
         SSH_Lib.Protocol.Buffers.Clear (Reply_Buffer);
         return Internal_Error;
   end Request_Identities;

   function Request_Signature
     (Socket_Path           : String;
      Key_Blob              : Stream_Element_Array;
      Data_To_Sign          : Stream_Element_Array;
      Public_Key_Algorithm  : String;
      Signature_Blob        : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return Status
   is
   begin
      return Request_Signature
        (Socket_Path, 30_000, Key_Blob, Data_To_Sign,
         Public_Key_Algorithm, Signature_Blob);
   end Request_Signature;

   function Request_Signature
     (Socket_Path           : String;
      Timeout_MS            : Natural;
      Key_Blob              : Stream_Element_Array;
      Data_To_Sign          : Stream_Element_Array;
      Public_Key_Algorithm  : String;
      Signature_Blob        : out SSH_Lib.Protocol.Buffers.Packet_Buffer)
      return Status
   is
      Connection     : SSH_Lib.Agent.Transport.Agent_Connection;
      Request_Buffer : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Buffer   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value   : Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Signature_Blob);
      if Timeout_MS = 0 then
         return Timeout;
      end if;

      Request_Buffer := SSH_Lib.Agent.Protocol.Encode_Sign_Request
        (Key_Blob, Data_To_Sign, Public_Key_Algorithm);
      if SSH_Lib.Protocol.Buffers.Is_Empty (Request_Buffer) then
         return Authentication_Failed;
      end if;

      Status_Value := SSH_Lib.Agent.Transport.Connect (Socket_Path, Timeout_MS, Connection);
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Buffers.Clear (Request_Buffer);
         return Status_Value;
      end if;

      Status_Value := SSH_Lib.Agent.Transport.Send_Message
        (Connection, SSH_Lib.Protocol.Buffers.To_Array (Request_Buffer), Timeout_MS);
      if Status_Value = Ok then
         Status_Value := SSH_Lib.Agent.Transport.Receive_Message
           (Connection, Reply_Buffer, Timeout_MS);
      end if;
      if Status_Value = Ok then
         Status_Value := SSH_Lib.Agent.Protocol.Parse_Sign_Response
           (SSH_Lib.Protocol.Buffers.To_Array (Reply_Buffer), Signature_Blob);
      end if;
      if Status_Value = Ok then
         Status_Value := SSH_Lib.Agent.Protocol.Validate_Signature_Blob_For_Algorithm
           (Signature_Blob, Public_Key_Algorithm);
         if Status_Value /= Ok then
            SSH_Lib.Protocol.Buffers.Clear (Signature_Blob);
         end if;
      end if;

      SSH_Lib.Protocol.Buffers.Clear (Request_Buffer);
      SSH_Lib.Protocol.Buffers.Clear (Reply_Buffer);
      declare
         Close_Status : constant Status := SSH_Lib.Agent.Transport.Close (Connection);
      begin
         if Status_Value = Ok and then Close_Status /= Ok then
            return Close_Status;
         end if;
      end;
      return Status_Value;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Request_Buffer);
         SSH_Lib.Protocol.Buffers.Clear (Reply_Buffer);
         SSH_Lib.Protocol.Buffers.Clear (Signature_Blob);
         return Internal_Error;
   end Request_Signature;
end SSH_Lib.Agent.Client;
