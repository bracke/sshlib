with Ada.Unchecked_Conversion;
with Ada.Unchecked_Deallocation;
with System;
with CryptoLib.Errors;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Transport_Messages;

package body SSH_Lib.Sessions.Live_Attachment is
   use type SSH_Lib.Sessions.Live_Transcript.Driver_Access;
   use type System.Address;
   procedure Free is new Ada.Unchecked_Deallocation
     (SSH_Lib.Sessions.Live_Transcript.Driver,
      SSH_Lib.Sessions.Live_Transcript.Driver_Access);

   function Address_To_Transcript is new Ada.Unchecked_Conversion
     (System.Address, Transcript_Access);

   function Address_Of (Pointer : Transcript_Access) return System.Address is
   begin
      if Pointer = null then
         return System.Null_Address;
      end if;
      return Pointer.all'Address;
   exception
      when others =>
         return System.Null_Address;
   end Address_Of;

   function To_Pointer (Item : in out Session) return Transcript_Access is
   begin
      if not Item.Live_Transcript_Attached
        or else Item.Live_Transcript_Address = System.Null_Address
      then
         return null;
      end if;
      return Address_To_Transcript (Item.Live_Transcript_Address);
   exception
      when others =>
         return null;
   end To_Pointer;

   function Create return Transcript_Access is
      Pointer : constant Transcript_Access := new SSH_Lib.Sessions.Live_Transcript.Driver;
   begin
      SSH_Lib.Sessions.Live_Transcript.Reset (Pointer.all);
      return Pointer;
   exception
      when others =>
         return null;
   end Create;

   procedure Destroy (Pointer : in out Transcript_Access) is
   begin
      if Pointer /= null then
         SSH_Lib.Sessions.Live_Transcript.Close (Pointer.all);
         Free (Pointer);
      end if;
   exception
      when others =>
         Pointer := null;
   end Destroy;

   procedure Attach
     (Item    : in out Session;
      Pointer : in out Transcript_Access)
   is
   begin
      Close_Attached (Item);
      if Pointer = null then
         Item.Live_Transcript_Address := System.Null_Address;
         Item.Live_Transcript_Attached := False;
      else
         Item.Live_Transcript_Address := Address_Of (Pointer);
         Item.Live_Transcript_Attached := True;
         Pointer := null;
      end if;
   exception
      when others =>
         Item.Live_Transcript_Address := System.Null_Address;
         Item.Live_Transcript_Attached := False;
   end Attach;

   function Attached (Item : Session) return Boolean is
   begin
      return Item.Live_Transcript_Attached
        and then Item.Live_Transcript_Address /= System.Null_Address;
   exception
      when others =>
         return False;
   end Attached;

   function Transcript (Item : in out Session) return Transcript_Access is
   begin
      return To_Pointer (Item);
   end Transcript;

   procedure Detach_Without_Close (Item : in out Session) is
   begin
      Item.Live_Transcript_Address := System.Null_Address;
      Item.Live_Transcript_Attached := False;
   exception
      when others =>
         Item.Live_Transcript_Address := System.Null_Address;
         Item.Live_Transcript_Attached := False;
   end Detach_Without_Close;

   procedure Send_Disconnect_Quietly (Pointer : Transcript_Access) is
      SSH_DISCONNECT_BY_APPLICATION : constant Natural := 11;
      Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
   begin
      if Pointer = null then
         return;
      end if;

      if not SSH_Lib.Sessions.Live_Transcript.Is_Connected (Pointer.all) then
         return;
      end if;

      Payload := SSH_Lib.Protocol.Transport_Messages.Encode_Disconnect
        (SSH_DISCONNECT_BY_APPLICATION, "SSH_Lib session closed");
      if SSH_Lib.Protocol.Buffers.Is_Empty (Payload) then
         return;
      end if;

      declare
         Ignored_Status : constant CryptoLib.Errors.Status :=
           SSH_Lib.Sessions.Live_Transcript.Send_Protected_Packet
             (Pointer.all, SSH_Lib.Protocol.Buffers.To_Array (Payload));
      begin
         null;
      end;
   exception
      when others =>
         null;
   end Send_Disconnect_Quietly;

   procedure Close_Attached (Item : in out Session) is
      Pointer : Transcript_Access := To_Pointer (Item);
   begin
      Item.Live_Transcript_Address := System.Null_Address;
      Item.Live_Transcript_Attached := False;
      if Pointer /= null then
         Send_Disconnect_Quietly (Pointer);
         SSH_Lib.Sessions.Live_Transcript.Close (Pointer.all);
         Item.Last_Proxy_Command_Diagnostic :=
           SSH_Lib.Sessions.Live_Transcript.Last_Proxy_Command_Diagnostics
             (Pointer.all);
         Destroy (Pointer);
      end if;
   exception
      when others =>
         Item.Live_Transcript_Address := System.Null_Address;
         Item.Live_Transcript_Attached := False;
   end Close_Attached;
end SSH_Lib.Sessions.Live_Attachment;
