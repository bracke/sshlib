with Ada.Calendar;
with Ada.Characters.Handling;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Strings.Unbounded;
with Interfaces;
with SSH_Lib.Keys;
with SSH_Lib.Known_Hosts;
with CryptoLib.Curve25519;
with CryptoLib.Diffie_Hellman;
with SSH_Lib.ECDSA;
with CryptoLib.Hashes;
with CryptoLib.Hybrid_PQ_Kex;
with CryptoLib.SNTRUP761;
with CryptoLib.MLKEM768;
with CryptoLib.Random;
with SSH_Lib.Protocol.Encrypted_State;
with SSH_Lib.Protocol.Exchange_Hash;
with SSH_Lib.Protocol.Host_Keys;
with SSH_Lib.Protocol.Kex;
with SSH_Lib.Protocol.Kexdh;
with SSH_Lib.Protocol.Kexinit;
with SSH_Lib.Protocol.Channels;
with SSH_Lib.Algorithms;
with SSH_Lib.Protocol.Session_Keys;
with SSH_Lib.Protocol.Transport_Messages;
with SSH_Lib.Sessions.Live_Transcript;
with SSH_Lib.Sessions.Live_Attachment;
with SSH_Lib.Sessions.Live_Userauth;
with SSH_Lib.Sessions.Channel_Table;
with SSH_Lib.Sessions.Open_Guards;

package body SSH_Lib.Sessions.Live_Transport is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;
   use type Ada.Calendar.Time;
   use type Interfaces.Unsigned_32;
   use type SSH_Lib.Known_Hosts.Verification_Result;
   use type CryptoLib.Diffie_Hellman.Supported_Gex_Group;
   use type SSH_Lib.Sessions.Live_Transcript.Driver_Access;
   use type Interfaces.Unsigned_64;

   function Digest_To_Array
     (Digest_Item : CryptoLib.Hashes.SHA1_Digest)
      return Stream_Element_Array
   is
      Result : Stream_Element_Array (1 .. 20);
   begin
      for Index_Value in Digest_Item'Range loop
         Result (Stream_Element_Offset (Index_Value)) :=
           Digest_Item (Index_Value);
      end loop;
      return Result;
   end Digest_To_Array;

   function Digest_To_Array
     (Digest_Item : CryptoLib.Hashes.SHA256_Digest)
      return Stream_Element_Array
   is
      Result : Stream_Element_Array (1 .. 32);
   begin
      for Index_Value in Digest_Item'Range loop
         Result (Stream_Element_Offset (Index_Value)) :=
           Digest_Item (Index_Value);
      end loop;
      return Result;
   end Digest_To_Array;

   function Digest_To_Array
     (Digest_Item : CryptoLib.Hashes.SHA384_Digest)
      return Stream_Element_Array
   is
      Result : Stream_Element_Array (1 .. 48);
   begin
      for Index_Value in Digest_Item'Range loop
         Result (Stream_Element_Offset (Index_Value)) :=
           Digest_Item (Index_Value);
      end loop;
      return Result;
   end Digest_To_Array;

   function Digest_To_Array
     (Digest_Item : CryptoLib.Hashes.SHA512_Digest)
      return Stream_Element_Array
   is
      Result : Stream_Element_Array (1 .. 64);
   begin
      for Index_Value in Digest_Item'Range loop
         Result (Stream_Element_Offset (Index_Value)) :=
           Digest_Item (Index_Value);
      end loop;
      return Result;
   end Digest_To_Array;

   function Buffer_To_Digest
     (Buffer_Item : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Result_Item : out CryptoLib.Hashes.SHA256_Digest) return Status
   is
      Data : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Buffer_Item);
   begin
      if Data'Length /= 32 then
         Result_Item := [others => 0];
         return Handshake_Failed;
      end if;

      for Index_Value in Result_Item'Range loop
         Result_Item (Index_Value) :=
           Data (Data'First + Stream_Element_Offset (Index_Value - 1));
      end loop;
      return Ok;
   exception
      when others =>
         Result_Item := [others => 0];
         return Internal_Error;
   end Buffer_To_Digest;

   function Cipher_Key_Length (Algorithm_Name : String) return Natural is
   begin
      if Algorithm_Name = "chacha20-poly1305@openssh.com" then
         return 64;
      elsif Algorithm_Name = "aes128-gcm@openssh.com" then
         return 16;
      elsif Algorithm_Name = "aes256-gcm@openssh.com" then
         return 32;
      elsif Algorithm_Name = "aes128-ctr" then
         return 16;
      elsif Algorithm_Name = "aes192-ctr" then
         return 24;
      elsif Algorithm_Name = "aes256-ctr" then
         return 32;
      elsif Algorithm_Name = "aes128-cbc" then
         return 16;
      elsif Algorithm_Name = "aes192-cbc" then
         return 24;
      elsif Algorithm_Name = "aes256-cbc" then
         return 32;
      elsif Algorithm_Name = "3des-cbc" then
         return 24;
      end if;
      return 0;
   end Cipher_Key_Length;

   function Mac_Key_Length (Algorithm_Name : String) return Natural is
   begin
      if Algorithm_Name = "umac-64@openssh.com"
        or else Algorithm_Name = "umac-128@openssh.com"
        or else Algorithm_Name = "umac-64-etm@openssh.com"
        or else Algorithm_Name = "umac-128-etm@openssh.com"
      then
         return 16;
      elsif Algorithm_Name = "hmac-sha1"
        or else Algorithm_Name = "hmac-sha1-etm@openssh.com"
        or else Algorithm_Name = "hmac-sha1-96"
        or else Algorithm_Name = "hmac-sha1-96-etm@openssh.com"
      then
         return 20;
      elsif Algorithm_Name = "hmac-md5"
        or else Algorithm_Name = "hmac-md5-etm@openssh.com"
        or else Algorithm_Name = "hmac-md5-96"
        or else Algorithm_Name = "hmac-md5-96-etm@openssh.com"
      then
         return 16;
      elsif Algorithm_Name = "hmac-sha2-256"
        or else Algorithm_Name = "hmac-sha2-256-etm@openssh.com"
      then
         return 32;
      elsif Algorithm_Name = "hmac-sha2-512"
        or else Algorithm_Name = "hmac-sha2-512-etm@openssh.com"
      then
         return 64;
      end if;
      return 0;
   end Mac_Key_Length;

   procedure Add_Rekey_Counters
     (Item            : in out Session;
      Packet_Count    : Interfaces.Unsigned_64;
      Wire_Byte_Count : Natural)
   is
      Byte_Increment : constant Interfaces.Unsigned_64 :=
        Interfaces.Unsigned_64 (Wire_Byte_Count);
   begin
      if Interfaces.Unsigned_64'Last - Item.Live_Packets_Since_Rekey
        < Packet_Count
      then
         Item.Live_Packets_Since_Rekey := Interfaces.Unsigned_64'Last;
      else
         Item.Live_Packets_Since_Rekey :=
           Item.Live_Packets_Since_Rekey + Packet_Count;
      end if;

      if Interfaces.Unsigned_64'Last - Item.Live_Bytes_Since_Rekey
        < Byte_Increment
      then
         Item.Live_Bytes_Since_Rekey := Interfaces.Unsigned_64'Last;
      else
         Item.Live_Bytes_Since_Rekey :=
           Item.Live_Bytes_Since_Rekey + Byte_Increment;
      end if;
   exception
      when others =>
         Item.Live_Packets_Since_Rekey := Interfaces.Unsigned_64'Last;
         Item.Live_Bytes_Since_Rekey := Interfaces.Unsigned_64'Last;
   end Add_Rekey_Counters;

   procedure Note_Protected_Outbound
     (Item : in out Session; Wire_Byte_Count : Natural) is
   begin
      Add_Rekey_Counters (Item, 1, Wire_Byte_Count);
   end Note_Protected_Outbound;

   procedure Note_Protected_Inbound
     (Item : in out Session; Wire_Byte_Count : Natural) is
   begin
      Add_Rekey_Counters (Item, 1, Wire_Byte_Count);
   end Note_Protected_Inbound;

   function Time_Based_Rekey_Needed (Item : Session) return Boolean is
      Seconds_Limit : constant Natural :=
        Item.Stored_Options.Rekey_After_Seconds;
      Elapsed_Time  : Duration;
   begin
      if Seconds_Limit = 0 then
         return False;
      end if;

      Elapsed_Time := Ada.Calendar.Clock - Item.Live_Rekey_Started;
      return Elapsed_Time >= Duration (Seconds_Limit);
   exception
      when others =>
         --  Clock anomalies must never force an unsafe or exception-raising
         --  channel path.  Packet and byte limits remain available.
         return False;
   end Time_Based_Rekey_Needed;

   function Automatic_Rekey_Needed (Item : Session) return Boolean is
      Packet_Limit : constant Interfaces.Unsigned_64 :=
        Interfaces.Unsigned_64 (Item.Stored_Options.Rekey_After_Packets);
      Byte_Limit   : constant Interfaces.Unsigned_64 :=
        Item.Stored_Options.Rekey_After_Bytes;
   begin
      if not Item.Stored_Options.Automatic_Rekey
        or else Item.Live_Rekey_In_Progress
        or else Item.Session_Dirty
        or else Item.Session_Closed
        or else not Item.User_Authenticated
      then
         return False;
      end if;

      return
        (Packet_Limit > 0
         and then Item.Live_Packets_Since_Rekey >= Packet_Limit)
        or else
          (Byte_Limit > 0 and then Item.Live_Bytes_Since_Rekey >= Byte_Limit)
        or else Time_Based_Rekey_Needed (Item);
   exception
      when others =>
         return False;
   end Automatic_Rekey_Needed;

   function Check_Automatic_Rekey (Item : in out Session) return Status is
      Status_Value : Status;
   begin
      if not Automatic_Rekey_Needed (Item) then
         return Ok;
      end if;

      Item.Live_Rekey_In_Progress := True;
      Status_Value := Rekey (Item);
      Item.Live_Rekey_In_Progress := False;

      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
      end if;

      return Status_Value;
   exception
      when others =>
         Item.Live_Rekey_In_Progress := False;
         Item.Session_Dirty := True;
         Item.Failure_Status := Internal_Error;
         return Internal_Error;
   end Check_Automatic_Rekey;

   function Buffer_To_SHA512_Digest
     (Buffer_Item : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Result_Item : out CryptoLib.Hashes.SHA512_Digest) return Status
   is
      Data : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Buffer_Item);
   begin
      if Data'Length /= 64 then
         Result_Item := [others => 0];
         return Handshake_Failed;
      end if;

      for Index_Value in Result_Item'Range loop
         Result_Item (Index_Value) :=
           Data (Stream_Element_Offset (Index_Value));
      end loop;
      return Ok;
   exception
      when others =>
         Result_Item := [others => 0];
         return Internal_Error;
   end Buffer_To_SHA512_Digest;

   function Buffer_To_SHA384_Digest
     (Buffer_Item : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Result_Item : out CryptoLib.Hashes.SHA384_Digest) return Status
   is
      Data : constant Stream_Element_Array :=
        SSH_Lib.Protocol.Buffers.To_Array (Buffer_Item);
   begin
      if Data'Length /= 48 then
         Result_Item := [others => 0];
         return Handshake_Failed;
      end if;

      for Index_Value in Result_Item'Range loop
         Result_Item (Index_Value) :=
           Data (Stream_Element_Offset (Index_Value));
      end loop;
      return Ok;
   exception
      when others =>
         Result_Item := [others => 0];
         return Internal_Error;
   end Buffer_To_SHA384_Digest;

   function Maximum_Of
     (Left_Value : Natural; Right_Value : Natural) return Natural is
   begin
      if Left_Value > Right_Value then
         return Left_Value;
      end if;
      return Right_Value;
   end Maximum_Of;

   function First_Name (List_Text : String) return String is
   begin
      if List_Text'Length = 0 then
         return "";
      end if;

      for Index_Value in List_Text'Range loop
         if List_Text (Index_Value) = ',' then
            if Index_Value = List_Text'First then
               return "";
            else
               return List_Text (List_Text'First .. Index_Value - 1);
            end if;
         end if;
      end loop;

      return List_Text;
   exception
      when others =>
         return "";
   end First_Name;

   function Read_Non_Ignorable_Key_Exchange_Packet
     (Transcript : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Payload    : out SSH_Lib.Protocol.Buffers.Packet_Buffer) return Status
   is
      Status_Value          : Status;
      Max_Ignorable_Packets : constant Natural := 64;
   begin
      for Attempt in 0 .. Max_Ignorable_Packets loop
         Status_Value :=
           SSH_Lib.Sessions.Live_Transcript.Read_Key_Exchange_Packet
             (Transcript, Payload);
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         declare
            Data : constant Stream_Element_Array :=
              SSH_Lib.Protocol.Buffers.To_Array (Payload);
            Kind :
              constant SSH_Lib
                         .Protocol
                         .Transport_Messages
                         .Transport_Message_Kind :=
                SSH_Lib.Protocol.Transport_Messages.Classify (Data);
         begin
            if Data'Length = 0 then
               SSH_Lib.Protocol.Buffers.Clear (Payload);
               return Handshake_Failed;
            end if;

            case Kind is
               when SSH_Lib.Protocol.Transport_Messages.Transport_Disconnect =>
                  SSH_Lib.Protocol.Buffers.Clear (Payload);
                  return Connection_Failed;

               when SSH_Lib.Protocol.Transport_Messages.Transport_Ignore
                  | SSH_Lib.Protocol.Transport_Messages.Transport_Unimplemented
                  | SSH_Lib.Protocol.Transport_Messages.Transport_Debug
                  | SSH_Lib.Protocol.Transport_Messages.Transport_Ext_Info   =>
                  SSH_Lib.Protocol.Buffers.Clear (Payload);
                  --  Terrapin strict kex forbids extraneous transport messages
                  --  during key exchange; terminate rather than skip them.
                  if SSH_Lib.Sessions.Live_Transcript.Is_Strict_Kex (Transcript)
                  then
                     return Handshake_Failed;
                  end if;
                  if Attempt = Max_Ignorable_Packets then
                     return Timeout;
                  end if;

               when SSH_Lib.Protocol.Transport_Messages.Transport_Other      =>
                  return Ok;
            end case;
         end;
      end loop;

      SSH_Lib.Protocol.Buffers.Clear (Payload);
      return Timeout;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Internal_Error;
   end Read_Non_Ignorable_Key_Exchange_Packet;

   function Server_First_Kex_Guess_Matches
     (Server_Item     : SSH_Lib.Protocol.Kexinit.Kexinit_Message;
      Negotiated_Item : SSH_Lib.Protocol.Kex.Negotiated_Algorithms)
      return Boolean
   is
      Server_Kex_Guess      : constant String :=
        First_Name (To_String (Server_Item.Kex_Algorithms));
      Server_Host_Key_Guess : constant String :=
        First_Name (To_String (Server_Item.Server_Host_Key_Algorithms));
   begin
      --  RFC 4253 first_kex_packet_follows is a server-side optimistic
      --  guess.  If the server guessed a different KEX or host-key algorithm
      --  than the negotiated pair, the next packet is not part of the actual
      --  key exchange and must be ignored before reading the real KEX packet.
      return
        Server_Kex_Guess = To_String (Negotiated_Item.Key_Exchange)
        and then
          Server_Host_Key_Guess = To_String (Negotiated_Item.Server_Host_Key);
   exception
      when others =>
         return False;
   end Server_First_Kex_Guess_Matches;

   function Discard_Wrong_First_Kex_Packet
     (Transcript      : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Server_Item     : SSH_Lib.Protocol.Kexinit.Kexinit_Message;
      Negotiated_Item : SSH_Lib.Protocol.Kex.Negotiated_Algorithms)
      return Status
   is
      Discarded_Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value      : Status;
   begin
      if not Server_Item.First_Kex_Packet_Follows
        or else Server_First_Kex_Guess_Matches (Server_Item, Negotiated_Item)
      then
         return Ok;
      end if;

      --  The optimistic guessed packet is the next non-ignorable key
      --  exchange packet.  SSH_MSG_IGNORE/DEBUG/UNIMPLEMENTED may appear
      --  around key exchange on real transports; do not let such noise be
      --  consumed as the guessed KEX packet and leave the wrong optimistic
      --  packet queued for the negotiated exchange parser.
      Status_Value :=
        Read_Non_Ignorable_Key_Exchange_Packet (Transcript, Discarded_Payload);
      SSH_Lib.Protocol.Buffers.Clear (Discarded_Payload);
      return Status_Value;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Discarded_Payload);
         return Internal_Error;
   end Discard_Wrong_First_Kex_Packet;

   function Apply_Configured_Kexinit_Preferences
     (Options : Session_Options;
      Item    : in out SSH_Lib.Protocol.Kexinit.Kexinit_Message;
      Payload : out SSH_Lib.Protocol.Buffers.Packet_Buffer) return Status
   is
      Status_Value : Status;

      procedure Maybe_Set
        (Target : in out Unbounded_String; Value : Unbounded_String) is
      begin
         if Length (Value) > 0 then
            Target := Value;
         end if;
      end Maybe_Set;
   begin
      Maybe_Set (Item.Kex_Algorithms, Options.Kex_Algorithms);
      Maybe_Set (Item.Server_Host_Key_Algorithms, Options.Host_Key_Algorithms);
      Maybe_Set
        (Item.Encryption_Algorithms_Client_To_Server,
         Options.Cipher_Algorithms);
      Maybe_Set
        (Item.Encryption_Algorithms_Server_To_Client,
         Options.Cipher_Algorithms);
      Maybe_Set (Item.Mac_Algorithms_Client_To_Server, Options.Mac_Algorithms);
      Maybe_Set (Item.Mac_Algorithms_Server_To_Client, Options.Mac_Algorithms);
      Maybe_Set
        (Item.Compression_Algorithms_Client_To_Server,
         Options.Compression_Algorithms);
      Maybe_Set
        (Item.Compression_Algorithms_Server_To_Client,
         Options.Compression_Algorithms);

      Status_Value := SSH_Lib.Protocol.Kexinit.Encode (Item, Payload);
      if Status_Value = Ok then
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Set
             (Item.Raw_Payload, SSH_Lib.Protocol.Buffers.To_Array (Payload));
      end if;
      return Status_Value;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Payload);
         return Internal_Error;
   end Apply_Configured_Kexinit_Preferences;

   function Exchange_Kexinit
     (Transcript      : in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Item            : in out Session;
      Client_Payload  : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Payload  : out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Negotiated_Item : out SSH_Lib.Protocol.Kex.Negotiated_Algorithms)
      return Status
   is
      Source_Item  : CryptoLib.Random.Random_Source;
      Client_Item  : SSH_Lib.Protocol.Kexinit.Kexinit_Message;
      Server_Item  : SSH_Lib.Protocol.Kexinit.Kexinit_Message;
      Status_Value : Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Client_Payload);
      SSH_Lib.Protocol.Buffers.Clear (Server_Payload);
      SSH_Lib.Protocol.Kex.Clear (Negotiated_Item);
      CryptoLib.Random.Initialize_Production (Source_Item);

      Status_Value :=
        SSH_Lib.Protocol.Kexinit.Construct_Client
          (Source_Item, Client_Item, Client_Payload);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Apply_Configured_Kexinit_Preferences
          (Item.Stored_Options, Client_Item, Client_Payload);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Key_Exchange_Packet
          (Transcript, SSH_Lib.Protocol.Buffers.To_Array (Client_Payload));
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Read_Non_Ignorable_Key_Exchange_Packet (Transcript, Server_Payload);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Kexinit.Parse
          (SSH_Lib.Protocol.Buffers.To_Array (Server_Payload), Server_Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Item.Kexinit_Exchanged := True;

      --  Terrapin (CVE-2023-48795): enable strict kex only if BOTH peers
      --  advertised their markers in this (initial) KEXINIT -- otherwise the
      --  peer will not reset its sequence numbers and the two sides desync.
      --  Set-once; the exchange hash signature protects the markers from being
      --  stripped by a MITM.
      if SSH_Lib.Algorithms.Contains_Name
           (Ada.Strings.Unbounded.To_String (Client_Item.Kex_Algorithms),
            "kex-strict-c-v00@openssh.com")
        and then SSH_Lib.Algorithms.Contains_Name
           (Ada.Strings.Unbounded.To_String (Server_Item.Kex_Algorithms),
            "kex-strict-s-v00@openssh.com")
      then
         SSH_Lib.Sessions.Live_Transcript.Set_Strict_Kex (Transcript);
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Kex.Negotiate
          (Client_Item, Server_Item, Negotiated_Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Discard_Wrong_First_Kex_Packet
          (Transcript, Server_Item, Negotiated_Item);
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Kex.Clear (Negotiated_Item);
         return Status_Value;
      end if;

      Item.Algorithms_Negotiated := True;
      return Ok;
   exception
      when others =>
         SSH_Lib.Protocol.Buffers.Clear (Client_Payload);
         SSH_Lib.Protocol.Buffers.Clear (Server_Payload);
         SSH_Lib.Protocol.Kex.Clear (Negotiated_Item);
         return Internal_Error;
   end Exchange_Kexinit;

   function File_Has_OpenSSH_KRL_Magic (Path_Text : String) return Boolean is
      File_Item : Ada.Streams.Stream_IO.File_Type;
      Header    : Ada.Streams.Stream_Element_Array (1 .. 7);
      Last      : Ada.Streams.Stream_Element_Offset;
      Magic     : constant Ada.Streams.Stream_Element_Array :=
        [Ada.Streams.Stream_Element (Character'Pos ('S')),
         Ada.Streams.Stream_Element (Character'Pos ('S')),
         Ada.Streams.Stream_Element (Character'Pos ('H')),
         Ada.Streams.Stream_Element (Character'Pos ('K')),
         Ada.Streams.Stream_Element (Character'Pos ('R')),
         Ada.Streams.Stream_Element (Character'Pos ('L')),
         Ada.Streams.Stream_Element (10)];
   begin
      if Path_Text'Length = 0 then
         return False;
      end if;

      Ada.Streams.Stream_IO.Open
        (File_Item, Ada.Streams.Stream_IO.In_File, Path_Text);
      Ada.Streams.Stream_IO.Read (File_Item, Header, Last);
      Ada.Streams.Stream_IO.Close (File_Item);
      return Last = Header'Last and then Header = Magic;
   exception
      when others =>
         if Ada.Streams.Stream_IO.Is_Open (File_Item) then
            Ada.Streams.Stream_IO.Close (File_Item);
         end if;
         return False;
   end File_Has_OpenSSH_KRL_Magic;

   function Verify_Known_Host_Path_List
     (Path_List : String;
      Host      : String;
      Port      : Natural;
      Key       : SSH_Lib.Known_Hosts.Host_Key)
      return SSH_Lib.Known_Hosts.Verification_Result
   is
      Start_Index : Positive;
      Stop_Index  : Natural;
      Result      : SSH_Lib.Known_Hosts.Verification_Result;
   begin
      if Path_List'Length = 0 then
         return SSH_Lib.Known_Hosts.Verify (Path_List, Host, Port, Key);
      end if;

      Start_Index := Path_List'First;
      loop
         Stop_Index := Start_Index;
         while Stop_Index <= Path_List'Last
           and then Path_List (Stop_Index) /= ','
         loop
            Stop_Index := Stop_Index + 1;
         end loop;

         if Stop_Index = Start_Index then
            return SSH_Lib.Known_Hosts.Invalid_Record;
         end if;

         Result :=
           SSH_Lib.Known_Hosts.Verify
             (Path_List (Start_Index .. Stop_Index - 1), Host, Port, Key);
         if Result /= SSH_Lib.Known_Hosts.Unknown then
            return Result;
         end if;

         exit when Stop_Index > Path_List'Last;
         Start_Index := Stop_Index + 1;
      end loop;

      return SSH_Lib.Known_Hosts.Unknown;
   exception
      when others =>
         return SSH_Lib.Known_Hosts.Invalid_Record;
   end Verify_Known_Host_Path_List;

   function Path_List_Has_OpenSSH_KRL_Magic (Path_List : String) return Boolean
   is
      Start_Index : Positive;
      Stop_Index  : Natural;
   begin
      if Path_List'Length = 0 then
         return False;
      end if;

      Start_Index := Path_List'First;
      loop
         Stop_Index := Start_Index;
         while Stop_Index <= Path_List'Last
           and then Path_List (Stop_Index) /= ','
         loop
            Stop_Index := Stop_Index + 1;
         end loop;

         if Stop_Index = Start_Index then
            return True;
         end if;

         if File_Has_OpenSSH_KRL_Magic
              (Path_List (Start_Index .. Stop_Index - 1))
         then
            return True;
         end if;

         exit when Stop_Index > Path_List'Last;
         Start_Index := Stop_Index + 1;
      end loop;

      return False;
   exception
      when others =>
         return True;
   end Path_List_Has_OpenSSH_KRL_Magic;

   function Verify_Presented_Host_Key
     (Options              : Session_Options;
      Negotiated_Algorithm : String;
      Host_Key_Blob        : Ada.Streams.Stream_Element_Array;
      Item                 : in out Session) return Status
   is
      function Is_Localhost_Name (Host_Text : String) return Boolean is
         Lower_Host : constant String :=
           Ada.Characters.Handling.To_Lower (Host_Text);
      begin
         return Lower_Host = "localhost"
           or else Lower_Host = "localhost.localdomain"
           or else Lower_Host = "::1"
           or else Lower_Host = "0:0:0:0:0:0:0:1"
           or else Lower_Host = "0000:0000:0000:0000:0000:0000:0000:0001"
           or else
             (Lower_Host'Length >= 4
              and then Lower_Host (Lower_Host'First .. Lower_Host'First + 3)
                       = "127.");
      exception
         when others =>
            return False;
      end Is_Localhost_Name;

      Parsed_Key                 : SSH_Lib.Keys.Public_Key;
      Presented_Key              : SSH_Lib.Known_Hosts.Host_Key;
      Verification               : SSH_Lib.Known_Hosts.Verification_Result;
      Known_Hosts_Path           : constant String :=
        (if To_String (Options.User_Known_Hosts_File)'Length > 0
         then To_String (Options.User_Known_Hosts_File)
         elsif To_String (Options.Known_Hosts_File)'Length = 0
         then To_String (SSH_Lib.Known_Hosts.Default_File)
         else To_String (Options.Known_Hosts_File));
      Global_Known_Hosts_Path    : constant String :=
        To_String (Options.Global_Known_Hosts_File);
      Certificate_Authority_Path : constant String :=
        To_String (Options.Certificate_Authority_File);
      Revoked_Path               : constant String :=
        To_String (Options.Revoked_Host_Keys_File);
      Verification_Host          : constant String :=
        (if To_String (Options.Host_Key_Alias)'Length > 0
         then To_String (Options.Host_Key_Alias)
         else To_String (Options.Host));
      Status_Value               : Status;
   begin
      if not Options.Verify_Known_Host then
         Item.Known_Host_Trusted := False;
         Item.Known_Host_Bypassed_Explicitly := True;
         return Ok;
      end if;

      if Options.No_Host_Authentication_For_Localhost
        and then To_String (Options.Host_Key_Alias)'Length = 0
        and then Is_Localhost_Name (To_String (Options.Host))
      then
         Item.Known_Host_Trusted := False;
         Item.Known_Host_Bypassed_Explicitly := True;
         return Ok;
      end if;

      if not Options.Strict_Host_Key then
         Item.Known_Host_Trusted := False;
         Item.Known_Host_Bypassed_Explicitly := False;
         return Host_Key_Unknown;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Parse
          (Host_Key_Blob, Negotiated_Algorithm, Parsed_Key);
      if Status_Value /= Ok then
         Item.Known_Host_Trusted := False;
         Item.Known_Host_Bypassed_Explicitly := False;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Known_Hosts.From_Public_Key (Parsed_Key, Presented_Key);
      if Status_Value /= Ok then
         Item.Known_Host_Trusted := False;
         Item.Known_Host_Bypassed_Explicitly := False;
         return Status_Value;
      end if;

      declare
         DNS_Mode : constant String :=
           Ada.Characters.Handling.To_Lower
             (To_String (Options.Verify_Host_Key_DNS));
      begin
         if DNS_Mode = "yes" or else DNS_Mode = "ask" then
            Item.Known_Host_Trusted := False;
            Item.Known_Host_Bypassed_Explicitly := False;
            return Unsupported_Feature;
         end if;
      end;

      if Revoked_Path'Length > 0 then
         if Path_List_Has_OpenSSH_KRL_Magic (Revoked_Path) then
            --  OpenSSH KRL is recognized as an explicit revocation policy
            --  source.  Full KRL section parsing is intentionally not guessed;
            --  fail closed instead of ignoring a configured revocation file.
            Item.Known_Host_Trusted := False;
            Item.Known_Host_Bypassed_Explicitly := False;
            return Host_Key_Mismatch;
         end if;

         Verification :=
           Verify_Known_Host_Path_List
             (Revoked_Path, Verification_Host, Options.Port, Presented_Key);
         if Verification = SSH_Lib.Known_Hosts.Trusted
           or else Verification = SSH_Lib.Known_Hosts.Mismatch
         then
            Item.Known_Host_Trusted := False;
            Item.Known_Host_Bypassed_Explicitly := False;
            return Host_Key_Mismatch;
         elsif Verification = SSH_Lib.Known_Hosts.Invalid_Record
           or else Verification = SSH_Lib.Known_Hosts.Unsupported_Entry
         then
            Item.Known_Host_Trusted := False;
            Item.Known_Host_Bypassed_Explicitly := False;
            return Host_Key_Mismatch;
         end if;
      end if;

      Verification :=
        Verify_Known_Host_Path_List
          (Known_Hosts_Path, Verification_Host, Options.Port, Presented_Key);

      if Verification = SSH_Lib.Known_Hosts.Unknown
        and then Global_Known_Hosts_Path'Length > 0
      then
         Verification :=
           Verify_Known_Host_Path_List
             (Global_Known_Hosts_Path,
              Verification_Host,
              Options.Port,
              Presented_Key);
      end if;

      if Verification = SSH_Lib.Known_Hosts.Unknown
        and then Certificate_Authority_Path'Length > 0
      then
         --  CertificateAuthorityFile is treated as a data-only known_hosts
         --  authority source.  It is never executed and can trust only
         --  @cert-authority records accepted by the certificate validator.
         Verification :=
           Verify_Known_Host_Path_List
             (Certificate_Authority_Path,
              Verification_Host,
              Options.Port,
              Presented_Key);
      end if;

      if Verification = SSH_Lib.Known_Hosts.Unknown
        and then Options.Trust_On_First_Use
      then
         Status_Value :=
           SSH_Lib.Known_Hosts.Append_Trusted_Host
             (Known_Hosts_Path,
              Verification_Host,
              Options.Port,
              Presented_Key,
              Options.Hash_Known_Hosts);
         if Status_Value = Ok then
            Verification := SSH_Lib.Known_Hosts.Trusted;
         else
            Item.Known_Host_Trusted := False;
            Item.Known_Host_Bypassed_Explicitly := False;
            return Status_Value;
         end if;
      end if;

      Status_Value := SSH_Lib.Known_Hosts.To_Status (Verification);
      if Status_Value = Ok then
         Item.Known_Host_Trusted := True;
         Item.Known_Host_Bypassed_Explicitly := False;
      else
         Item.Known_Host_Trusted := False;
         Item.Known_Host_Bypassed_Explicitly := False;
      end if;

      return Status_Value;
   exception
      when others =>
         Item.Known_Host_Trusted := False;
         Item.Known_Host_Bypassed_Explicitly := False;
         return Internal_Error;
   end Verify_Presented_Host_Key;

   function Run_Group14_Kex
     (Transcript                     :
        in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Item                           : in out Session;
      Client_Kexinit                 : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit                 : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Negotiated_Item                :
        SSH_Lib.Protocol.Kex.Negotiated_Algorithms;
      Established_Session_Identifier : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Session_Identifier             :
        out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Host_Key_Blob                  :
        out SSH_Lib.Protocol.Buffers.Packet_Buffer) return Status
   is
      Source_Item              : CryptoLib.Random.Random_Source;
      Client_Private           : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Client_Public            : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Kex_Init_Payload         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Kex_Reply_Payload        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Item               : SSH_Lib.Protocol.Kexdh.Reply;
      Gex_Group_Item           : SSH_Lib.Protocol.Kexdh.Group_Exchange_Group;
      Selected_Gex_Group       :
        CryptoLib.Diffie_Hellman.Supported_Gex_Group :=
          CryptoLib.Diffie_Hellman.No_Supported_Gex_Group;
      Is_Gex                   : Boolean := False;
      Gex_Minimum_Bits         : constant Natural :=
        Item.Stored_Options.Gex_Minimum_Bits;
      Gex_Preferred_Bits       : constant Natural :=
        Item.Stored_Options.Gex_Preferred_Bits;
      Gex_Maximum_Bits         : constant Natural :=
        Item.Stored_Options.Gex_Maximum_Bits;
      Shared_Secret            : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Exchange_Digest          :
        SSH_Lib.Protocol.Exchange_Hash.Exchange_Digest;
      Exchange_SHA1_Digest     :
        SSH_Lib.Protocol.Exchange_Hash.Exchange_SHA1_Digest;
      Exchange_SHA512_Digest   :
        SSH_Lib.Protocol.Exchange_Hash.Exchange_SHA512_Digest;
      Derivation_Digest        : CryptoLib.Hashes.SHA256_Digest;
      Derivation_SHA512_Digest : CryptoLib.Hashes.SHA512_Digest;
      Null_SHA256_Digest       :
        constant CryptoLib.Hashes.SHA256_Digest := [others => 0];
      Derived_Item             : SSH_Lib.Protocol.Session_Keys.Derived_Keys;
      Kex_State                : SSH_Lib.Protocol.Encrypted_State.Kex_State;
      Status_Value             : Status;

      procedure Clear_Kex_Material is
      begin
         SSH_Lib.Protocol.Buffers.Clear (Client_Private);
         SSH_Lib.Protocol.Buffers.Clear (Client_Public);
         SSH_Lib.Protocol.Buffers.Clear (Kex_Init_Payload);
         SSH_Lib.Protocol.Buffers.Clear (Kex_Reply_Payload);
         SSH_Lib.Protocol.Kexdh.Clear (Gex_Group_Item);
         SSH_Lib.Protocol.Buffers.Clear (Shared_Secret);
         SSH_Lib.Protocol.Session_Keys.Clear (Derived_Item);
      exception
         when others =>
            null;
      end Clear_Kex_Material;

   begin
      SSH_Lib.Protocol.Buffers.Clear (Session_Identifier);
      SSH_Lib.Protocol.Buffers.Clear (Host_Key_Blob);
      if To_String (Negotiated_Item.Key_Exchange)
        /= "diffie-hellman-group18-sha512"
        and then
          To_String (Negotiated_Item.Key_Exchange)
          /= "diffie-hellman-group16-sha512"
        and then
          To_String (Negotiated_Item.Key_Exchange)
          /= "diffie-hellman-group14-sha256"
        and then
          To_String (Negotiated_Item.Key_Exchange)
          /= "diffie-hellman-group14-sha1"
        and then
          To_String (Negotiated_Item.Key_Exchange)
          /= "diffie-hellman-group1-sha1"
        and then
          To_String (Negotiated_Item.Key_Exchange)
          /= "diffie-hellman-group-exchange-sha256"
        and then
          To_String (Negotiated_Item.Key_Exchange)
          /= "diffie-hellman-group-exchange-sha1"
      then
         Clear_Kex_Material;
         return Unsupported_Feature;
      end if;

      Is_Gex :=
        To_String (Negotiated_Item.Key_Exchange)
        = "diffie-hellman-group-exchange-sha256"
        or else
          To_String (Negotiated_Item.Key_Exchange)
          = "diffie-hellman-group-exchange-sha1";

      if Is_Gex then
         Status_Value :=
           SSH_Lib.Protocol.Kexdh.Encode_Group_Exchange_Request
             (Gex_Minimum_Bits,
              Gex_Preferred_Bits,
              Gex_Maximum_Bits,
              Kex_Init_Payload);
         if Status_Value /= Ok then
            Clear_Kex_Material;
            return Status_Value;
         end if;
         Status_Value :=
           SSH_Lib.Sessions.Live_Transcript.Send_Key_Exchange_Packet
             (Transcript,
              SSH_Lib.Protocol.Buffers.To_Array (Kex_Init_Payload));
         if Status_Value /= Ok then
            Clear_Kex_Material;
            return Status_Value;
         end if;
         Status_Value :=
           Read_Non_Ignorable_Key_Exchange_Packet
             (Transcript, Kex_Reply_Payload);
         if Status_Value /= Ok then
            Clear_Kex_Material;
            return Status_Value;
         end if;
         Status_Value :=
           SSH_Lib.Protocol.Kexdh.Parse_Group_Exchange_Group
             (SSH_Lib.Protocol.Buffers.To_Array (Kex_Reply_Payload),
              Gex_Group_Item);
         if Status_Value /= Ok then
            Clear_Kex_Material;
            return Status_Value;
         end if;
         Selected_Gex_Group :=
           CryptoLib.Diffie_Hellman.Select_Group_Exchange_Group
             (SSH_Lib.Protocol.Buffers.To_Array (Gex_Group_Item.Prime_Value),
              SSH_Lib.Protocol.Buffers.To_Array
                (Gex_Group_Item.Generator_Value));
         if Selected_Gex_Group
           = CryptoLib.Diffie_Hellman.No_Supported_Gex_Group
         then
            Clear_Kex_Material;
            return Unsupported_Feature;
         end if;
      end if;

      CryptoLib.Random.Initialize_Production (Source_Item);
      if Is_Gex
        and then Selected_Gex_Group = CryptoLib.Diffie_Hellman.Gex_Group18
      then
         Status_Value :=
           CryptoLib.Diffie_Hellman.Generate_Group18_Keypair
             (Source_Item, Client_Private, Client_Public);
      elsif Is_Gex
        and then Selected_Gex_Group = CryptoLib.Diffie_Hellman.Gex_Group16
      then
         Status_Value :=
           CryptoLib.Diffie_Hellman.Generate_Group16_Keypair
             (Source_Item, Client_Private, Client_Public);
      elsif Is_Gex
        and then Selected_Gex_Group = CryptoLib.Diffie_Hellman.Gex_Group14
      then
         Status_Value :=
           CryptoLib.Diffie_Hellman.Generate_Group14_Keypair
             (Source_Item, Client_Private, Client_Public);
      elsif To_String (Negotiated_Item.Key_Exchange)
        = "diffie-hellman-group18-sha512"
      then
         Status_Value :=
           CryptoLib.Diffie_Hellman.Generate_Group18_Keypair
             (Source_Item, Client_Private, Client_Public);
      elsif To_String (Negotiated_Item.Key_Exchange)
        = "diffie-hellman-group16-sha512"
      then
         Status_Value :=
           CryptoLib.Diffie_Hellman.Generate_Group16_Keypair
             (Source_Item, Client_Private, Client_Public);
      elsif To_String (Negotiated_Item.Key_Exchange)
        = "diffie-hellman-group1-sha1"
      then
         Status_Value :=
           CryptoLib.Diffie_Hellman.Generate_Group1_Keypair
             (Source_Item, Client_Private, Client_Public);
      else
         Status_Value :=
           CryptoLib.Diffie_Hellman.Generate_Group14_Keypair
             (Source_Item, Client_Private, Client_Public);
      end if;
      if Status_Value /= Ok then
         Clear_Kex_Material;
         return Status_Value;
      end if;

      if Is_Gex then
         Status_Value :=
           SSH_Lib.Protocol.Kexdh.Encode_Group_Exchange_Init
             (SSH_Lib.Protocol.Buffers.To_Array (Client_Public),
              Kex_Init_Payload);
      else
         Status_Value :=
           SSH_Lib.Protocol.Kexdh.Encode_Group14_Init
             (SSH_Lib.Protocol.Buffers.To_Array (Client_Public),
              Kex_Init_Payload);
      end if;
      if Status_Value /= Ok then
         Clear_Kex_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Key_Exchange_Packet
          (Transcript, SSH_Lib.Protocol.Buffers.To_Array (Kex_Init_Payload));
      if Status_Value /= Ok then
         Clear_Kex_Material;
         return Status_Value;
      end if;

      Status_Value :=
        Read_Non_Ignorable_Key_Exchange_Packet (Transcript, Kex_Reply_Payload);
      if Status_Value /= Ok then
         Clear_Kex_Material;
         return Status_Value;
      end if;

      if Is_Gex then
         Status_Value :=
           SSH_Lib.Protocol.Kexdh.Parse_Group_Exchange_Reply
             (SSH_Lib.Protocol.Buffers.To_Array (Kex_Reply_Payload),
              Reply_Item);
      else
         Status_Value :=
           SSH_Lib.Protocol.Kexdh.Parse_Group14_Reply
             (SSH_Lib.Protocol.Buffers.To_Array (Kex_Reply_Payload),
              Reply_Item);
      end if;
      if Status_Value /= Ok then
         Clear_Kex_Material;
         return Status_Value;
      end if;

      if Is_Gex
        and then Selected_Gex_Group = CryptoLib.Diffie_Hellman.Gex_Group18
      then
         Status_Value :=
           CryptoLib.Diffie_Hellman.Compute_Group18_Shared_Secret
             (SSH_Lib.Protocol.Buffers.To_Array (Client_Private),
              SSH_Lib.Protocol.Buffers.To_Array
                (Reply_Item.Server_Public_Value),
              Shared_Secret);
      elsif Is_Gex
        and then Selected_Gex_Group = CryptoLib.Diffie_Hellman.Gex_Group16
      then
         Status_Value :=
           CryptoLib.Diffie_Hellman.Compute_Group16_Shared_Secret
             (SSH_Lib.Protocol.Buffers.To_Array (Client_Private),
              SSH_Lib.Protocol.Buffers.To_Array
                (Reply_Item.Server_Public_Value),
              Shared_Secret);
      elsif Is_Gex
        and then Selected_Gex_Group = CryptoLib.Diffie_Hellman.Gex_Group14
      then
         Status_Value :=
           CryptoLib.Diffie_Hellman.Compute_Group14_Shared_Secret
             (SSH_Lib.Protocol.Buffers.To_Array (Client_Private),
              SSH_Lib.Protocol.Buffers.To_Array
                (Reply_Item.Server_Public_Value),
              Shared_Secret);
      elsif To_String (Negotiated_Item.Key_Exchange)
        = "diffie-hellman-group18-sha512"
      then
         Status_Value :=
           CryptoLib.Diffie_Hellman.Compute_Group18_Shared_Secret
             (SSH_Lib.Protocol.Buffers.To_Array (Client_Private),
              SSH_Lib.Protocol.Buffers.To_Array
                (Reply_Item.Server_Public_Value),
              Shared_Secret);
      elsif To_String (Negotiated_Item.Key_Exchange)
        = "diffie-hellman-group16-sha512"
      then
         Status_Value :=
           CryptoLib.Diffie_Hellman.Compute_Group16_Shared_Secret
             (SSH_Lib.Protocol.Buffers.To_Array (Client_Private),
              SSH_Lib.Protocol.Buffers.To_Array
                (Reply_Item.Server_Public_Value),
              Shared_Secret);
      elsif To_String (Negotiated_Item.Key_Exchange)
        = "diffie-hellman-group1-sha1"
      then
         Status_Value :=
           CryptoLib.Diffie_Hellman.Compute_Group1_Shared_Secret
             (SSH_Lib.Protocol.Buffers.To_Array (Client_Private),
              SSH_Lib.Protocol.Buffers.To_Array
                (Reply_Item.Server_Public_Value),
              Shared_Secret);
      else
         Status_Value :=
           CryptoLib.Diffie_Hellman.Compute_Group14_Shared_Secret
             (SSH_Lib.Protocol.Buffers.To_Array (Client_Private),
              SSH_Lib.Protocol.Buffers.To_Array
                (Reply_Item.Server_Public_Value),
              Shared_Secret);
      end if;
      if Status_Value /= Ok then
         Clear_Kex_Material;
         return Status_Value;
      end if;

      if To_String (Negotiated_Item.Key_Exchange)
        = "diffie-hellman-group-exchange-sha1"
      then
         Status_Value :=
           SSH_Lib.Protocol.Exchange_Hash.Compute_Group_Exchange_SHA1
             (SSH_Lib.Sessions.Live_Transcript.Local_Identification
                (Transcript),
              SSH_Lib.Sessions.Live_Transcript.Remote_Identification
                (Transcript),
              Client_Kexinit,
              Server_Kexinit,
              SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
              Gex_Minimum_Bits,
              Gex_Preferred_Bits,
              Gex_Maximum_Bits,
              SSH_Lib.Protocol.Buffers.To_Array (Gex_Group_Item.Prime_Value),
              SSH_Lib.Protocol.Buffers.To_Array
                (Gex_Group_Item.Generator_Value),
              SSH_Lib.Protocol.Buffers.To_Array (Client_Public),
              SSH_Lib.Protocol.Buffers.To_Array
                (Reply_Item.Server_Public_Value),
              SSH_Lib.Protocol.Buffers.To_Array (Shared_Secret),
              Exchange_SHA1_Digest);
      elsif Is_Gex then
         Status_Value :=
           SSH_Lib.Protocol.Exchange_Hash.Compute_Group_Exchange_SHA256
             (SSH_Lib.Sessions.Live_Transcript.Local_Identification
                (Transcript),
              SSH_Lib.Sessions.Live_Transcript.Remote_Identification
                (Transcript),
              Client_Kexinit,
              Server_Kexinit,
              SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
              Gex_Minimum_Bits,
              Gex_Preferred_Bits,
              Gex_Maximum_Bits,
              SSH_Lib.Protocol.Buffers.To_Array (Gex_Group_Item.Prime_Value),
              SSH_Lib.Protocol.Buffers.To_Array
                (Gex_Group_Item.Generator_Value),
              SSH_Lib.Protocol.Buffers.To_Array (Client_Public),
              SSH_Lib.Protocol.Buffers.To_Array
                (Reply_Item.Server_Public_Value),
              SSH_Lib.Protocol.Buffers.To_Array (Shared_Secret),
              Exchange_Digest);
      elsif To_String (Negotiated_Item.Key_Exchange)
        = "diffie-hellman-group18-sha512"
      then
         Status_Value :=
           SSH_Lib.Protocol.Exchange_Hash.Compute_Group18_SHA512
             (SSH_Lib.Sessions.Live_Transcript.Local_Identification
                (Transcript),
              SSH_Lib.Sessions.Live_Transcript.Remote_Identification
                (Transcript),
              Client_Kexinit,
              Server_Kexinit,
              SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
              SSH_Lib.Protocol.Buffers.To_Array (Client_Public),
              SSH_Lib.Protocol.Buffers.To_Array
                (Reply_Item.Server_Public_Value),
              SSH_Lib.Protocol.Buffers.To_Array (Shared_Secret),
              Exchange_SHA512_Digest);
      elsif To_String (Negotiated_Item.Key_Exchange)
        = "diffie-hellman-group16-sha512"
      then
         Status_Value :=
           SSH_Lib.Protocol.Exchange_Hash.Compute_Group16_SHA512
             (SSH_Lib.Sessions.Live_Transcript.Local_Identification
                (Transcript),
              SSH_Lib.Sessions.Live_Transcript.Remote_Identification
                (Transcript),
              Client_Kexinit,
              Server_Kexinit,
              SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
              SSH_Lib.Protocol.Buffers.To_Array (Client_Public),
              SSH_Lib.Protocol.Buffers.To_Array
                (Reply_Item.Server_Public_Value),
              SSH_Lib.Protocol.Buffers.To_Array (Shared_Secret),
              Exchange_SHA512_Digest);
      elsif To_String (Negotiated_Item.Key_Exchange)
        = "diffie-hellman-group14-sha1"
        or else
          To_String (Negotiated_Item.Key_Exchange)
          = "diffie-hellman-group1-sha1"
      then
         Status_Value :=
           SSH_Lib.Protocol.Exchange_Hash.Compute_Group14_SHA1
             (SSH_Lib.Sessions.Live_Transcript.Local_Identification
                (Transcript),
              SSH_Lib.Sessions.Live_Transcript.Remote_Identification
                (Transcript),
              Client_Kexinit,
              Server_Kexinit,
              SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
              SSH_Lib.Protocol.Buffers.To_Array (Client_Public),
              SSH_Lib.Protocol.Buffers.To_Array
                (Reply_Item.Server_Public_Value),
              SSH_Lib.Protocol.Buffers.To_Array (Shared_Secret),
              Exchange_SHA1_Digest);
      else
         Status_Value :=
           SSH_Lib.Protocol.Exchange_Hash.Compute_Group14_SHA256
             (SSH_Lib.Sessions.Live_Transcript.Local_Identification
                (Transcript),
              SSH_Lib.Sessions.Live_Transcript.Remote_Identification
                (Transcript),
              Client_Kexinit,
              Server_Kexinit,
              SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
              SSH_Lib.Protocol.Buffers.To_Array (Client_Public),
              SSH_Lib.Protocol.Buffers.To_Array
                (Reply_Item.Server_Public_Value),
              SSH_Lib.Protocol.Buffers.To_Array (Shared_Secret),
              Exchange_Digest);
      end if;
      if Status_Value /= Ok then
         Clear_Kex_Material;
         return Status_Value;
      end if;

      SSH_Lib.Protocol.Encrypted_State.Reset (Kex_State);
      if To_String (Negotiated_Item.Key_Exchange)
        = "diffie-hellman-group18-sha512"
        or else
          To_String (Negotiated_Item.Key_Exchange)
          = "diffie-hellman-group16-sha512"
      then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Verify_And_Store
             (SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
              SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Signature_Blob),
              To_String (Negotiated_Item.Server_Host_Key),
              Digest_To_Array (Exchange_SHA512_Digest),
              Kex_State);
      elsif To_String (Negotiated_Item.Key_Exchange)
        = "diffie-hellman-group14-sha1"
        or else
          To_String (Negotiated_Item.Key_Exchange)
          = "diffie-hellman-group1-sha1"
        or else
          To_String (Negotiated_Item.Key_Exchange)
          = "diffie-hellman-group-exchange-sha1"
      then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Verify_And_Store
             (SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
              SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Signature_Blob),
              To_String (Negotiated_Item.Server_Host_Key),
              Digest_To_Array (Exchange_SHA1_Digest),
              Kex_State);
      else
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Verify_And_Store
             (SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
              SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Signature_Blob),
              To_String (Negotiated_Item.Server_Host_Key),
              Digest_To_Array (Exchange_Digest),
              Kex_State);
      end if;
      if Status_Value /= Ok then
         Clear_Kex_Material;
         return Status_Value;
      end if;
      Item.Host_Key_Signature_Verified := True;

      if SSH_Lib.Protocol.Buffers.Length (Established_Session_Identifier) = 0
      then
         if To_String (Negotiated_Item.Key_Exchange)
           = "diffie-hellman-group18-sha512"
           or else
             To_String (Negotiated_Item.Key_Exchange)
             = "diffie-hellman-group16-sha512"
         then
            Derivation_SHA512_Digest := Exchange_SHA512_Digest;
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Set
                (Session_Identifier, Digest_To_Array (Exchange_SHA512_Digest));
         elsif To_String (Negotiated_Item.Key_Exchange)
           = "diffie-hellman-group14-sha1"
           or else
             To_String (Negotiated_Item.Key_Exchange)
             = "diffie-hellman-group1-sha1"
           or else
             To_String (Negotiated_Item.Key_Exchange)
             = "diffie-hellman-group-exchange-sha1"
         then
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Set
                (Session_Identifier, Digest_To_Array (Exchange_SHA1_Digest));
         else
            Derivation_Digest := Exchange_Digest;
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Set
                (Session_Identifier, Digest_To_Array (Exchange_Digest));
         end if;
      else
         if To_String (Negotiated_Item.Key_Exchange)
           = "diffie-hellman-group18-sha512"
           or else
             To_String (Negotiated_Item.Key_Exchange)
             = "diffie-hellman-group16-sha512"
         then
            Status_Value :=
              Buffer_To_SHA512_Digest
                (Established_Session_Identifier, Derivation_SHA512_Digest);
            if Status_Value = Ok then
               Status_Value :=
                 SSH_Lib.Protocol.Buffers.Set
                   (Session_Identifier,
                    SSH_Lib.Protocol.Buffers.To_Array
                      (Established_Session_Identifier));
            end if;
         elsif To_String (Negotiated_Item.Key_Exchange)
           = "diffie-hellman-group14-sha1"
           or else
             To_String (Negotiated_Item.Key_Exchange)
             = "diffie-hellman-group1-sha1"
           or else
             To_String (Negotiated_Item.Key_Exchange)
             = "diffie-hellman-group-exchange-sha1"
         then
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Set
                (Session_Identifier,
                 SSH_Lib.Protocol.Buffers.To_Array
                   (Established_Session_Identifier));
         else
            Status_Value :=
              Buffer_To_Digest
                (Established_Session_Identifier, Derivation_Digest);
            if Status_Value = Ok then
               Status_Value :=
                 SSH_Lib.Protocol.Buffers.Set
                   (Session_Identifier,
                    SSH_Lib.Protocol.Buffers.To_Array
                      (Established_Session_Identifier));
            end if;
         end if;
      end if;
      if Status_Value /= Ok then
         Clear_Kex_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Set
          (Host_Key_Blob,
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob));
      if Status_Value /= Ok then
         Clear_Kex_Material;
         return Status_Value;
      end if;

      if To_String (Negotiated_Item.Key_Exchange)
        = "diffie-hellman-group18-sha512"
        or else
          To_String (Negotiated_Item.Key_Exchange)
          = "diffie-hellman-group16-sha512"
      then
         Status_Value :=
           SSH_Lib.Protocol.Session_Keys.Derive_SHA512_Keys
             (SSH_Lib.Protocol.Buffers.To_Array (Shared_Secret),
              Exchange_SHA512_Digest,
              Derivation_SHA512_Digest,
              16,
              Maximum_Of
                (Cipher_Key_Length
                   (To_String (Negotiated_Item.Cipher_Client_To_Server)),
                 Cipher_Key_Length
                   (To_String (Negotiated_Item.Cipher_Server_To_Client))),
              Maximum_Of
                (Mac_Key_Length
                   (To_String (Negotiated_Item.Mac_Client_To_Server)),
                 Mac_Key_Length
                   (To_String (Negotiated_Item.Mac_Server_To_Client))),
              Derived_Item);
      elsif To_String (Negotiated_Item.Key_Exchange)
        = "diffie-hellman-group14-sha1"
        or else
          To_String (Negotiated_Item.Key_Exchange)
          = "diffie-hellman-group1-sha1"
        or else
          To_String (Negotiated_Item.Key_Exchange)
          = "diffie-hellman-group-exchange-sha1"
      then
         Status_Value :=
           SSH_Lib.Protocol.Session_Keys.Derive_SHA1_Keys
             (SSH_Lib.Protocol.Buffers.To_Array (Shared_Secret),
              Exchange_SHA1_Digest,
              SSH_Lib.Protocol.Buffers.To_Array (Session_Identifier),
              16,
              Maximum_Of
                (Cipher_Key_Length
                   (To_String (Negotiated_Item.Cipher_Client_To_Server)),
                 Cipher_Key_Length
                   (To_String (Negotiated_Item.Cipher_Server_To_Client))),
              Maximum_Of
                (Mac_Key_Length
                   (To_String (Negotiated_Item.Mac_Client_To_Server)),
                 Mac_Key_Length
                   (To_String (Negotiated_Item.Mac_Server_To_Client))),
              Derived_Item);
      else
         Status_Value :=
           SSH_Lib.Protocol.Session_Keys.Derive_SHA256_Keys
             (SSH_Lib.Protocol.Buffers.To_Array (Shared_Secret),
              Exchange_Digest,
              Derivation_Digest,
              16,
              Maximum_Of
                (Cipher_Key_Length
                   (To_String (Negotiated_Item.Cipher_Client_To_Server)),
                 Cipher_Key_Length
                   (To_String (Negotiated_Item.Cipher_Server_To_Client))),
              Maximum_Of
                (Mac_Key_Length
                   (To_String (Negotiated_Item.Mac_Client_To_Server)),
                 Mac_Key_Length
                   (To_String (Negotiated_Item.Mac_Server_To_Client))),
              Derived_Item);
      end if;
      if Status_Value /= Ok then
         Clear_Kex_Material;
         return Status_Value;
      end if;
      Item.Keys_Derived := True;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Install_Derived_Keys
          (Kex_State,
           Negotiated_Item,
           (if To_String (Negotiated_Item.Key_Exchange)
              = "diffie-hellman-group14-sha1"
              or else
                To_String (Negotiated_Item.Key_Exchange)
                = "diffie-hellman-group1-sha1"
              or else
                To_String (Negotiated_Item.Key_Exchange)
                = "diffie-hellman-group-exchange-sha1"
              or else
                To_String (Negotiated_Item.Key_Exchange)
                = "diffie-hellman-group16-sha512"
              or else
                To_String (Negotiated_Item.Key_Exchange)
                = "diffie-hellman-group18-sha512"
           then Null_SHA256_Digest
            else Exchange_Digest),
           (if To_String (Negotiated_Item.Key_Exchange)
              = "diffie-hellman-group14-sha1"
              or else
                To_String (Negotiated_Item.Key_Exchange)
                = "diffie-hellman-group1-sha1"
              or else
                To_String (Negotiated_Item.Key_Exchange)
                = "diffie-hellman-group-exchange-sha1"
              or else
                To_String (Negotiated_Item.Key_Exchange)
                = "diffie-hellman-group16-sha512"
              or else
                To_String (Negotiated_Item.Key_Exchange)
                = "diffie-hellman-group18-sha512"
           then Null_SHA256_Digest
            else Derivation_Digest),
           Derived_Item);
      if Status_Value /= Ok then
         Clear_Kex_Material;
         return Status_Value;
      end if;
      Item.Kex_Complete := True;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Key_Exchange_Packet
          (Transcript, SSH_Lib.Protocol.Encrypted_State.Encode_Newkeys);
      if Status_Value /= Ok then
         Clear_Kex_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Send_Newkeys (Kex_State);
      if Status_Value /= Ok then
         Clear_Kex_Material;
         return Status_Value;
      end if;
      Item.Newkeys_Sent := True;
      Item.Encrypted_Outbound_Active := True;

      Status_Value :=
        Read_Non_Ignorable_Key_Exchange_Packet (Transcript, Kex_Reply_Payload);
      if Status_Value /= Ok then
         Clear_Kex_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Receive_Newkeys
          (Kex_State, SSH_Lib.Protocol.Buffers.To_Array (Kex_Reply_Payload));
      if Status_Value /= Ok then
         Clear_Kex_Material;
         return Status_Value;
      end if;
      Item.Newkeys_Received := True;
      Item.Encrypted_Inbound_Active := True;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Install_Protected_Keys
          (Transcript,
           To_String (Negotiated_Item.Cipher_Client_To_Server),
           To_String (Negotiated_Item.Cipher_Server_To_Client),
           To_String (Negotiated_Item.Mac_Client_To_Server),
           To_String (Negotiated_Item.Mac_Server_To_Client),
           To_String (Negotiated_Item.Compression_Client_To_Server),
           To_String (Negotiated_Item.Compression_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Integrity_Key_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Integrity_Key_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Encryption_Key_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Initial_IV_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Encryption_Key_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Initial_IV_Server_To_Client));
      if Status_Value /= Ok then
         Clear_Kex_Material;
         return Status_Value;
      end if;

      Clear_Kex_Material;
      return Ok;
   exception
      when others =>
         Clear_Kex_Material;
         SSH_Lib.Protocol.Buffers.Clear (Session_Identifier);
         SSH_Lib.Protocol.Buffers.Clear (Host_Key_Blob);
         return Internal_Error;
   end Run_Group14_Kex;

   function Run_Hybrid_PQ_Kex
     (Transcript                     :
        in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Item                           : in out Session;
      Client_Kexinit                 : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit                 : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Negotiated_Item                :
        SSH_Lib.Protocol.Kex.Negotiated_Algorithms;
      Established_Session_Identifier : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Session_Identifier             :
        out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Host_Key_Blob                  :
        out SSH_Lib.Protocol.Buffers.Packet_Buffer) return Status
   is
      Kex_Name                 : constant String :=
        To_String (Negotiated_Item.Key_Exchange);
      Source_Item              : CryptoLib.Random.Random_Source;
      Client_Private           : CryptoLib.Curve25519.Private_Key;
      Client_Public            : CryptoLib.Curve25519.Public_Key;
      Server_Public            : CryptoLib.Curve25519.Public_Key;
      X25519_Secret_LE         : CryptoLib.Curve25519.Public_Key;
      Client_X25519_Array      : Stream_Element_Array (1 .. 32);
      X25519_Secret_Raw         : Stream_Element_Array (1 .. 32);
      Client_Init              : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Kex_Init_Payload         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Kex_Reply_Payload        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Item               : SSH_Lib.Protocol.Kexdh.Reply;
      Combined_SHA256          : CryptoLib.Hashes.SHA256_Digest :=
        [others => 0];
      Combined_SHA512          : CryptoLib.Hashes.SHA512_Digest :=
        [others => 0];
      Exchange_Digest          :
        SSH_Lib.Protocol.Exchange_Hash.Exchange_Digest := [others => 0];
      Exchange_SHA512_Digest   :
        SSH_Lib.Protocol.Exchange_Hash.Exchange_SHA512_Digest := [others => 0];
      Derivation_Digest        : CryptoLib.Hashes.SHA256_Digest :=
        [others => 0];
      Derivation_SHA512_Digest : CryptoLib.Hashes.SHA512_Digest :=
        [others => 0];
      Null_SHA256_Digest       :
        constant CryptoLib.Hashes.SHA256_Digest := [others => 0];
      Derived_Item             : SSH_Lib.Protocol.Session_Keys.Derived_Keys;
      Kex_State                : SSH_Lib.Protocol.Encrypted_State.Kex_State;
      Status_Value             : Status;

      procedure Clear_Hybrid_Material is
      begin
         CryptoLib.Curve25519.Clear (Client_Private);
         CryptoLib.Curve25519.Clear (Client_Public);
         CryptoLib.Curve25519.Clear (Server_Public);
         CryptoLib.Curve25519.Clear (X25519_Secret_LE);
         Client_X25519_Array := [others => 0];
         X25519_Secret_Raw := [others => 0];
         Combined_SHA256 := [others => 0];
         Combined_SHA512 := [others => 0];
         SSH_Lib.Protocol.Buffers.Clear (Client_Init);
         SSH_Lib.Protocol.Buffers.Clear (Kex_Init_Payload);
         SSH_Lib.Protocol.Buffers.Clear (Kex_Reply_Payload);
         SSH_Lib.Protocol.Kexdh.Clear (Reply_Item);
         SSH_Lib.Protocol.Session_Keys.Clear (Derived_Item);
      exception
         when others =>
            null;
      end Clear_Hybrid_Material;

      function Append_X25519_Public return Status is
      begin
         for Offset_Value in 0 .. 31 loop
            Client_X25519_Array
              (Client_X25519_Array'First
               + Stream_Element_Offset (Offset_Value)) :=
              Client_Public
                (CryptoLib.Curve25519.Public_Key_Index
                   (Offset_Value + 1));
         end loop;
         return
           SSH_Lib.Protocol.Buffers.Append (Client_Init, Client_X25519_Array);
      end Append_X25519_Public;

      function Combine_SHA256
        (PQ_Secret : Stream_Element_Array; X_Secret : Stream_Element_Array)
         return CryptoLib.Hashes.SHA256_Digest
      is
         Work_Item   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
         Result_Item : CryptoLib.Hashes.SHA256_Digest := [others => 0];
      begin
         SSH_Lib.Protocol.Buffers.Clear (Work_Item);
         if SSH_Lib.Protocol.Buffers.Append (Work_Item, PQ_Secret) /= Ok then
            return Result_Item;
         end if;
         if SSH_Lib.Protocol.Buffers.Append (Work_Item, X_Secret) /= Ok then
            SSH_Lib.Protocol.Buffers.Clear (Work_Item);
            return Result_Item;
         end if;
         Result_Item :=
           CryptoLib.Hashes.SHA256
             (SSH_Lib.Protocol.Buffers.To_Array (Work_Item));
         SSH_Lib.Protocol.Buffers.Clear (Work_Item);
         return Result_Item;
      end Combine_SHA256;

      function Combine_SHA512
        (PQ_Secret : Stream_Element_Array; X_Secret : Stream_Element_Array)
         return CryptoLib.Hashes.SHA512_Digest
      is
         Work_Item   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
         Result_Item : CryptoLib.Hashes.SHA512_Digest := [others => 0];
      begin
         SSH_Lib.Protocol.Buffers.Clear (Work_Item);
         if SSH_Lib.Protocol.Buffers.Append (Work_Item, PQ_Secret) /= Ok then
            return Result_Item;
         end if;
         if SSH_Lib.Protocol.Buffers.Append (Work_Item, X_Secret) /= Ok then
            SSH_Lib.Protocol.Buffers.Clear (Work_Item);
            return Result_Item;
         end if;
         Result_Item :=
           CryptoLib.Hashes.SHA512
             (SSH_Lib.Protocol.Buffers.To_Array (Work_Item));
         SSH_Lib.Protocol.Buffers.Clear (Work_Item);
         return Result_Item;
      end Combine_SHA512;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Session_Identifier);
      SSH_Lib.Protocol.Buffers.Clear (Host_Key_Blob);

      if not CryptoLib.Hybrid_PQ_Kex.Is_OpenSSH_Hybrid_PQ_Kex_Name
               (Kex_Name)
      then
         Clear_Hybrid_Material;
         return Unsupported_Feature;
      end if;

      CryptoLib.Random.Initialize_Production (Source_Item);
      Status_Value :=
        CryptoLib.Curve25519.Generate_Keypair
          (Source_Item, Client_Private, Client_Public);
      if Status_Value /= Ok then
         Clear_Hybrid_Material;
         return Status_Value;
      end if;

      if CryptoLib.Hybrid_PQ_Kex.Is_MLKEM768_Hybrid_PQ_Kex_Name (Kex_Name)
      then
         declare
            PQ_Public     : CryptoLib.MLKEM768.Public_Key;
            PQ_Secret_Key : CryptoLib.MLKEM768.Secret_Key;
         begin
            Status_Value :=
              CryptoLib.MLKEM768.Generate_Keypair
                (Source_Item, PQ_Public, PQ_Secret_Key);
            if Status_Value /= Ok then
               CryptoLib.MLKEM768.Clear (PQ_Secret_Key);
               Clear_Hybrid_Material;
               return Status_Value;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Buffers.Append (Client_Init, PQ_Public);
            if Status_Value = Ok then
               Status_Value := Append_X25519_Public;
            end if;
            PQ_Public := [others => 0];
            if Status_Value /= Ok then
               CryptoLib.MLKEM768.Clear (PQ_Secret_Key);
               Clear_Hybrid_Material;
               return Status_Value;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Kexdh.Encode_Hybrid_PQ_Init
                (SSH_Lib.Protocol.Buffers.To_Array (Client_Init),
                 Kex_Init_Payload);
            if Status_Value /= Ok then
               CryptoLib.MLKEM768.Clear (PQ_Secret_Key);
               Clear_Hybrid_Material;
               return Status_Value;
            end if;

            Status_Value :=
              SSH_Lib.Sessions.Live_Transcript.Send_Key_Exchange_Packet
                (Transcript,
                 SSH_Lib.Protocol.Buffers.To_Array (Kex_Init_Payload));
            if Status_Value /= Ok then
               CryptoLib.MLKEM768.Clear (PQ_Secret_Key);
               Clear_Hybrid_Material;
               return Status_Value;
            end if;

            Status_Value :=
              Read_Non_Ignorable_Key_Exchange_Packet
                (Transcript, Kex_Reply_Payload);
            if Status_Value /= Ok then
               CryptoLib.MLKEM768.Clear (PQ_Secret_Key);
               Clear_Hybrid_Material;
               return Status_Value;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Kexdh.Parse_Hybrid_PQ_Reply
                (SSH_Lib.Protocol.Buffers.To_Array (Kex_Reply_Payload),
                 Reply_Item);
            if Status_Value /= Ok then
               CryptoLib.MLKEM768.Clear (PQ_Secret_Key);
               Clear_Hybrid_Material;
               return Status_Value;
            end if;

            declare
               Server_Reply_Array : constant Stream_Element_Array :=
                 SSH_Lib.Protocol.Buffers.To_Array
                   (Reply_Item.Server_Public_Value);
               PQ_Ciphertext      : CryptoLib.MLKEM768.Ciphertext;
               PQ_Shared          : CryptoLib.MLKEM768.Shared_Key;
            begin
               if Server_Reply_Array'Length
                 /= CryptoLib.MLKEM768.Ciphertext_Length + 32
               then
                  CryptoLib.MLKEM768.Clear (PQ_Secret_Key);
                  Clear_Hybrid_Material;
                  return Handshake_Failed;
               end if;

               for Offset_Value in
                 0 .. CryptoLib.MLKEM768.Ciphertext_Length - 1
               loop
                  PQ_Ciphertext
                    (PQ_Ciphertext'First
                     + Stream_Element_Offset (Offset_Value)) :=
                    Server_Reply_Array
                      (Server_Reply_Array'First
                       + Stream_Element_Offset (Offset_Value));
               end loop;
               for Offset_Value in 0 .. 31 loop
                  Server_Public
                    (CryptoLib.Curve25519.Public_Key_Index
                       (Offset_Value + 1)) :=
                    Server_Reply_Array
                      (Server_Reply_Array'First
                       + Stream_Element_Offset
                           (CryptoLib.MLKEM768.Ciphertext_Length
                            + Offset_Value));
               end loop;

               Status_Value :=
                 CryptoLib.MLKEM768.Decapsulate
                   (PQ_Secret_Key, PQ_Ciphertext, PQ_Shared);
               CryptoLib.MLKEM768.Clear (PQ_Secret_Key);
               PQ_Ciphertext := [others => 0];
               if Status_Value /= Ok then
                  PQ_Shared := [others => 0];
                  Clear_Hybrid_Material;
                  return Status_Value;
               end if;

               Status_Value :=
                 CryptoLib.Curve25519.Shared_Secret
                   (Client_Private, Server_Public, X25519_Secret_LE);
               if Status_Value /= Ok then
                  PQ_Shared := [others => 0];
                  Clear_Hybrid_Material;
                  return Status_Value;
               end if;

               for Offset_Value in 0 .. 31 loop
                  X25519_Secret_Raw
                    (X25519_Secret_Raw'First
                     + Stream_Element_Offset (Offset_Value)) :=
                    X25519_Secret_LE
                      (CryptoLib.Curve25519.Public_Key_Index
                         (Offset_Value + 1));
               end loop;

               if CryptoLib.Hybrid_PQ_Kex.Uses_SHA512_Combiner (Kex_Name)
               then
                  Combined_SHA512 :=
                    Combine_SHA512 (PQ_Shared, X25519_Secret_Raw);
               else
                  Combined_SHA256 :=
                    Combine_SHA256 (PQ_Shared, X25519_Secret_Raw);
               end if;
               PQ_Shared := [others => 0];
            end;
         end;
      else
         declare
            PQ_Public     : CryptoLib.SNTRUP761.Public_Key;
            PQ_Secret_Key : CryptoLib.SNTRUP761.Secret_Key;
         begin
            Status_Value :=
              CryptoLib.SNTRUP761.Generate_Keypair
                (Source_Item, PQ_Public, PQ_Secret_Key);
            if Status_Value /= Ok then
               CryptoLib.SNTRUP761.Clear (PQ_Secret_Key);
               Clear_Hybrid_Material;
               return Status_Value;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Buffers.Append (Client_Init, PQ_Public);
            if Status_Value = Ok then
               Status_Value := Append_X25519_Public;
            end if;
            PQ_Public := [others => 0];
            if Status_Value /= Ok then
               CryptoLib.SNTRUP761.Clear (PQ_Secret_Key);
               Clear_Hybrid_Material;
               return Status_Value;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Kexdh.Encode_Hybrid_PQ_Init
                (SSH_Lib.Protocol.Buffers.To_Array (Client_Init),
                 Kex_Init_Payload);
            if Status_Value /= Ok then
               CryptoLib.SNTRUP761.Clear (PQ_Secret_Key);
               Clear_Hybrid_Material;
               return Status_Value;
            end if;

            Status_Value :=
              SSH_Lib.Sessions.Live_Transcript.Send_Key_Exchange_Packet
                (Transcript,
                 SSH_Lib.Protocol.Buffers.To_Array (Kex_Init_Payload));
            if Status_Value /= Ok then
               CryptoLib.SNTRUP761.Clear (PQ_Secret_Key);
               Clear_Hybrid_Material;
               return Status_Value;
            end if;

            Status_Value :=
              Read_Non_Ignorable_Key_Exchange_Packet
                (Transcript, Kex_Reply_Payload);
            if Status_Value /= Ok then
               CryptoLib.SNTRUP761.Clear (PQ_Secret_Key);
               Clear_Hybrid_Material;
               return Status_Value;
            end if;

            Status_Value :=
              SSH_Lib.Protocol.Kexdh.Parse_Hybrid_PQ_Reply
                (SSH_Lib.Protocol.Buffers.To_Array (Kex_Reply_Payload),
                 Reply_Item);
            if Status_Value /= Ok then
               CryptoLib.SNTRUP761.Clear (PQ_Secret_Key);
               Clear_Hybrid_Material;
               return Status_Value;
            end if;

            declare
               Server_Reply_Array : constant Stream_Element_Array :=
                 SSH_Lib.Protocol.Buffers.To_Array
                   (Reply_Item.Server_Public_Value);
               PQ_Ciphertext      : CryptoLib.SNTRUP761.Ciphertext;
               PQ_Shared          : CryptoLib.SNTRUP761.Shared_Key;
            begin
               if Server_Reply_Array'Length
                 /= CryptoLib.SNTRUP761.Ciphertext_Length + 32
               then
                  CryptoLib.SNTRUP761.Clear (PQ_Secret_Key);
                  Clear_Hybrid_Material;
                  return Handshake_Failed;
               end if;

               for Offset_Value in
                 0 .. CryptoLib.SNTRUP761.Ciphertext_Length - 1
               loop
                  PQ_Ciphertext
                    (PQ_Ciphertext'First
                     + Stream_Element_Offset (Offset_Value)) :=
                    Server_Reply_Array
                      (Server_Reply_Array'First
                       + Stream_Element_Offset (Offset_Value));
               end loop;
               for Offset_Value in 0 .. 31 loop
                  Server_Public
                    (CryptoLib.Curve25519.Public_Key_Index
                       (Offset_Value + 1)) :=
                    Server_Reply_Array
                      (Server_Reply_Array'First
                       + Stream_Element_Offset
                           (CryptoLib.SNTRUP761.Ciphertext_Length
                            + Offset_Value));
               end loop;

               Status_Value :=
                 CryptoLib.SNTRUP761.Decapsulate
                   (PQ_Secret_Key, PQ_Ciphertext, PQ_Shared);
               CryptoLib.SNTRUP761.Clear (PQ_Secret_Key);
               PQ_Ciphertext := [others => 0];
               if Status_Value /= Ok then
                  PQ_Shared := [others => 0];
                  Clear_Hybrid_Material;
                  return Status_Value;
               end if;

               Status_Value :=
                 CryptoLib.Curve25519.Shared_Secret
                   (Client_Private, Server_Public, X25519_Secret_LE);
               if Status_Value /= Ok then
                  PQ_Shared := [others => 0];
                  Clear_Hybrid_Material;
                  return Status_Value;
               end if;

               for Offset_Value in 0 .. 31 loop
                  X25519_Secret_Raw
                    (X25519_Secret_Raw'First
                     + Stream_Element_Offset (Offset_Value)) :=
                    X25519_Secret_LE
                      (CryptoLib.Curve25519.Public_Key_Index
                         (Offset_Value + 1));
               end loop;

               Combined_SHA512 := Combine_SHA512 (PQ_Shared, X25519_Secret_Raw);
               PQ_Shared := [others => 0];
            end;
         end;
      end if;

      if CryptoLib.Hybrid_PQ_Kex.Uses_SHA512_Combiner (Kex_Name) then
         Status_Value :=
           SSH_Lib.Protocol.Exchange_Hash.Compute_Hybrid_PQ_SHA512
             (SSH_Lib.Sessions.Live_Transcript.Local_Identification
                (Transcript),
              SSH_Lib.Sessions.Live_Transcript.Remote_Identification
                (Transcript),
              Client_Kexinit,
              Server_Kexinit,
              SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
              SSH_Lib.Protocol.Buffers.To_Array (Client_Init),
              SSH_Lib.Protocol.Buffers.To_Array
                (Reply_Item.Server_Public_Value),
              Digest_To_Array (Combined_SHA512),
              Exchange_SHA512_Digest);
      else
         Status_Value :=
           SSH_Lib.Protocol.Exchange_Hash.Compute_Hybrid_PQ_SHA256
             (SSH_Lib.Sessions.Live_Transcript.Local_Identification
                (Transcript),
              SSH_Lib.Sessions.Live_Transcript.Remote_Identification
                (Transcript),
              Client_Kexinit,
              Server_Kexinit,
              SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
              SSH_Lib.Protocol.Buffers.To_Array (Client_Init),
              SSH_Lib.Protocol.Buffers.To_Array
                (Reply_Item.Server_Public_Value),
              Digest_To_Array (Combined_SHA256),
              Exchange_Digest);
      end if;
      if Status_Value /= Ok then
         Clear_Hybrid_Material;
         return Status_Value;
      end if;

      SSH_Lib.Protocol.Encrypted_State.Reset (Kex_State);
      if CryptoLib.Hybrid_PQ_Kex.Uses_SHA512_Combiner (Kex_Name) then
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Verify_And_Store
             (SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
              SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Signature_Blob),
              To_String (Negotiated_Item.Server_Host_Key),
              Digest_To_Array (Exchange_SHA512_Digest),
              Kex_State);
      else
         Status_Value :=
           SSH_Lib.Protocol.Host_Keys.Verify_And_Store
             (SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
              SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Signature_Blob),
              To_String (Negotiated_Item.Server_Host_Key),
              Digest_To_Array (Exchange_Digest),
              Kex_State);
      end if;
      if Status_Value /= Ok then
         Clear_Hybrid_Material;
         return Status_Value;
      end if;
      Item.Host_Key_Signature_Verified := True;

      if SSH_Lib.Protocol.Buffers.Length (Established_Session_Identifier) = 0
      then
         if CryptoLib.Hybrid_PQ_Kex.Uses_SHA512_Combiner (Kex_Name) then
            Derivation_SHA512_Digest := Exchange_SHA512_Digest;
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Set
                (Session_Identifier, Digest_To_Array (Exchange_SHA512_Digest));
         else
            Derivation_Digest := Exchange_Digest;
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Set
                (Session_Identifier, Digest_To_Array (Exchange_Digest));
         end if;
      else
         if CryptoLib.Hybrid_PQ_Kex.Uses_SHA512_Combiner (Kex_Name) then
            Status_Value :=
              Buffer_To_SHA512_Digest
                (Established_Session_Identifier, Derivation_SHA512_Digest);
            if Status_Value = Ok then
               Status_Value :=
                 SSH_Lib.Protocol.Buffers.Set
                   (Session_Identifier,
                    SSH_Lib.Protocol.Buffers.To_Array
                      (Established_Session_Identifier));
            end if;
         else
            Status_Value :=
              Buffer_To_Digest
                (Established_Session_Identifier, Derivation_Digest);
            if Status_Value = Ok then
               Status_Value :=
                 SSH_Lib.Protocol.Buffers.Set
                   (Session_Identifier,
                    SSH_Lib.Protocol.Buffers.To_Array
                      (Established_Session_Identifier));
            end if;
         end if;
      end if;
      if Status_Value /= Ok then
         Clear_Hybrid_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Set
          (Host_Key_Blob,
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob));
      if Status_Value /= Ok then
         Clear_Hybrid_Material;
         return Status_Value;
      end if;

      if CryptoLib.Hybrid_PQ_Kex.Uses_SHA512_Combiner (Kex_Name) then
         Status_Value :=
           SSH_Lib.Protocol.Session_Keys.Derive_SHA512_Keys
             (Digest_To_Array (Combined_SHA512),
              Exchange_SHA512_Digest,
              Derivation_SHA512_Digest,
              16,
              Maximum_Of
                (Cipher_Key_Length
                   (To_String (Negotiated_Item.Cipher_Client_To_Server)),
                 Cipher_Key_Length
                   (To_String (Negotiated_Item.Cipher_Server_To_Client))),
              Maximum_Of
                (Mac_Key_Length
                   (To_String (Negotiated_Item.Mac_Client_To_Server)),
                 Mac_Key_Length
                   (To_String (Negotiated_Item.Mac_Server_To_Client))),
              Derived_Item,
              As_String => True);
      else
         Status_Value :=
           SSH_Lib.Protocol.Session_Keys.Derive_SHA256_Keys
             (Digest_To_Array (Combined_SHA256),
              Exchange_Digest,
              Derivation_Digest,
              16,
              Maximum_Of
                (Cipher_Key_Length
                   (To_String (Negotiated_Item.Cipher_Client_To_Server)),
                 Cipher_Key_Length
                   (To_String (Negotiated_Item.Cipher_Server_To_Client))),
              Maximum_Of
                (Mac_Key_Length
                   (To_String (Negotiated_Item.Mac_Client_To_Server)),
                 Mac_Key_Length
                   (To_String (Negotiated_Item.Mac_Server_To_Client))),
              Derived_Item,
              As_String => True);
      end if;
      if Status_Value /= Ok then
         Clear_Hybrid_Material;
         return Status_Value;
      end if;
      Item.Keys_Derived := True;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Install_Derived_Keys
          (Kex_State,
           Negotiated_Item,
           (if CryptoLib.Hybrid_PQ_Kex.Uses_SHA512_Combiner (Kex_Name)
            then Null_SHA256_Digest
            else Exchange_Digest),
           (if CryptoLib.Hybrid_PQ_Kex.Uses_SHA512_Combiner (Kex_Name)
            then Null_SHA256_Digest
            else Derivation_Digest),
           Derived_Item);
      if Status_Value /= Ok then
         Clear_Hybrid_Material;
         return Status_Value;
      end if;
      Item.Kex_Complete := True;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Key_Exchange_Packet
          (Transcript, SSH_Lib.Protocol.Encrypted_State.Encode_Newkeys);
      if Status_Value /= Ok then
         Clear_Hybrid_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Send_Newkeys (Kex_State);
      if Status_Value /= Ok then
         Clear_Hybrid_Material;
         return Status_Value;
      end if;
      Item.Newkeys_Sent := True;
      Item.Encrypted_Outbound_Active := True;

      Status_Value :=
        Read_Non_Ignorable_Key_Exchange_Packet (Transcript, Kex_Reply_Payload);
      if Status_Value /= Ok then
         Clear_Hybrid_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Receive_Newkeys
          (Kex_State, SSH_Lib.Protocol.Buffers.To_Array (Kex_Reply_Payload));
      if Status_Value /= Ok then
         Clear_Hybrid_Material;
         return Status_Value;
      end if;
      Item.Newkeys_Received := True;
      Item.Encrypted_Inbound_Active := True;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Install_Protected_Keys
          (Transcript,
           To_String (Negotiated_Item.Cipher_Client_To_Server),
           To_String (Negotiated_Item.Cipher_Server_To_Client),
           To_String (Negotiated_Item.Mac_Client_To_Server),
           To_String (Negotiated_Item.Mac_Server_To_Client),
           To_String (Negotiated_Item.Compression_Client_To_Server),
           To_String (Negotiated_Item.Compression_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Integrity_Key_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Integrity_Key_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Encryption_Key_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Initial_IV_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Encryption_Key_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Initial_IV_Server_To_Client));
      if Status_Value /= Ok then
         Clear_Hybrid_Material;
         return Status_Value;
      end if;

      Clear_Hybrid_Material;
      return Ok;
   exception
      when others =>
         Clear_Hybrid_Material;
         SSH_Lib.Protocol.Buffers.Clear (Session_Identifier);
         SSH_Lib.Protocol.Buffers.Clear (Host_Key_Blob);
         return Internal_Error;
   end Run_Hybrid_PQ_Kex;

   function Run_Curve25519_Kex
     (Transcript                     :
        in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Item                           : in out Session;
      Client_Kexinit                 : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit                 : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Negotiated_Item                :
        SSH_Lib.Protocol.Kex.Negotiated_Algorithms;
      Established_Session_Identifier : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Session_Identifier             :
        out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Host_Key_Blob                  :
        out SSH_Lib.Protocol.Buffers.Packet_Buffer) return Status
   is
      Source_Item         : CryptoLib.Random.Random_Source;
      Client_Private      : CryptoLib.Curve25519.Private_Key;
      Client_Public       : CryptoLib.Curve25519.Public_Key;
      Server_Public       : CryptoLib.Curve25519.Public_Key;
      Shared_Secret_LE    : CryptoLib.Curve25519.Public_Key;
      Client_Public_Array : Stream_Element_Array (1 .. 32);
      Shared_Secret_K     : Stream_Element_Array (1 .. 32);
      Kex_Init_Payload    : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Kex_Reply_Payload   : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Item          : SSH_Lib.Protocol.Kexdh.Reply;
      Exchange_Digest     : SSH_Lib.Protocol.Exchange_Hash.Exchange_Digest;
      Derivation_Digest   : CryptoLib.Hashes.SHA256_Digest;
      Derived_Item        : SSH_Lib.Protocol.Session_Keys.Derived_Keys;
      Kex_State           : SSH_Lib.Protocol.Encrypted_State.Kex_State;
      Status_Value        : Status;

      procedure Clear_Curve_Material is
      begin
         CryptoLib.Curve25519.Clear (Client_Private);
         CryptoLib.Curve25519.Clear (Client_Public);
         CryptoLib.Curve25519.Clear (Server_Public);
         CryptoLib.Curve25519.Clear (Shared_Secret_LE);
         Shared_Secret_K := [others => 0];
         Client_Public_Array := [others => 0];
         SSH_Lib.Protocol.Buffers.Clear (Kex_Init_Payload);
         SSH_Lib.Protocol.Buffers.Clear (Kex_Reply_Payload);
         SSH_Lib.Protocol.Session_Keys.Clear (Derived_Item);
      exception
         when others =>
            null;
      end Clear_Curve_Material;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Session_Identifier);
      SSH_Lib.Protocol.Buffers.Clear (Host_Key_Blob);
      if To_String (Negotiated_Item.Key_Exchange) /= "curve25519-sha256"
        and then
          To_String (Negotiated_Item.Key_Exchange)
          /= "curve25519-sha256@libssh.org"
      then
         Clear_Curve_Material;
         return Unsupported_Feature;
      end if;

      CryptoLib.Random.Initialize_Production (Source_Item);
      Status_Value :=
        CryptoLib.Curve25519.Generate_Keypair
          (Source_Item, Client_Private, Client_Public);
      if Status_Value /= Ok then
         Clear_Curve_Material;
         return Status_Value;
      end if;

      for Offset_Value in 0 .. 31 loop
         Client_Public_Array
           (Client_Public_Array'First
            + Stream_Element_Offset (Offset_Value)) :=
           Client_Public
             (CryptoLib.Curve25519.Public_Key_Index (Offset_Value + 1));
      end loop;

      Status_Value :=
        SSH_Lib.Protocol.Kexdh.Encode_Curve25519_Init
          (Client_Public_Array, Kex_Init_Payload);
      if Status_Value /= Ok then
         Clear_Curve_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Key_Exchange_Packet
          (Transcript, SSH_Lib.Protocol.Buffers.To_Array (Kex_Init_Payload));
      if Status_Value /= Ok then
         Clear_Curve_Material;
         return Status_Value;
      end if;

      Status_Value :=
        Read_Non_Ignorable_Key_Exchange_Packet (Transcript, Kex_Reply_Payload);
      if Status_Value /= Ok then
         Clear_Curve_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Kexdh.Parse_Curve25519_Reply
          (SSH_Lib.Protocol.Buffers.To_Array (Kex_Reply_Payload), Reply_Item);
      if Status_Value /= Ok then
         Clear_Curve_Material;
         return Status_Value;
      end if;

      declare
         Server_Public_Array : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Server_Public_Value);
      begin
         for Offset_Value in 0 .. 31 loop
            Server_Public
              (CryptoLib.Curve25519.Public_Key_Index
                 (Offset_Value + 1)) :=
              Server_Public_Array
                (Server_Public_Array'First
                 + Stream_Element_Offset (Offset_Value));
         end loop;
      end;

      Status_Value :=
        CryptoLib.Curve25519.Shared_Secret
          (Client_Private, Server_Public, Shared_Secret_LE);
      if Status_Value /= Ok then
         Clear_Curve_Material;
         return Status_Value;
      end if;

      --  RFC 8731 feeds the X25519 output bytes to SSH as the fixed-width
      --  integer K input before mpint encoding.  The RFC 7748 byte string is
      --  reinterpreted for SSH; it is not byte-swapped first.
      for Offset_Value in 0 .. 31 loop
         Shared_Secret_K
           (Shared_Secret_K'First + Stream_Element_Offset (Offset_Value)) :=
           Shared_Secret_LE
             (CryptoLib.Curve25519.Public_Key_Index (Offset_Value + 1));
      end loop;

      Status_Value :=
        SSH_Lib.Protocol.Exchange_Hash.Compute_Curve25519_SHA256
          (SSH_Lib.Sessions.Live_Transcript.Local_Identification (Transcript),
           SSH_Lib.Sessions.Live_Transcript.Remote_Identification (Transcript),
           Client_Kexinit,
           Server_Kexinit,
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
           Client_Public_Array,
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Server_Public_Value),
           Shared_Secret_K,
           Exchange_Digest);
      if Status_Value /= Ok then
         Clear_Curve_Material;
         return Status_Value;
      end if;

      SSH_Lib.Protocol.Encrypted_State.Reset (Kex_State);
      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Verify_And_Store
          (SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Signature_Blob),
           To_String (Negotiated_Item.Server_Host_Key),
           Digest_To_Array (Exchange_Digest),
           Kex_State);
      if Status_Value /= Ok then
         Clear_Curve_Material;
         return Status_Value;
      end if;
      Item.Host_Key_Signature_Verified := True;

      if SSH_Lib.Protocol.Buffers.Length (Established_Session_Identifier) = 0
      then
         Derivation_Digest := Exchange_Digest;
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Set
             (Session_Identifier, Digest_To_Array (Exchange_Digest));
      else
         Status_Value :=
           Buffer_To_Digest
             (Established_Session_Identifier, Derivation_Digest);
         if Status_Value = Ok then
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Set
                (Session_Identifier,
                 SSH_Lib.Protocol.Buffers.To_Array
                   (Established_Session_Identifier));
         end if;
      end if;
      if Status_Value /= Ok then
         Clear_Curve_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Set
          (Host_Key_Blob,
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob));
      if Status_Value /= Ok then
         Clear_Curve_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Session_Keys.Derive_SHA256_Keys
          (Shared_Secret_K,
           Exchange_Digest,
           Derivation_Digest,
           16,
           Maximum_Of
             (Cipher_Key_Length
                (To_String (Negotiated_Item.Cipher_Client_To_Server)),
              Cipher_Key_Length
                (To_String (Negotiated_Item.Cipher_Server_To_Client))),
           Maximum_Of
             (Mac_Key_Length
                (To_String (Negotiated_Item.Mac_Client_To_Server)),
              Mac_Key_Length
                (To_String (Negotiated_Item.Mac_Server_To_Client))),
           Derived_Item);
      if Status_Value /= Ok then
         Clear_Curve_Material;
         return Status_Value;
      end if;
      Item.Keys_Derived := True;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Install_Derived_Keys
          (Kex_State,
           Negotiated_Item,
           Exchange_Digest,
           Derivation_Digest,
           Derived_Item);
      if Status_Value /= Ok then
         Clear_Curve_Material;
         return Status_Value;
      end if;
      Item.Kex_Complete := True;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Key_Exchange_Packet
          (Transcript, SSH_Lib.Protocol.Encrypted_State.Encode_Newkeys);
      if Status_Value /= Ok then
         Clear_Curve_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Send_Newkeys (Kex_State);
      if Status_Value /= Ok then
         Clear_Curve_Material;
         return Status_Value;
      end if;
      Item.Newkeys_Sent := True;
      Item.Encrypted_Outbound_Active := True;

      Status_Value :=
        Read_Non_Ignorable_Key_Exchange_Packet (Transcript, Kex_Reply_Payload);
      if Status_Value /= Ok then
         Clear_Curve_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Receive_Newkeys
          (Kex_State, SSH_Lib.Protocol.Buffers.To_Array (Kex_Reply_Payload));
      if Status_Value /= Ok then
         Clear_Curve_Material;
         return Status_Value;
      end if;
      Item.Newkeys_Received := True;
      Item.Encrypted_Inbound_Active := True;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Install_Protected_Keys
          (Transcript,
           To_String (Negotiated_Item.Cipher_Client_To_Server),
           To_String (Negotiated_Item.Cipher_Server_To_Client),
           To_String (Negotiated_Item.Mac_Client_To_Server),
           To_String (Negotiated_Item.Mac_Server_To_Client),
           To_String (Negotiated_Item.Compression_Client_To_Server),
           To_String (Negotiated_Item.Compression_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Integrity_Key_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Integrity_Key_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Encryption_Key_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Initial_IV_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Encryption_Key_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Initial_IV_Server_To_Client));
      if Status_Value /= Ok then
         Clear_Curve_Material;
         return Status_Value;
      end if;

      Clear_Curve_Material;
      return Ok;
   exception
      when others =>
         Clear_Curve_Material;
         SSH_Lib.Protocol.Buffers.Clear (Session_Identifier);
         SSH_Lib.Protocol.Buffers.Clear (Host_Key_Blob);
         return Internal_Error;
   end Run_Curve25519_Kex;

   function Run_ECDH_Nistp256_Kex
     (Transcript                     :
        in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Item                           : in out Session;
      Client_Kexinit                 : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit                 : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Negotiated_Item                :
        SSH_Lib.Protocol.Kex.Negotiated_Algorithms;
      Established_Session_Identifier : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Session_Identifier             :
        out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Host_Key_Blob                  :
        out SSH_Lib.Protocol.Buffers.Packet_Buffer) return Status
   is
      Source_Item          : CryptoLib.Random.Random_Source;
      Client_Private_Array : Stream_Element_Array (1 .. 32) := [others => 0];
      Client_Public_Array  : Stream_Element_Array (1 .. 65) := [others => 0];
      Shared_Secret_Array  : Stream_Element_Array (1 .. 32) := [others => 0];
      Kex_Init_Payload     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Kex_Reply_Payload    : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Item           : SSH_Lib.Protocol.Kexdh.Reply;
      Exchange_Digest      : SSH_Lib.Protocol.Exchange_Hash.Exchange_Digest;
      Derivation_Digest    : CryptoLib.Hashes.SHA256_Digest;
      Derived_Item         : SSH_Lib.Protocol.Session_Keys.Derived_Keys;
      Kex_State            : SSH_Lib.Protocol.Encrypted_State.Kex_State;
      Status_Value         : Status;

      procedure Clear_ECDH_Material is
      begin
         Client_Private_Array := [others => 0];
         Client_Public_Array := [others => 0];
         Shared_Secret_Array := [others => 0];
         SSH_Lib.Protocol.Buffers.Clear (Kex_Init_Payload);
         SSH_Lib.Protocol.Buffers.Clear (Kex_Reply_Payload);
         SSH_Lib.Protocol.Kexdh.Clear (Reply_Item);
         SSH_Lib.Protocol.Session_Keys.Clear (Derived_Item);
      exception
         when others =>
            null;
      end Clear_ECDH_Material;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Session_Identifier);
      SSH_Lib.Protocol.Buffers.Clear (Host_Key_Blob);
      if To_String (Negotiated_Item.Key_Exchange) /= "ecdh-sha2-nistp256" then
         Clear_ECDH_Material;
         return Unsupported_Feature;
      end if;

      CryptoLib.Random.Initialize_Production (Source_Item);
      Status_Value :=
        SSH_Lib.ECDSA.Generate_ECDH_Nistp256_Keypair
          (Source_Item, Client_Private_Array, Client_Public_Array);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Kexdh.Encode_ECDH_Nistp256_Init
          (Client_Public_Array, Kex_Init_Payload);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Key_Exchange_Packet
          (Transcript, SSH_Lib.Protocol.Buffers.To_Array (Kex_Init_Payload));
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        Read_Non_Ignorable_Key_Exchange_Packet (Transcript, Kex_Reply_Payload);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Kexdh.Parse_ECDH_Nistp256_Reply
          (SSH_Lib.Protocol.Buffers.To_Array (Kex_Reply_Payload), Reply_Item);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      declare
         Server_Public_Array : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Server_Public_Value);
      begin
         Status_Value :=
           SSH_Lib.ECDSA.Compute_ECDH_Nistp256_Shared_Secret
             (Client_Private_Array, Server_Public_Array, Shared_Secret_Array);
      end;
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Exchange_Hash.Compute_ECDH_SHA256
          (SSH_Lib.Sessions.Live_Transcript.Local_Identification (Transcript),
           SSH_Lib.Sessions.Live_Transcript.Remote_Identification (Transcript),
           Client_Kexinit,
           Server_Kexinit,
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
           Client_Public_Array,
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Server_Public_Value),
           Shared_Secret_Array,
           Exchange_Digest);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      SSH_Lib.Protocol.Encrypted_State.Reset (Kex_State);
      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Verify_And_Store
          (SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Signature_Blob),
           To_String (Negotiated_Item.Server_Host_Key),
           Digest_To_Array (Exchange_Digest),
           Kex_State);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;
      Item.Host_Key_Signature_Verified := True;

      if SSH_Lib.Protocol.Buffers.Length (Established_Session_Identifier) = 0
      then
         Derivation_Digest := Exchange_Digest;
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Set
             (Session_Identifier, Digest_To_Array (Exchange_Digest));
      else
         Status_Value :=
           Buffer_To_Digest
             (Established_Session_Identifier, Derivation_Digest);
         if Status_Value = Ok then
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Set
                (Session_Identifier,
                 SSH_Lib.Protocol.Buffers.To_Array
                   (Established_Session_Identifier));
         end if;
      end if;
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Set
          (Host_Key_Blob,
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob));
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Session_Keys.Derive_SHA256_Keys
          (Shared_Secret_Array,
           Exchange_Digest,
           Derivation_Digest,
           16,
           Maximum_Of
             (Cipher_Key_Length
                (To_String (Negotiated_Item.Cipher_Client_To_Server)),
              Cipher_Key_Length
                (To_String (Negotiated_Item.Cipher_Server_To_Client))),
           Maximum_Of
             (Mac_Key_Length
                (To_String (Negotiated_Item.Mac_Client_To_Server)),
              Mac_Key_Length
                (To_String (Negotiated_Item.Mac_Server_To_Client))),
           Derived_Item);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;
      Item.Keys_Derived := True;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Install_Derived_Keys
          (Kex_State,
           Negotiated_Item,
           Exchange_Digest,
           Derivation_Digest,
           Derived_Item);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;
      Item.Kex_Complete := True;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Key_Exchange_Packet
          (Transcript, SSH_Lib.Protocol.Encrypted_State.Encode_Newkeys);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Send_Newkeys (Kex_State);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;
      Item.Newkeys_Sent := True;
      Item.Encrypted_Outbound_Active := True;

      Status_Value :=
        Read_Non_Ignorable_Key_Exchange_Packet (Transcript, Kex_Reply_Payload);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Receive_Newkeys
          (Kex_State, SSH_Lib.Protocol.Buffers.To_Array (Kex_Reply_Payload));
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;
      Item.Newkeys_Received := True;
      Item.Encrypted_Inbound_Active := True;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Install_Protected_Keys
          (Transcript,
           To_String (Negotiated_Item.Cipher_Client_To_Server),
           To_String (Negotiated_Item.Cipher_Server_To_Client),
           To_String (Negotiated_Item.Mac_Client_To_Server),
           To_String (Negotiated_Item.Mac_Server_To_Client),
           To_String (Negotiated_Item.Compression_Client_To_Server),
           To_String (Negotiated_Item.Compression_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Integrity_Key_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Integrity_Key_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Encryption_Key_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Initial_IV_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Encryption_Key_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Initial_IV_Server_To_Client));
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Clear_ECDH_Material;
      return Ok;
   exception
      when others =>
         Clear_ECDH_Material;
         SSH_Lib.Protocol.Buffers.Clear (Session_Identifier);
         SSH_Lib.Protocol.Buffers.Clear (Host_Key_Blob);
         return Internal_Error;
   end Run_ECDH_Nistp256_Kex;

   function Run_ECDH_Nistp384_Kex
     (Transcript                     :
        in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Item                           : in out Session;
      Client_Kexinit                 : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit                 : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Negotiated_Item                :
        SSH_Lib.Protocol.Kex.Negotiated_Algorithms;
      Established_Session_Identifier : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Session_Identifier             :
        out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Host_Key_Blob                  :
        out SSH_Lib.Protocol.Buffers.Packet_Buffer) return Status
   is
      Source_Item              : CryptoLib.Random.Random_Source;
      Client_Private_Array     : Stream_Element_Array (1 .. 48) := [others => 0];
      Client_Public_Array      : Stream_Element_Array (1 .. 97) := [others => 0];
      Shared_Secret_Array      : Stream_Element_Array (1 .. 48) := [others => 0];
      Kex_Init_Payload         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Kex_Reply_Payload        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Item               : SSH_Lib.Protocol.Kexdh.Reply;
      Exchange_SHA384_Digest   :
        SSH_Lib.Protocol.Exchange_Hash.Exchange_SHA384_Digest;
      Derivation_SHA384_Digest : CryptoLib.Hashes.SHA384_Digest;
      Null_SHA256_Digest       :
        constant CryptoLib.Hashes.SHA256_Digest := [others => 0];
      Derived_Item             : SSH_Lib.Protocol.Session_Keys.Derived_Keys;
      Kex_State                : SSH_Lib.Protocol.Encrypted_State.Kex_State;
      Status_Value             : Status;

      procedure Clear_ECDH_Material is
      begin
         Client_Private_Array := [others => 0];
         Client_Public_Array := [others => 0];
         Shared_Secret_Array := [others => 0];
         SSH_Lib.Protocol.Buffers.Clear (Kex_Init_Payload);
         SSH_Lib.Protocol.Buffers.Clear (Kex_Reply_Payload);
         SSH_Lib.Protocol.Kexdh.Clear (Reply_Item);
         SSH_Lib.Protocol.Session_Keys.Clear (Derived_Item);
      exception
         when others =>
            null;
      end Clear_ECDH_Material;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Session_Identifier);
      SSH_Lib.Protocol.Buffers.Clear (Host_Key_Blob);
      if To_String (Negotiated_Item.Key_Exchange) /= "ecdh-sha2-nistp384" then
         Clear_ECDH_Material;
         return Unsupported_Feature;
      end if;

      CryptoLib.Random.Initialize_Production (Source_Item);
      Status_Value :=
        SSH_Lib.ECDSA.Generate_ECDH_Nistp384_Keypair
          (Source_Item, Client_Private_Array, Client_Public_Array);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Kexdh.Encode_ECDH_Nistp384_Init
          (Client_Public_Array, Kex_Init_Payload);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Key_Exchange_Packet
          (Transcript, SSH_Lib.Protocol.Buffers.To_Array (Kex_Init_Payload));
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        Read_Non_Ignorable_Key_Exchange_Packet (Transcript, Kex_Reply_Payload);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Kexdh.Parse_ECDH_Nistp384_Reply
          (SSH_Lib.Protocol.Buffers.To_Array (Kex_Reply_Payload), Reply_Item);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      declare
         Server_Public_Array : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Server_Public_Value);
      begin
         Status_Value :=
           SSH_Lib.ECDSA.Compute_ECDH_Nistp384_Shared_Secret
             (Client_Private_Array, Server_Public_Array, Shared_Secret_Array);
      end;
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Exchange_Hash.Compute_ECDH_Nistp384_SHA384
          (SSH_Lib.Sessions.Live_Transcript.Local_Identification (Transcript),
           SSH_Lib.Sessions.Live_Transcript.Remote_Identification (Transcript),
           Client_Kexinit,
           Server_Kexinit,
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
           Client_Public_Array,
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Server_Public_Value),
           Shared_Secret_Array,
           Exchange_SHA384_Digest);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      SSH_Lib.Protocol.Encrypted_State.Reset (Kex_State);
      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Verify_And_Store
          (SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Signature_Blob),
           To_String (Negotiated_Item.Server_Host_Key),
           Digest_To_Array (Exchange_SHA384_Digest),
           Kex_State);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;
      Item.Host_Key_Signature_Verified := True;

      if SSH_Lib.Protocol.Buffers.Length (Established_Session_Identifier) = 0
      then
         Derivation_SHA384_Digest := Exchange_SHA384_Digest;
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Set
             (Session_Identifier, Digest_To_Array (Exchange_SHA384_Digest));
      else
         Status_Value :=
           Buffer_To_SHA384_Digest
             (Established_Session_Identifier, Derivation_SHA384_Digest);
         if Status_Value = Ok then
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Set
                (Session_Identifier,
                 SSH_Lib.Protocol.Buffers.To_Array
                   (Established_Session_Identifier));
         end if;
      end if;
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Set
          (Host_Key_Blob,
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob));
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Session_Keys.Derive_SHA384_Keys
          (Shared_Secret_Array,
           Exchange_SHA384_Digest,
           Derivation_SHA384_Digest,
           16,
           Maximum_Of
             (Cipher_Key_Length
                (To_String (Negotiated_Item.Cipher_Client_To_Server)),
              Cipher_Key_Length
                (To_String (Negotiated_Item.Cipher_Server_To_Client))),
           Maximum_Of
             (Mac_Key_Length
                (To_String (Negotiated_Item.Mac_Client_To_Server)),
              Mac_Key_Length
                (To_String (Negotiated_Item.Mac_Server_To_Client))),
           Derived_Item);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;
      Item.Keys_Derived := True;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Install_Derived_Keys
          (Kex_State,
           Negotiated_Item,
           Null_SHA256_Digest,
           Null_SHA256_Digest,
           Derived_Item);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;
      Item.Kex_Complete := True;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Key_Exchange_Packet
          (Transcript, SSH_Lib.Protocol.Encrypted_State.Encode_Newkeys);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Send_Newkeys (Kex_State);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;
      Item.Newkeys_Sent := True;
      Item.Encrypted_Outbound_Active := True;

      Status_Value :=
        Read_Non_Ignorable_Key_Exchange_Packet (Transcript, Kex_Reply_Payload);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Receive_Newkeys
          (Kex_State, SSH_Lib.Protocol.Buffers.To_Array (Kex_Reply_Payload));
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;
      Item.Newkeys_Received := True;
      Item.Encrypted_Inbound_Active := True;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Install_Protected_Keys
          (Transcript,
           To_String (Negotiated_Item.Cipher_Client_To_Server),
           To_String (Negotiated_Item.Cipher_Server_To_Client),
           To_String (Negotiated_Item.Mac_Client_To_Server),
           To_String (Negotiated_Item.Mac_Server_To_Client),
           To_String (Negotiated_Item.Compression_Client_To_Server),
           To_String (Negotiated_Item.Compression_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Integrity_Key_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Integrity_Key_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Encryption_Key_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Initial_IV_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Encryption_Key_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Initial_IV_Server_To_Client));
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Clear_ECDH_Material;
      return Ok;
   exception
      when others =>
         Clear_ECDH_Material;
         SSH_Lib.Protocol.Buffers.Clear (Session_Identifier);
         SSH_Lib.Protocol.Buffers.Clear (Host_Key_Blob);
         return Internal_Error;
   end Run_ECDH_Nistp384_Kex;

   function Run_ECDH_Nistp521_Kex
     (Transcript                     :
        in out SSH_Lib.Sessions.Live_Transcript.Driver;
      Item                           : in out Session;
      Client_Kexinit                 : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit                 : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Negotiated_Item                :
        SSH_Lib.Protocol.Kex.Negotiated_Algorithms;
      Established_Session_Identifier : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Session_Identifier             :
        out SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Host_Key_Blob                  :
        out SSH_Lib.Protocol.Buffers.Packet_Buffer) return Status
   is
      Source_Item              : CryptoLib.Random.Random_Source;
      Client_Private_Array     : Stream_Element_Array (1 .. 66) := [others => 0];
      Client_Public_Array      : Stream_Element_Array (1 .. 133) := [others => 0];
      Shared_Secret_Array      : Stream_Element_Array (1 .. 66) := [others => 0];
      Kex_Init_Payload         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Kex_Reply_Payload        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Item               : SSH_Lib.Protocol.Kexdh.Reply;
      Exchange_SHA512_Digest   :
        SSH_Lib.Protocol.Exchange_Hash.Exchange_SHA512_Digest;
      Derivation_SHA512_Digest : CryptoLib.Hashes.SHA512_Digest;
      Null_SHA256_Digest       :
        constant CryptoLib.Hashes.SHA256_Digest := [others => 0];
      Derived_Item             : SSH_Lib.Protocol.Session_Keys.Derived_Keys;
      Kex_State                : SSH_Lib.Protocol.Encrypted_State.Kex_State;
      Status_Value             : Status;

      procedure Clear_ECDH_Material is
      begin
         Client_Private_Array := [others => 0];
         Client_Public_Array := [others => 0];
         Shared_Secret_Array := [others => 0];
         SSH_Lib.Protocol.Buffers.Clear (Kex_Init_Payload);
         SSH_Lib.Protocol.Buffers.Clear (Kex_Reply_Payload);
         SSH_Lib.Protocol.Kexdh.Clear (Reply_Item);
         SSH_Lib.Protocol.Session_Keys.Clear (Derived_Item);
      exception
         when others =>
            null;
      end Clear_ECDH_Material;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Session_Identifier);
      SSH_Lib.Protocol.Buffers.Clear (Host_Key_Blob);
      if To_String (Negotiated_Item.Key_Exchange) /= "ecdh-sha2-nistp521" then
         Clear_ECDH_Material;
         return Unsupported_Feature;
      end if;

      CryptoLib.Random.Initialize_Production (Source_Item);
      Status_Value :=
        SSH_Lib.ECDSA.Generate_ECDH_Nistp521_Keypair
          (Source_Item, Client_Private_Array, Client_Public_Array);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Kexdh.Encode_ECDH_Nistp521_Init
          (Client_Public_Array, Kex_Init_Payload);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Key_Exchange_Packet
          (Transcript, SSH_Lib.Protocol.Buffers.To_Array (Kex_Init_Payload));
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        Read_Non_Ignorable_Key_Exchange_Packet (Transcript, Kex_Reply_Payload);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Kexdh.Parse_ECDH_Nistp521_Reply
          (SSH_Lib.Protocol.Buffers.To_Array (Kex_Reply_Payload), Reply_Item);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      declare
         Server_Public_Array : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Server_Public_Value);
      begin
         Status_Value :=
           SSH_Lib.ECDSA.Compute_ECDH_Nistp521_Shared_Secret
             (Client_Private_Array, Server_Public_Array, Shared_Secret_Array);
      end;
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Exchange_Hash.Compute_ECDH_Nistp521_SHA512
          (SSH_Lib.Sessions.Live_Transcript.Local_Identification (Transcript),
           SSH_Lib.Sessions.Live_Transcript.Remote_Identification (Transcript),
           Client_Kexinit,
           Server_Kexinit,
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
           Client_Public_Array,
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Server_Public_Value),
           Shared_Secret_Array,
           Exchange_SHA512_Digest);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      SSH_Lib.Protocol.Encrypted_State.Reset (Kex_State);
      Status_Value :=
        SSH_Lib.Protocol.Host_Keys.Verify_And_Store
          (SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob),
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Signature_Blob),
           To_String (Negotiated_Item.Server_Host_Key),
           Digest_To_Array (Exchange_SHA512_Digest),
           Kex_State);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;
      Item.Host_Key_Signature_Verified := True;

      if SSH_Lib.Protocol.Buffers.Length (Established_Session_Identifier) = 0
      then
         Derivation_SHA512_Digest := Exchange_SHA512_Digest;
         Status_Value :=
           SSH_Lib.Protocol.Buffers.Set
             (Session_Identifier, Digest_To_Array (Exchange_SHA512_Digest));
      else
         Status_Value :=
           Buffer_To_SHA512_Digest
             (Established_Session_Identifier, Derivation_SHA512_Digest);
         if Status_Value = Ok then
            Status_Value :=
              SSH_Lib.Protocol.Buffers.Set
                (Session_Identifier,
                 SSH_Lib.Protocol.Buffers.To_Array
                   (Established_Session_Identifier));
         end if;
      end if;
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Set
          (Host_Key_Blob,
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Item.Host_Key_Blob));
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Session_Keys.Derive_SHA512_Keys
          (Shared_Secret_Array,
           Exchange_SHA512_Digest,
           Derivation_SHA512_Digest,
           16,
           Maximum_Of
             (Cipher_Key_Length
                (To_String (Negotiated_Item.Cipher_Client_To_Server)),
              Cipher_Key_Length
                (To_String (Negotiated_Item.Cipher_Server_To_Client))),
           Maximum_Of
             (Mac_Key_Length
                (To_String (Negotiated_Item.Mac_Client_To_Server)),
              Mac_Key_Length
                (To_String (Negotiated_Item.Mac_Server_To_Client))),
           Derived_Item);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;
      Item.Keys_Derived := True;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Install_Derived_Keys
          (Kex_State,
           Negotiated_Item,
           Null_SHA256_Digest,
           Null_SHA256_Digest,
           Derived_Item);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;
      Item.Kex_Complete := True;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Key_Exchange_Packet
          (Transcript, SSH_Lib.Protocol.Encrypted_State.Encode_Newkeys);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Send_Newkeys (Kex_State);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;
      Item.Newkeys_Sent := True;
      Item.Encrypted_Outbound_Active := True;

      Status_Value :=
        Read_Non_Ignorable_Key_Exchange_Packet (Transcript, Kex_Reply_Payload);
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Encrypted_State.Receive_Newkeys
          (Kex_State, SSH_Lib.Protocol.Buffers.To_Array (Kex_Reply_Payload));
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;
      Item.Newkeys_Received := True;
      Item.Encrypted_Inbound_Active := True;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Install_Protected_Keys
          (Transcript,
           To_String (Negotiated_Item.Cipher_Client_To_Server),
           To_String (Negotiated_Item.Cipher_Server_To_Client),
           To_String (Negotiated_Item.Mac_Client_To_Server),
           To_String (Negotiated_Item.Mac_Server_To_Client),
           To_String (Negotiated_Item.Compression_Client_To_Server),
           To_String (Negotiated_Item.Compression_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Integrity_Key_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Integrity_Key_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Encryption_Key_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Initial_IV_Client_To_Server),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Encryption_Key_Server_To_Client),
           SSH_Lib.Protocol.Buffers.To_Array
             (Derived_Item.Initial_IV_Server_To_Client));
      if Status_Value /= Ok then
         Clear_ECDH_Material;
         return Status_Value;
      end if;

      Clear_ECDH_Material;
      return Ok;
   exception
      when others =>
         Clear_ECDH_Material;
         SSH_Lib.Protocol.Buffers.Clear (Session_Identifier);
         SSH_Lib.Protocol.Buffers.Clear (Host_Key_Blob);
         return Internal_Error;
   end Run_ECDH_Nistp521_Kex;

   type Proxy_Jump_Target is record
      Host  : Unbounded_String;
      Port  : Natural := 22;
      User  : Unbounded_String;
      Valid : Boolean := False;
   end record;

   function Split_Proxy_Jump_Chain
     (Value     : String;
      Prefix    : out Unbounded_String;
      Final_Hop : out Unbounded_String) return Boolean
   is
      Last_Comma         : Natural := 0;
      Inside_Brackets    : Boolean := False;
      Previous_Was_Comma : Boolean := False;
   begin
      Prefix := Null_Unbounded_String;
      Final_Hop := Null_Unbounded_String;

      if Value'Length = 0 then
         return False;
      end if;

      for Index_Value in Value'Range loop
         if Value (Index_Value) = Character'Val (0)
           or else Value (Index_Value) = Character'Val (10)
           or else Value (Index_Value) = Character'Val (13)
         then
            return False;
         elsif Value (Index_Value) = '[' then
            if Inside_Brackets then
               return False;
            end if;
            Inside_Brackets := True;
            Previous_Was_Comma := False;
         elsif Value (Index_Value) = ']' then
            if not Inside_Brackets then
               return False;
            end if;
            Inside_Brackets := False;
            Previous_Was_Comma := False;
         elsif Value (Index_Value) = ',' and then not Inside_Brackets then
            if Index_Value = Value'First
              or else Index_Value = Value'Last
              or else Previous_Was_Comma
            then
               return False;
            end if;
            Last_Comma := Index_Value;
            Previous_Was_Comma := True;
         else
            Previous_Was_Comma := False;
         end if;
      end loop;

      if Inside_Brackets then
         return False;
      end if;

      if Last_Comma = 0 then
         Final_Hop := To_Unbounded_String (Value);
      else
         Prefix := To_Unbounded_String (Value (Value'First .. Last_Comma - 1));
         Final_Hop :=
           To_Unbounded_String (Value (Last_Comma + 1 .. Value'Last));
      end if;

      return To_String (Final_Hop)'Length > 0;
   exception
      when others =>
         Prefix := Null_Unbounded_String;
         Final_Hop := Null_Unbounded_String;
         return False;
   end Split_Proxy_Jump_Chain;

   function Parse_Proxy_Jump (Value : String) return Proxy_Jump_Target is
      Result      : Proxy_Jump_Target;
      Text_First  : constant Positive := Value'First;
      Text_Last   : constant Natural := Value'Last;
      At_Index    : Natural := 0;
      Colon_Index : Natural := 0;

      function Parse_Port
        (First_Index : Positive;
         Last_Index  : Natural;
         Port_Value  : out Natural) return Boolean is
      begin
         Port_Value := 0;
         if Last_Index < First_Index then
            return False;
         end if;

         for Index_Value in First_Index .. Last_Index loop
            if Value (Index_Value) not in '0' .. '9' then
               return False;
            end if;
            Port_Value :=
              Port_Value
              * 10
              + Character'Pos (Value (Index_Value))
              - Character'Pos ('0');
            if Port_Value > 65535 then
               return False;
            end if;
         end loop;

         return Port_Value /= 0;
      end Parse_Port;
   begin
      if Value'Length = 0 then
         return Result;
      end if;

      for Index_Value in Value'Range loop
         if Value (Index_Value) = ',' then
            --  Parse_Proxy_Jump handles exactly one hop.  Multi-hop chains are
            --  split by Split_Proxy_Jump_Chain before this parser is called.
            return Result;
         elsif Value (Index_Value) = Character'Val (0)
           or else Value (Index_Value) = Character'Val (10)
           or else Value (Index_Value) = Character'Val (13)
         then
            return Result;
         elsif Value (Index_Value) = '@' then
            At_Index := Index_Value;
         end if;
      end loop;

      if Text_Last < Text_First then
         return Result;
      end if;

      declare
         Host_First : Positive := Text_First;
      begin
         if At_Index /= 0 then
            if At_Index = Text_First or else At_Index = Text_Last then
               return Result;
            end if;
            Result.User :=
              To_Unbounded_String (Value (Text_First .. At_Index - 1));
            Host_First := At_Index + 1;
         end if;

         if Value (Host_First) = '[' then
            declare
               Close_Index : Natural := 0;
               Port_Value  : Natural := 0;
            begin
               for Index_Value in Host_First + 1 .. Text_Last loop
                  if Value (Index_Value) = ']' then
                     Close_Index := Index_Value;
                     exit;
                  end if;
               end loop;

               if Close_Index = 0 or else Close_Index = Host_First + 1 then
                  return Result;
               end if;

               Result.Host :=
                 To_Unbounded_String
                   (Value (Host_First + 1 .. Close_Index - 1));

               if Close_Index = Text_Last then
                  null;
               elsif Close_Index + 1 < Text_Last
                 and then Value (Close_Index + 1) = ':'
               then
                  if not Parse_Port (Close_Index + 2, Text_Last, Port_Value)
                  then
                     return Result;
                  end if;
                  Result.Port := Port_Value;
               else
                  return Result;
               end if;
            end;
         else
            declare
               Colon_Count : Natural := 0;
            begin
               for Index_Value in Host_First .. Text_Last loop
                  if Value (Index_Value) = ':' then
                     Colon_Count := Colon_Count + 1;
                     Colon_Index := Index_Value;
                  end if;
               end loop;

               if Colon_Count = 0 then
                  Result.Host :=
                    To_Unbounded_String (Value (Host_First .. Text_Last));
               elsif Colon_Count = 1 then
                  if Colon_Index = Host_First or else Colon_Index = Text_Last
                  then
                     return Result;
                  end if;
                  Result.Host :=
                    To_Unbounded_String
                      (Value (Host_First .. Colon_Index - 1));
                  declare
                     Port_Value : Natural := 0;
                  begin
                     if not Parse_Port (Colon_Index + 1, Text_Last, Port_Value)
                     then
                        return Result;
                     end if;
                     Result.Port := Port_Value;
                  end;
               else
                  --  Unbracketed IPv6 literals are ambiguous with :port.
                  --  Require [addr] or [addr]:port just like OpenSSH syntax.
                  return Result;
               end if;
            end;
         end if;
      end;

      Result.Valid := To_String (Result.Host)'Length > 0;
      return Result;
   exception
      when others =>
         return
           (Host  => Null_Unbounded_String,
            Port  => 22,
            User  => Null_Unbounded_String,
            Valid => False);
   end Parse_Proxy_Jump;

   function Complete_Handshake_On_Transcript
     (Options        : Session_Options;
      Item           : in out Session;
      Transcript_Ptr :
        in out SSH_Lib.Sessions.Live_Attachment.Transcript_Access)
      return Status
   is
      Client_Kexinit             : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit             : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Negotiated_Item            : SSH_Lib.Protocol.Kex.Negotiated_Algorithms;
      Initial_Session_Identifier : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Session_Identifier         : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Host_Key_Blob              : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value               : Status;

      procedure Destroy_Transcript_With_Diagnostics is
      begin
         if Transcript_Ptr /= null then
            SSH_Lib.Sessions.Live_Transcript.Close (Transcript_Ptr.all);
            Item.Last_Proxy_Command_Diagnostic :=
              SSH_Lib.Sessions.Live_Transcript.Last_Proxy_Command_Diagnostics
                (Transcript_Ptr.all);
         end if;
         SSH_Lib.Sessions.Live_Attachment.Destroy (Transcript_Ptr);
      exception
         when others =>
            SSH_Lib.Sessions.Live_Attachment.Destroy (Transcript_Ptr);
      end Destroy_Transcript_With_Diagnostics;
   begin
      if Transcript_Ptr = null then
         return Internal_Error;
      end if;

      Item.Transport_Connected := True;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Identification
          (Transcript_Ptr.all);
      if Status_Value /= Ok then
         Destroy_Transcript_With_Diagnostics;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Read_Identification
          (Transcript_Ptr.all);
      if Status_Value /= Ok then
         Destroy_Transcript_With_Diagnostics;
         return Status_Value;
      end if;
      Item.Identification_Complete := True;

      Status_Value :=
        Exchange_Kexinit
          (Transcript_Ptr.all,
           Item,
           Client_Kexinit,
           Server_Kexinit,
           Negotiated_Item);
      if Status_Value /= Ok then
         Destroy_Transcript_With_Diagnostics;
         return Status_Value;
      end if;

      if CryptoLib.Hybrid_PQ_Kex.Is_OpenSSH_Hybrid_PQ_Kex_Name
           (To_String (Negotiated_Item.Key_Exchange))
      then
         Status_Value :=
           Run_Hybrid_PQ_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Initial_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      elsif To_String (Negotiated_Item.Key_Exchange) = "curve25519-sha256"
        or else
          To_String (Negotiated_Item.Key_Exchange)
          = "curve25519-sha256@libssh.org"
      then
         Status_Value :=
           Run_Curve25519_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Initial_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      elsif To_String (Negotiated_Item.Key_Exchange) = "ecdh-sha2-nistp256"
      then
         Status_Value :=
           Run_ECDH_Nistp256_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Initial_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      elsif To_String (Negotiated_Item.Key_Exchange) = "ecdh-sha2-nistp521"
      then
         Status_Value :=
           Run_ECDH_Nistp521_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Initial_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      elsif To_String (Negotiated_Item.Key_Exchange) = "ecdh-sha2-nistp384"
      then
         Status_Value :=
           Run_ECDH_Nistp384_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Initial_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      else
         Status_Value :=
           Run_Group14_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Initial_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      end if;

      if Status_Value /= Ok then
         Destroy_Transcript_With_Diagnostics;
         return Status_Value;
      end if;

      Status_Value :=
        Verify_Presented_Host_Key
          (Options,
           To_String (Negotiated_Item.Server_Host_Key),
           SSH_Lib.Protocol.Buffers.To_Array (Host_Key_Blob),
           Item);
      if Status_Value /= Ok then
         Destroy_Transcript_With_Diagnostics;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Set
          (Item.Live_Session_Identifier,
           SSH_Lib.Protocol.Buffers.To_Array (Session_Identifier));
      if Status_Value /= Ok then
         Destroy_Transcript_With_Diagnostics;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Live_Userauth.Authenticate
          (Transcript_Ptr.all,
           Options,
           SSH_Lib.Protocol.Buffers.To_Array (Session_Identifier),
           Item);
      if Status_Value /= Ok then
         Destroy_Transcript_With_Diagnostics;
         return Status_Value;
      end if;

      if not SSH_Lib.Sessions.Open_Guards.Success_Gates_Complete (Item) then
         Destroy_Transcript_With_Diagnostics;
         return
           SSH_Lib.Sessions.Open_Guards.Status_For_Incomplete_Gates (Item);
      end if;

      Item.Current_State := Opened;
      Item.Session_Open := True;
      Item.Session_Closed := False;
      Item.Failure_Status := Ok;
      Item.Session_Dirty := False;
      SSH_Lib.Sessions.Channel_Table.Reset (Item);

      Item.Live_Channel_IO_Enabled := True;
      Item.Live_Packets_Since_Rekey := 0;
      Item.Live_Bytes_Since_Rekey := 0;
      Item.Live_Rekey_Started := Ada.Calendar.Clock;
      Item.Live_Rekey_In_Progress := False;
      SSH_Lib.Sessions.Live_Transcript.Configure_Server_Alive
        (Transcript_Ptr.all,
         Options.Server_Alive_Interval,
         Options.Server_Alive_Count_Max);
      SSH_Lib.Sessions.Live_Attachment.Attach (Item, Transcript_Ptr);
      return Ok;
   exception
      when others =>
         Destroy_Transcript_With_Diagnostics;
         return Internal_Error;
   end Complete_Handshake_On_Transcript;

   function Open_Direct_TCPIP_Tunnel
     (Jump_Session     : in out Session;
      Target_Host      : String;
      Target_Port      : Natural;
      Inner_Transcript :
        in out SSH_Lib.Sessions.Live_Attachment.Transcript_Access)
      return Status
   is
      Local_Channel_Id    : Interfaces.Unsigned_32 := 0;
      Open_Payload        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Reply_Payload       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Confirmation        : SSH_Lib.Protocol.Channels.Open_Confirmation;
      Failure_Item        : SSH_Lib.Protocol.Channels.Open_Failure;
      Jump_Transcript     :
        constant SSH_Lib.Sessions.Live_Attachment.Transcript_Access :=
          SSH_Lib.Sessions.Live_Attachment.Transcript (Jump_Session);
      Remote_Channel_Open : Boolean := False;
      Status_Value        : Status;

      procedure Close_Remote_Tunnel_Quietly is
         Close_Payload : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      begin
         if Remote_Channel_Open and then Jump_Transcript /= null then
            Close_Payload :=
              SSH_Lib.Protocol.Channels.Encode_Channel_Close
                (Confirmation.Sender_Channel);
            if not SSH_Lib.Protocol.Buffers.Is_Empty (Close_Payload) then
               declare
                  Ignored_Status : constant Status :=
                    SSH_Lib.Sessions.Live_Transcript.Send_Protected_Packet
                      (Jump_Transcript.all,
                       SSH_Lib.Protocol.Buffers.To_Array (Close_Payload));
               begin
                  null;
               end;
            end if;
            Remote_Channel_Open := False;
         end if;
      exception
         when others =>
            Remote_Channel_Open := False;
      end Close_Remote_Tunnel_Quietly;
   begin
      if Jump_Transcript = null then
         return Connection_Failed;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Allocate
          (Jump_Session, Local_Channel_Id);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Open_Payload :=
        SSH_Lib.Protocol.Channels.Encode_Direct_TCPIP_Open
          (Local_Channel_Id, Target_Host, Target_Port);
      if SSH_Lib.Protocol.Buffers.Is_Empty (Open_Payload) then
         SSH_Lib.Sessions.Channel_Table.Release
           (Jump_Session, Local_Channel_Id);
         return Invalid_Host;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Send_Open_Payload
          (Jump_Session, Open_Payload);
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Release
           (Jump_Session, Local_Channel_Id);
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Channel_Table.Read_Open_Response
          (Jump_Session, Local_Channel_Id, Reply_Payload);
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Channel_Table.Release
           (Jump_Session, Local_Channel_Id);
         return Status_Value;
      end if;

      declare
         Reply_Data : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Reply_Payload);
      begin
         Status_Value :=
           SSH_Lib.Protocol.Channels.Parse_Channel_Open_Confirmation
             (Reply_Data, Local_Channel_Id, Confirmation);
         if Status_Value /= Ok then
            Status_Value :=
              SSH_Lib.Protocol.Channels.Parse_Channel_Open_Failure
                (Reply_Data, Local_Channel_Id, Failure_Item);
            SSH_Lib.Sessions.Channel_Table.Release
              (Jump_Session, Local_Channel_Id);
            return Channel_Open_Failed;
         end if;
         Remote_Channel_Open := True;
      end;

      Inner_Transcript := SSH_Lib.Sessions.Live_Attachment.Create;
      if Inner_Transcript = null then
         Close_Remote_Tunnel_Quietly;
         SSH_Lib.Sessions.Channel_Table.Release
           (Jump_Session, Local_Channel_Id);
         return Internal_Error;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Connect_Through_Jump
          (Inner_Transcript.all,
           Jump_Transcript,
           Local_Channel_Id,
           Confirmation.Sender_Channel,
           Own_Outer        => True,
           Read_Timeout_MS  => Jump_Session.Stored_Options.Read_Timeout_MS,
           Write_Timeout_MS => Jump_Session.Stored_Options.Write_Timeout_MS);
      if Status_Value /= Ok then
         Close_Remote_Tunnel_Quietly;
         SSH_Lib.Sessions.Live_Attachment.Destroy (Inner_Transcript);
         SSH_Lib.Sessions.Channel_Table.Release
           (Jump_Session, Local_Channel_Id);
         return Status_Value;
      end if;

      Remote_Channel_Open := False;

      --  The inner jump-backed transcript now owns the outer transcript and
      --  will close/free it when the public target session closes.  Detach
      --  the local jump session handle without closing to prevent double
      --  close or double free on later failure cleanup.
      SSH_Lib.Sessions.Live_Attachment.Detach_Without_Close (Jump_Session);

      return Ok;
   exception
      when others =>
         Close_Remote_Tunnel_Quietly;
         SSH_Lib.Sessions.Live_Attachment.Destroy (Inner_Transcript);
         if Local_Channel_Id /= 0 then
            SSH_Lib.Sessions.Channel_Table.Release
              (Jump_Session, Local_Channel_Id);
         end if;
         return Internal_Error;
   end Open_Direct_TCPIP_Tunnel;

   function Connect_And_Run_Handshake
     (Options : Session_Options; Item : in out Session) return Status
   is
      Transcript_Ptr : SSH_Lib.Sessions.Live_Attachment.Transcript_Access :=
        SSH_Lib.Sessions.Live_Attachment.Create;
      Status_Value   : Status;
   begin
      if Transcript_Ptr = null then
         return Internal_Error;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Connect
          (Transcript_Ptr.all,
           To_String (Options.Host),
           Options.Port,
           Options.Connect_Timeout_MS,
           Options.Read_Timeout_MS,
           Options.Write_Timeout_MS,
           To_String (Options.Address_Family),
           To_String (Options.Bind_Address),
           Options.TCP_Keep_Alive,
           To_String (Options.IP_QoS),
           To_String (Options.Bind_Interface));
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Live_Attachment.Destroy (Transcript_Ptr);
         return Status_Value;
      end if;

      return Complete_Handshake_On_Transcript (Options, Item, Transcript_Ptr);
   exception
      when others =>
         SSH_Lib.Sessions.Live_Attachment.Destroy (Transcript_Ptr);
         return Internal_Error;
   end Connect_And_Run_Handshake;

   function Connect_Through_Proxy_Command
     (Options : Session_Options; Item : in out Session) return Status
   is
      Transcript_Ptr : SSH_Lib.Sessions.Live_Attachment.Transcript_Access :=
        SSH_Lib.Sessions.Live_Attachment.Create;
      Target_Options : Session_Options := Options;
      Status_Value   : Status;
   begin
      if Transcript_Ptr = null then
         return Internal_Error;
      end if;

      Target_Options.Proxy_Command := Null_Unbounded_String;
      Target_Options.Proxy_Jump := Null_Unbounded_String;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Connect_Through_Proxy_Command
          (Transcript_Ptr.all,
           To_String (Options.Proxy_Command),
           To_String (Options.Host),
           Options.Port,
           To_String (Options.User),
           Options.Connect_Timeout_MS,
           Options.Read_Timeout_MS,
           Options.Write_Timeout_MS);
      Item.Last_Proxy_Command_Diagnostic :=
        SSH_Lib.Sessions.Live_Transcript.Last_Proxy_Command_Diagnostics
          (Transcript_Ptr.all);
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Live_Transcript.Close (Transcript_Ptr.all);
         Item.Last_Proxy_Command_Diagnostic :=
           SSH_Lib.Sessions.Live_Transcript.Last_Proxy_Command_Diagnostics
             (Transcript_Ptr.all);
         SSH_Lib.Sessions.Live_Attachment.Destroy (Transcript_Ptr);
         return Status_Value;
      end if;

      Status_Value :=
        Complete_Handshake_On_Transcript (Target_Options, Item, Transcript_Ptr);
      return Status_Value;
   exception
      when others =>
         SSH_Lib.Sessions.Live_Attachment.Destroy (Transcript_Ptr);
         return Internal_Error;
   end Connect_Through_Proxy_Command;

   function Connect_Through_Control_Master
     (Options      : Session_Options;
      Control_Path : String;
      Item         : in out Session)
      return Status
   is
      Transcript_Ptr : SSH_Lib.Sessions.Live_Attachment.Transcript_Access :=
        SSH_Lib.Sessions.Live_Attachment.Create;
      Target_Options : Session_Options := Options;
      Status_Value   : Status;
   begin
      if Transcript_Ptr = null then
         return Internal_Error;
      end if;

      Target_Options.Proxy_Command := Null_Unbounded_String;
      Target_Options.Proxy_Jump := Null_Unbounded_String;
      Target_Options.Control_Master := Null_Unbounded_String;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Connect_Through_Mux_Proxy
          (Transcript_Ptr.all,
           Control_Path,
           Options.Read_Timeout_MS,
           Options.Write_Timeout_MS);
      if Status_Value /= Ok then
         SSH_Lib.Sessions.Live_Attachment.Destroy (Transcript_Ptr);
         return Status_Value;
      end if;

      return Complete_Handshake_On_Transcript
        (Target_Options, Item, Transcript_Ptr);
   exception
      when others =>
         SSH_Lib.Sessions.Live_Attachment.Destroy (Transcript_Ptr);
         return Internal_Error;
   end Connect_Through_Control_Master;

   function Rekey (Item : in out Session) return Status is
      Transcript_Ptr     :
        constant SSH_Lib.Sessions.Live_Attachment.Transcript_Access :=
          SSH_Lib.Sessions.Live_Attachment.Transcript (Item);
      Client_Kexinit     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Negotiated_Item    : SSH_Lib.Protocol.Kex.Negotiated_Algorithms;
      Session_Identifier : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Host_Key_Blob      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value       : Status;
   begin
      if Item.Current_State /= Opened
        or else not Item.Session_Open
        or else Item.Session_Closed
        or else not Item.User_Authenticated
        or else Transcript_Ptr = null
      then
         return Connection_Failed;
      end if;

      if SSH_Lib.Protocol.Buffers.Length (Item.Live_Session_Identifier) /= 20
        and then
          SSH_Lib.Protocol.Buffers.Length (Item.Live_Session_Identifier) /= 32
        and then
          SSH_Lib.Protocol.Buffers.Length (Item.Live_Session_Identifier) /= 48
        and then
          SSH_Lib.Protocol.Buffers.Length (Item.Live_Session_Identifier) /= 64
      then
         Item.Session_Dirty := True;
         Item.Failure_Status := Handshake_Failed;
         return Handshake_Failed;
      end if;

      Status_Value :=
        Exchange_Kexinit
          (Transcript_Ptr.all,
           Item,
           Client_Kexinit,
           Server_Kexinit,
           Negotiated_Item);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      if CryptoLib.Hybrid_PQ_Kex.Is_OpenSSH_Hybrid_PQ_Kex_Name
           (To_String (Negotiated_Item.Key_Exchange))
      then
         Status_Value :=
           Run_Hybrid_PQ_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Item.Live_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      elsif To_String (Negotiated_Item.Key_Exchange) = "curve25519-sha256"
        or else
          To_String (Negotiated_Item.Key_Exchange)
          = "curve25519-sha256@libssh.org"
      then
         Status_Value :=
           Run_Curve25519_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Item.Live_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      elsif To_String (Negotiated_Item.Key_Exchange) = "ecdh-sha2-nistp256"
      then
         Status_Value :=
           Run_ECDH_Nistp256_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Item.Live_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      elsif To_String (Negotiated_Item.Key_Exchange) = "ecdh-sha2-nistp521"
      then
         Status_Value :=
           Run_ECDH_Nistp521_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Item.Live_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      elsif To_String (Negotiated_Item.Key_Exchange) = "ecdh-sha2-nistp384"
      then
         Status_Value :=
           Run_ECDH_Nistp384_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Item.Live_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      else
         Status_Value :=
           Run_Group14_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Item.Live_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      end if;

      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value :=
        Verify_Presented_Host_Key
          (Item.Stored_Options,
           To_String (Negotiated_Item.Server_Host_Key),
           SSH_Lib.Protocol.Buffers.To_Array (Host_Key_Blob),
           Item);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      --  Rekey must preserve the original session identifier.  The KEX
      --  helpers return the established identifier in Session_Identifier when
      --  an existing identifier was supplied; assert that invariant before
      --  replacing the local buffer.
      declare
         Returned_Identifier : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Session_Identifier);
         Stored_Identifier   : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Item.Live_Session_Identifier);
         Matches             : Boolean :=
           Returned_Identifier'Length = Stored_Identifier'Length;
      begin
         if Matches and then Returned_Identifier'Length > 0 then
            for Offset_Value in 0 .. Returned_Identifier'Length - 1 loop
               if Returned_Identifier
                    (Returned_Identifier'First
                     + Stream_Element_Offset (Offset_Value))
                 /= Stored_Identifier
                      (Stored_Identifier'First
                       + Stream_Element_Offset (Offset_Value))
               then
                  Matches := False;
                  exit;
               end if;
            end loop;
         end if;

         if not Matches then
            Item.Session_Dirty := True;
            Item.Failure_Status := Handshake_Failed;
            return Handshake_Failed;
         end if;
      end;

      Status_Value :=
        SSH_Lib.Protocol.Buffers.Set
          (Item.Live_Session_Identifier,
           SSH_Lib.Protocol.Buffers.To_Array (Session_Identifier));
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Item.Live_Rekey_Count := Item.Live_Rekey_Count + 1;
      Item.Live_Packets_Since_Rekey := 0;
      Item.Live_Bytes_Since_Rekey := 0;
      Item.Live_Rekey_Started := Ada.Calendar.Clock;
      Item.Session_Dirty := False;
      Item.Failure_Status := Ok;
      return Ok;
   exception
      when others =>
         Item.Session_Dirty := True;
         Item.Failure_Status := Internal_Error;
         return Internal_Error;
   end Rekey;

   function Rekey_With_Peer_Kexinit
     (Item           : in out Session;
      Server_Kexinit : SSH_Lib.Protocol.Buffers.Packet_Buffer) return Status
   is
      Transcript_Ptr     :
        constant SSH_Lib.Sessions.Live_Attachment.Transcript_Access :=
          SSH_Lib.Sessions.Live_Attachment.Transcript (Item);
      Source_Item        : CryptoLib.Random.Random_Source;
      Client_Item        : SSH_Lib.Protocol.Kexinit.Kexinit_Message;
      Server_Item        : SSH_Lib.Protocol.Kexinit.Kexinit_Message;
      Client_Kexinit     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Negotiated_Item    : SSH_Lib.Protocol.Kex.Negotiated_Algorithms;
      Session_Identifier : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Host_Key_Blob      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value       : Status;
   begin
      if Item.Current_State /= Opened
        or else not Item.Session_Open
        or else Item.Session_Closed
        or else not Item.User_Authenticated
        or else Transcript_Ptr = null
      then
         return Connection_Failed;
      end if;

      if SSH_Lib.Protocol.Buffers.Length (Item.Live_Session_Identifier) /= 20
        and then
          SSH_Lib.Protocol.Buffers.Length (Item.Live_Session_Identifier) /= 32
        and then
          SSH_Lib.Protocol.Buffers.Length (Item.Live_Session_Identifier) /= 64
      then
         Item.Session_Dirty := True;
         Item.Failure_Status := Handshake_Failed;
         return Handshake_Failed;
      end if;

      SSH_Lib.Protocol.Kex.Clear (Negotiated_Item);
      CryptoLib.Random.Initialize_Production (Source_Item);

      Status_Value :=
        SSH_Lib.Protocol.Kexinit.Construct_Client
          (Source_Item, Client_Item, Client_Kexinit);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value :=
        Apply_Configured_Kexinit_Preferences
          (Item.Stored_Options, Client_Item, Client_Kexinit);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Sessions.Live_Transcript.Send_Key_Exchange_Packet
          (Transcript_Ptr.all,
           SSH_Lib.Protocol.Buffers.To_Array (Client_Kexinit));
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.Protocol.Kexinit.Parse
          (SSH_Lib.Protocol.Buffers.To_Array (Server_Kexinit), Server_Item);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Item.Kexinit_Exchanged := True;
      Status_Value :=
        SSH_Lib.Protocol.Kex.Negotiate
          (Client_Item, Server_Item, Negotiated_Item);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value :=
        Discard_Wrong_First_Kex_Packet
          (Transcript_Ptr.all, Server_Item, Negotiated_Item);
      if Status_Value /= Ok then
         SSH_Lib.Protocol.Kex.Clear (Negotiated_Item);
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Item.Algorithms_Negotiated := True;

      if CryptoLib.Hybrid_PQ_Kex.Is_OpenSSH_Hybrid_PQ_Kex_Name
           (To_String (Negotiated_Item.Key_Exchange))
      then
         Status_Value :=
           Run_Hybrid_PQ_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Item.Live_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      elsif To_String (Negotiated_Item.Key_Exchange) = "curve25519-sha256"
        or else
          To_String (Negotiated_Item.Key_Exchange)
          = "curve25519-sha256@libssh.org"
      then
         Status_Value :=
           Run_Curve25519_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Item.Live_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      elsif To_String (Negotiated_Item.Key_Exchange) = "ecdh-sha2-nistp256"
      then
         Status_Value :=
           Run_ECDH_Nistp256_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Item.Live_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      elsif To_String (Negotiated_Item.Key_Exchange) = "ecdh-sha2-nistp521"
      then
         Status_Value :=
           Run_ECDH_Nistp521_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Item.Live_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      elsif To_String (Negotiated_Item.Key_Exchange) = "ecdh-sha2-nistp384"
      then
         Status_Value :=
           Run_ECDH_Nistp384_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Item.Live_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      else
         Status_Value :=
           Run_Group14_Kex
             (Transcript_Ptr.all,
              Item,
              Client_Kexinit,
              Server_Kexinit,
              Negotiated_Item,
              Item.Live_Session_Identifier,
              Session_Identifier,
              Host_Key_Blob);
      end if;

      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      Status_Value :=
        Verify_Presented_Host_Key
          (Item.Stored_Options,
           To_String (Negotiated_Item.Server_Host_Key),
           SSH_Lib.Protocol.Buffers.To_Array (Host_Key_Blob),
           Item);
      if Status_Value /= Ok then
         Item.Session_Dirty := True;
         Item.Failure_Status := Status_Value;
         return Status_Value;
      end if;

      declare
         Returned_Identifier : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Session_Identifier);
         Stored_Identifier   : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Item.Live_Session_Identifier);
         Matches             : Boolean :=
           Returned_Identifier'Length = Stored_Identifier'Length;
      begin
         if Matches and then Returned_Identifier'Length > 0 then
            for Offset_Value in 0 .. Returned_Identifier'Length - 1 loop
               if Returned_Identifier
                    (Returned_Identifier'First
                     + Stream_Element_Offset (Offset_Value))
                 /= Stored_Identifier
                      (Stored_Identifier'First
                       + Stream_Element_Offset (Offset_Value))
               then
                  Matches := False;
                  exit;
               end if;
            end loop;
         end if;

         if not Matches then
            Item.Session_Dirty := True;
            Item.Failure_Status := Handshake_Failed;
            return Handshake_Failed;
         end if;
      end;

      Item.Live_Rekey_Count := Item.Live_Rekey_Count + 1;
      Item.Live_Packets_Since_Rekey := 0;
      Item.Live_Bytes_Since_Rekey := 0;
      Item.Live_Rekey_Started := Ada.Calendar.Clock;
      Item.Session_Dirty := False;
      Item.Failure_Status := Ok;
      return Ok;
   exception
      when others =>
         Item.Session_Dirty := True;
         Item.Failure_Status := Internal_Error;
         return Internal_Error;
   end Rekey_With_Peer_Kexinit;

   function Connect_Through_Proxy_Jump
     (Options : Session_Options; Item : in out Session) return Status
   is
      Prefix_Jumps     : Unbounded_String;
      Final_Jump_Text  : Unbounded_String;
      Jump_Target      : Proxy_Jump_Target;
      Jump_Options     : Session_Options := Options;
      Target_Options   : Session_Options := Options;
      Jump_Session     : Session;
      Inner_Transcript : SSH_Lib.Sessions.Live_Attachment.Transcript_Access :=
        null;
      Status_Value     : Status;
   begin
      if not Split_Proxy_Jump_Chain
               (To_String (Options.Proxy_Jump), Prefix_Jumps, Final_Jump_Text)
      then
         return Invalid_Host;
      end if;

      Jump_Target := Parse_Proxy_Jump (To_String (Final_Jump_Text));
      if not Jump_Target.Valid then
         return Invalid_Host;
      end if;

      Jump_Options.Host := Jump_Target.Host;
      Jump_Options.Port := Jump_Target.Port;
      if To_String (Jump_Target.User)'Length > 0 then
         Jump_Options.User := Jump_Target.User;
      end if;
      Jump_Options.Proxy_Jump := Prefix_Jumps;
      Jump_Options.Proxy_Command := Null_Unbounded_String;

      Target_Options.Proxy_Jump := Null_Unbounded_String;
      Target_Options.Proxy_Command := Null_Unbounded_String;

      Status_Value := SSH_Lib.Sessions.Open (Jump_Options, Jump_Session);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        Open_Direct_TCPIP_Tunnel
          (Jump_Session,
           To_String (Options.Host),
           Options.Port,
           Inner_Transcript);
      if Status_Value /= Ok then
         declare
            Ignored_Close : constant Status :=
              SSH_Lib.Sessions.Close (Jump_Session);
         begin
            null;
         end;
         return Status_Value;
      end if;

      Status_Value :=
        Complete_Handshake_On_Transcript
          (Target_Options, Item, Inner_Transcript);
      if Status_Value /= Ok then
         declare
            Ignored_Close : constant Status :=
              SSH_Lib.Sessions.Close (Jump_Session);
         begin
            null;
         end;
         return Status_Value;
      end if;

      --  Ownership of the outer socket-backed transcript is transferred by
      --  reference to the inner jump-backed transcript.  Do not close the
      --  jump session here: closing the public target session will close the
      --  direct-tcpip channel and then the outer transport best-effort.
      return Ok;
   exception
      when others =>
         SSH_Lib.Sessions.Live_Attachment.Destroy (Inner_Transcript);
         return Internal_Error;
   end Connect_Through_Proxy_Jump;

end SSH_Lib.Sessions.Live_Transport;
