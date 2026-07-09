with Ada.Strings.Unbounded;
with Interfaces;
with Ada.Text_IO;
with Ada.Streams;
with SSH_Lib.Algorithms;
with SSH_Lib.Derive;
with CryptoLib.Hybrid_PQ_Kex;
with CryptoLib.Errors;
with SSH_Lib.Keys;
with SSH_Lib.Keys.Internal;
with SSH_Lib.Known_Hosts;
with SSH_Lib.Protocol.Algorithm_Guards;
with SSH_Lib.Protocol.Buffers;
with SSH_Lib.Protocol.Encrypted_State;
with SSH_Lib.Protocol.Exchange_Hash;
with SSH_Lib.Protocol.Host_Keys;
with SSH_Lib.Protocol.Kex;
with SSH_Lib.Protocol.Kexinit;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Session_Keys;
with SSH_Lib.Protocol.Signatures;
with SSH_Lib.Protocol.Protected_Packets;
with SSH_Lib.Tests.Assertions;

package body SSH_Lib.Tests.Fixtures.Algorithm_Security is

   use Ada.Strings.Unbounded;
   use type Ada.Streams.Stream_Element_Array;
   use type SSH_Lib.Algorithms.Support_Status;
   use type CryptoLib.Errors.Status;
   use type Interfaces.Unsigned_32;
   use type SSH_Lib.Protocol.Exchange_Hash.Exchange_Digest;

   Kex_List : constant String :=
     "mlkem768x25519-sha256,mlkem768x25519-sha512,"
     & "sntrup761x25519-sha512@openssh.com,sntrup761x25519-sha512,"
     & "curve25519-sha256,curve25519-sha256@libssh.org,"
     & "ecdh-sha2-nistp256,ecdh-sha2-nistp384,"
     & "ecdh-sha2-nistp521,diffie-hellman-group18-sha512,"
     & "diffie-hellman-group16-sha512,diffie-hellman-group14-sha256,"
     & "diffie-hellman-group-exchange-sha256,"
     & "diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,"
     & "ext-info-c,kex-strict-c-v00@openssh.com";

   Host_Key_List : constant String :=
     "ssh-ed25519-cert-v01@openssh.com,"
     & "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
     & "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
     & "ecdsa-sha2-nistp521-cert-v01@openssh.com,"
     & "rsa-sha2-512-cert-v01@openssh.com,"
     & "rsa-sha2-256-cert-v01@openssh.com,"
     & "ssh-rsa-cert-v01@openssh.com,"
     & "sk-ssh-ed25519-cert-v01@openssh.com,"
     & "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,ssh-ed25519,"
     & "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,"
     & "ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,"
     & "sk-ssh-ed25519@openssh.com,"
     & "sk-ecdsa-sha2-nistp256@openssh.com,ssh-rsa";

   Cipher_List : constant String :=
     "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,"
     & "aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,"
     & "aes256-cbc,aes192-cbc,aes128-cbc";

   Mac_List : constant String :=
     "umac-128-etm@openssh.com,umac-64-etm@openssh.com,"
     & "umac-128@openssh.com,umac-64@openssh.com,"
     & "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,"
     & "hmac-sha2-512,hmac-sha2-256,hmac-sha1-etm@openssh.com,"
     & "hmac-sha1,hmac-sha1-96-etm@openssh.com,hmac-sha1-96";

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   function Bytes_From_String (Value : String) return Ada.Streams.Stream_Element_Array is
      Result : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Value'Length));
   begin
      for Index_Value in Value'Range loop
         Result
           (Ada.Streams.Stream_Element_Offset
              (Index_Value - Value'First + 1)) :=
           Ada.Streams.Stream_Element (Character'Pos (Value (Index_Value)));
      end loop;
      return Result;
   end Bytes_From_String;

   function Host_Key_Blob
     (Algorithm_Name : String;
      Key_Bytes      : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Result       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String
              (Bytes_From_String (Algorithm_Name))));
      Check (Status_Value = CryptoLib.Errors.Ok,
             "host-key blob algorithm fixture encodes");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Key_Bytes)));
      Check (Status_Value = CryptoLib.Errors.Ok,
             "host-key blob key fixture encodes");
      return Result;
   end Host_Key_Blob;

   function SK_Ed25519_Host_Key_Blob
     (Key_Bytes : Ada.Streams.Stream_Element_Array;
      App_Text  : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Result       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String
              (Bytes_From_String ("sk-ssh-ed25519@openssh.com"))));
      Check (Status_Value = CryptoLib.Errors.Ok,
             "SK Ed25519 host-key algorithm fixture encodes");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Key_Bytes)));
      Check (Status_Value = CryptoLib.Errors.Ok,
             "SK Ed25519 host-key key fixture encodes");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String
              (Bytes_From_String (App_Text))));
      Check (Status_Value = CryptoLib.Errors.Ok,
             "SK Ed25519 host-key application fixture encodes");
      return Result;
   end SK_Ed25519_Host_Key_Blob;

   function SK_ECDSA_Nistp256_Host_Key_Blob
     (Point_Bytes : Ada.Streams.Stream_Element_Array;
      App_Text    : String)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Result       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String
              (Bytes_From_String ("sk-ecdsa-sha2-nistp256@openssh.com"))));
      Check (Status_Value = CryptoLib.Errors.Ok,
             "SK ECDSA host-key algorithm fixture encodes");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String
              (Bytes_From_String ("nistp256"))));
      Check (Status_Value = CryptoLib.Errors.Ok,
             "SK ECDSA host-key curve fixture encodes");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Point_Bytes)));
      Check (Status_Value = CryptoLib.Errors.Ok,
             "SK ECDSA host-key point fixture encodes");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String
              (Bytes_From_String (App_Text))));
      Check (Status_Value = CryptoLib.Errors.Ok,
             "SK ECDSA host-key application fixture encodes");
      return Result;
   end SK_ECDSA_Nistp256_Host_Key_Blob;

   function Signature_Blob
     (Algorithm_Name  : String;
      Signature_Bytes : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Result       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String
              (Bytes_From_String (Algorithm_Name))));
      Check (Status_Value = CryptoLib.Errors.Ok,
             "signature algorithm fixture encodes");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Signature_Bytes)));
      Check (Status_Value = CryptoLib.Errors.Ok,
             "signature bytes fixture encodes");
      return Result;
   end Signature_Blob;

   function Security_Key_Signature_Payload
     (Inner_Signature : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array
   is
      Result       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Inner_Signature)));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Protocol.Buffers.Append_Byte (Result, 1);
      end if;
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Protocol.Buffers.Append
           (Result, SSH_Lib.Protocol.Numbers.Encode_Uint32 (7));
      end if;
      Check (Status_Value = CryptoLib.Errors.Ok,
             "security-key signature payload fixture encodes");
      return SSH_Lib.Protocol.Buffers.To_Array (Result);
   end Security_Key_Signature_Payload;

   function RSA_Host_Key_Blob
     (Exponent_Bytes : Ada.Streams.Stream_Element_Array;
      Modulus_Bytes  : Ada.Streams.Stream_Element_Array)
      return SSH_Lib.Protocol.Buffers.Packet_Buffer
   is
      Result       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Buffers.Clear (Result);
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String
              (Bytes_From_String ("ssh-rsa"))));
      Check (Status_Value = CryptoLib.Errors.Ok,
             "RSA host-key blob algorithm fixture encodes");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Exponent_Bytes)));
      Check (Status_Value = CryptoLib.Errors.Ok,
             "RSA host-key blob exponent fixture encodes");
      Status_Value := SSH_Lib.Protocol.Buffers.Append
        (Result,
         SSH_Lib.Protocol.Buffers.To_Array
           (SSH_Lib.Protocol.Numbers.Encode_SSH_String (Modulus_Bytes)));
      Check (Status_Value = CryptoLib.Errors.Ok,
             "RSA host-key blob modulus fixture encodes");
      return Result;
   end RSA_Host_Key_Blob;

   procedure For_Each_Name_Assert_Supported
     (Class_Item : SSH_Lib.Algorithms.Algorithm_Class;
      List_Text  : String;
      Label_Text : String)
   is
      Start_Index : Positive := List_Text'First;
      Stop_Index  : Natural;
   begin
      if List_Text'Length = 0 then
         return;
      end if;

      loop
         Stop_Index := Start_Index;
         while Stop_Index <= List_Text'Last
           and then List_Text (Stop_Index) /= ','
         loop
            Stop_Index := Stop_Index + 1;
         end loop;

         declare
            Candidate : constant String := List_Text (Start_Index .. Stop_Index - 1);
         begin
            declare
               Support_Value : constant SSH_Lib.Algorithms.Support_Status :=
                 SSH_Lib.Algorithms.Support_For (Class_Item, Candidate);
            begin
               Check
                 (Support_Value = SSH_Lib.Algorithms.Available
                  or else Support_Value = SSH_Lib.Algorithms.Extension_Only,
                  Label_Text & " advertised only implemented algorithm or extension marker " & Candidate);
            end;
         end;

         exit when Stop_Index > List_Text'Last;
         Start_Index := Stop_Index + 1;
      end loop;
   end For_Each_Name_Assert_Supported;

   procedure Assert_Advertised_Algorithms_Are_Implemented is
      use SSH_Lib.Algorithms;
   begin
      for Class_Item in Algorithm_Class loop
         declare
            Advertised_Text : constant String := Advertised_Name_List (Class_Item);
         begin
            Check (Validate_Name_List (Advertised_Text),
                   "advertised algorithm list validates for "
                   & Algorithm_Class'Image (Class_Item));
            For_Each_Name_Assert_Supported
              (Class_Item, Advertised_Text, Algorithm_Class'Image (Class_Item));
         end;
      end loop;

      Check (Advertised_Name_List (Key_Exchange) = Kex_List,
             "implemented KEX algorithms plus RFC8308 ext-info-c marker are advertised");
      Check (Advertised_Name_List (Server_Host_Key) = Host_Key_List,
             "only implemented host-key algorithms are advertised");
      Check (Advertised_Name_List (Encryption_Client_To_Server) = Cipher_List,
             "only implemented ciphers are advertised client-to-server");
      Check (Advertised_Name_List (Encryption_Server_To_Client) = Cipher_List,
             "only implemented ciphers are advertised server-to-client");
      Check (Advertised_Name_List (Compression_Client_To_Server) = "none,zlib@openssh.com,zlib",
             "none, delayed zlib, and immediate zlib are advertised client-to-server");
      Check (Advertised_Name_List (Compression_Server_To_Client) = "none,zlib@openssh.com,zlib",
             "none, delayed zlib, and immediate zlib are advertised server-to-client");
   end Assert_Advertised_Algorithms_Are_Implemented;

   procedure Assert_Selection_Preserves_Client_Preference is
      Selected_Name : Unbounded_String;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Mac_Client_To_Server,
         Mac_List,
         "hmac-sha2-256-etm@openssh.com,hmac-sha2-512",
         Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "client preference selects EtM MAC before non-EtM fallback");
      Check (To_String (Selected_Name) = "hmac-sha2-256-etm@openssh.com",
             "client preference order selects the first mutually supported EtM MAC");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Mac_Client_To_Server,
         Mac_List,
         "hmac-sha2-256,hmac-sha2-512",
         Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "client preference selects hmac-sha2-512 before hmac-sha2-256");
      Check (To_String (Selected_Name) = "hmac-sha2-512",
             "client preference order is preserved during non-EtM MAC selection");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Encryption_Client_To_Server,
         Cipher_List,
         "aes128-ctr,aes256-ctr",
         Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "client preference selects aes256-ctr before server-preferred aes128-ctr");
      Check (To_String (Selected_Name) = "aes256-ctr",
             "client preference order is preserved during cipher selection");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Compression_Client_To_Server,
         "zlib@openssh.com,zlib,none",
         "zlib@openssh.com,zlib,none",
         Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "delayed zlib compression selected when both peers support it");
      Check (To_String (Selected_Name) = "zlib@openssh.com",
             "compression preference selects delayed zlib before immediate zlib and none");
   end Assert_Selection_Preserves_Client_Preference;

   procedure Assert_Unsupported_Intersections_Fail is
      Selected_Name : Unbounded_String;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Key_Exchange,
         "curve25519-sha256,curve25519-sha256@libssh.org",
         "curve25519-sha256@libssh.org", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "libssh Curve25519 alias intersects successfully");
      Check (To_String (Selected_Name) = "curve25519-sha256@libssh.org",
             "implemented KEX selection records libssh Curve25519 alias");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Key_Exchange,
         "diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
         "diffie-hellman-group-exchange-sha1", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "legacy GEX SHA-1 KEX intersects as final fallback");
      Check (To_String (Selected_Name) = "diffie-hellman-group-exchange-sha1",
             "legacy GEX SHA-1 fallback records selected KEX");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Key_Exchange,
         "diffie-hellman-group1-sha1",
         "diffie-hellman-group1-sha1", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "legacy group1 SHA-1 KEX intersects as final fallback");
      Check (To_String (Selected_Name) = "diffie-hellman-group1-sha1",
             "legacy group1 SHA-1 fallback records selected KEX");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Key_Exchange,
         Kex_List,
         "ecdh-sha2-nistp256", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "NIST P-256 ECDH KEX intersects successfully");
      Check (To_String (Selected_Name) = "ecdh-sha2-nistp256",
             "NIST P-256 ECDH success records selected KEX");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Key_Exchange,
         Kex_List,
         "ecdh-sha2-nistp384", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "NIST P-384 ECDH KEX intersects successfully");
      Check (To_String (Selected_Name) = "ecdh-sha2-nistp384",
             "NIST P-384 ECDH success records selected KEX");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Key_Exchange,
         Kex_List,
         "ecdh-sha2-nistp521", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "NIST P-521 ECDH KEX intersects successfully");
      Check (To_String (Selected_Name) = "ecdh-sha2-nistp521",
             "NIST P-521 ECDH success records selected KEX");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Key_Exchange,
         Kex_List,
         "ecdh-sha2-unknown", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "algorithm security", "server offers no supported KEX");
      Check (To_String (Selected_Name)'Length = 0,
             "unsupported ECDH offer leaves no selected KEX");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Key_Exchange,
         "ext-info-c", "ext-info-c", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "algorithm security", "RFC8308 ext-info-c marker is not selected as a key exchange");
      Check (To_String (Selected_Name)'Length = 0,
             "ext-info-c rejection leaves no selected KEX");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Server_Host_Key,
         "rsa-sha2-256", "ssh-ed25519", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "algorithm security", "server offers no supported host-key algorithm");
      Check (To_String (Selected_Name)'Length = 0,
             "unsupported host-key offer leaves no selected algorithm");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Key_Exchange,
         "diffie-hellman-group18-sha512", "diffie-hellman-group18-sha512", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "group18 SHA-512 KEX intersects successfully");
      Check (To_String (Selected_Name) = "diffie-hellman-group18-sha512",
             "group18 SHA-512 success records selected KEX");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Key_Exchange,
         "diffie-hellman-group16-sha512", "diffie-hellman-group16-sha512", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "group16 SHA-512 KEX intersects successfully");
      Check (To_String (Selected_Name) = "diffie-hellman-group16-sha512",
             "group16 SHA-512 success records selected KEX");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Key_Exchange,
         "diffie-hellman-group-exchange-sha256",
         "diffie-hellman-group-exchange-sha256", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "GEX SHA-256 KEX intersects successfully");
      Check (To_String (Selected_Name) = "diffie-hellman-group-exchange-sha256",
             "GEX SHA-256 success records selected KEX");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Key_Exchange,
         "curve25519-sha256", "curve25519-sha256", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "Curve25519 KEX intersects successfully");
      Check (To_String (Selected_Name) = "curve25519-sha256",
             "Curve25519 KEX success records selected algorithm");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Key_Exchange,
         "diffie-hellman-group14-sha1", "diffie-hellman-group14-sha1", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "group14 SHA-1 KEX intersects as final fallback");
      Check (To_String (Selected_Name) = "diffie-hellman-group14-sha1",
             "group14 SHA-1 fallback records selected KEX");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Server_Host_Key,
         Host_Key_List, Host_Key_List, Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "implemented host-key algorithm intersects successfully");
      Check (To_String (Selected_Name) = "ssh-ed25519-cert-v01@openssh.com",
             "implemented host-key selection records preferred Ed25519 cert");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Server_Host_Key,
         "ssh-ed25519", "ssh-ed25519", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "raw Ed25519 host-key algorithm intersects successfully");
      Check (To_String (Selected_Name) = "ssh-ed25519",
             "raw Ed25519 host-key selection records selected algorithm");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Encryption_Client_To_Server,
         Cipher_List, "chacha20-poly1305@openssh.com", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "chacha20-poly1305 AEAD cipher intersects successfully");
      Check (To_String (Selected_Name) = "chacha20-poly1305@openssh.com",
             "chacha20-poly1305 AEAD selection records preferred cipher");


      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Encryption_Client_To_Server,
         Cipher_List, "aes256-gcm@openssh.com,aes128-gcm@openssh.com", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "AES-GCM AEAD cipher intersects successfully");
      Check (To_String (Selected_Name) = "aes256-gcm@openssh.com",
             "AES-GCM AEAD selection records preferred GCM cipher");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Mac_Client_To_Server,
         "hmac-sha2-256", "hmac-md5", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "algorithm security", "server offers no supported MAC");
      Check (To_String (Selected_Name)'Length = 0,
             "unsupported MAC offer leaves no selected algorithm");

      Status_Value := SSH_Lib.Algorithms.Select_Algorithm
        (SSH_Lib.Algorithms.Compression_Client_To_Server,
         "zlib@openssh.com,zlib,none", "zlib@openssh.com", Selected_Name);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "server offers supported delayed compression");
      Check (To_String (Selected_Name) = "zlib@openssh.com",
             "delayed zlib is selectable after authenticated-boundary switching implementation");
   end Assert_Unsupported_Intersections_Fail;

   procedure Assert_Malformed_Or_Not_Advertised_Selection_Fails is
   begin
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Algorithm_Guards.Selected_Algorithm_Accepted
           (SSH_Lib.Algorithms.Mac_Client_To_Server,
            "hmac-sha2-256", "hmac-sha1"),
         CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "server-selected algorithm not advertised by client is rejected");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Algorithm_Guards.Selected_Algorithm_Accepted
           (SSH_Lib.Algorithms.Mac_Client_To_Server,
            "hmac-sha2-256,hmac-md5", "hmac-md5"),
         CryptoLib.Errors.Ok,
         "algorithm security", "hmac-md5 fallback is accepted when advertised by the client");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Algorithm_Guards.Selected_Algorithm_Accepted
           (SSH_Lib.Algorithms.Mac_Client_To_Server,
            "hmac-sha2-256,umac-64@openssh.com", "umac-64@openssh.com"),
         CryptoLib.Errors.Ok,
         "algorithm security", "client-to-server UMAC is accepted when advertised by the client");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Algorithm_Guards.Selected_Algorithm_Accepted
           (SSH_Lib.Algorithms.Mac_Server_To_Client,
            "hmac-sha2-256,umac-128-etm@openssh.com", "umac-128-etm@openssh.com"),
         CryptoLib.Errors.Ok,
         "algorithm security", "server-to-client UMAC-ETM is accepted when advertised by the client");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Algorithm_Guards.Selected_Algorithm_Accepted
           (SSH_Lib.Algorithms.Compression_Client_To_Server,
            "none", "zlib@openssh.com"),
         CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "compression selected outside client advertisement is rejected");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Algorithm_Guards.Selected_Algorithm_Accepted
           (SSH_Lib.Algorithms.Server_Host_Key,
            "sk-ssh-ed25519-cert-v01@openssh.com",
            "sk-ssh-ed25519-cert-v01@openssh.com"),
         CryptoLib.Errors.Ok,
         "algorithm security", "SK Ed25519 host certificate selection is accepted");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Algorithm_Guards.Selected_Algorithm_Accepted
           (SSH_Lib.Algorithms.Server_Host_Key,
            "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
            "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"),
         CryptoLib.Errors.Ok,
         "algorithm security", "SK ECDSA host certificate selection is accepted");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Algorithm_Guards.Kex_Reply_Consistent
           ("curve25519-sha256", "diffie-hellman-group14-sha256"),
         CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "KEX reply inconsistent with negotiated algorithm is rejected");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Algorithm_Guards.Kex_Reply_Consistent
           ("curve25519-sha256", "curve25519-sha256"),
         CryptoLib.Errors.Ok,
         "algorithm security", "matching implemented KEX reply algorithm is accepted by consistency guard");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Algorithm_Guards.Kex_Reply_Consistent
           ("sntrup761x25519-sha512@openssh.com",
            "sntrup761x25519-sha512@openssh.com"),
         CryptoLib.Errors.Ok,
         "algorithm security", "OpenSSH SNTRUP/X25519 hybrid KEX is accepted after PQ conformance gates");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Algorithm_Guards.Kex_Reply_Consistent
           ("sntrup761x25519-sha512",
            "sntrup761x25519-sha512"),
         CryptoLib.Errors.Ok,
         "algorithm security", "OpenSSH SNTRUP hybrid alias is accepted after PQ conformance gates");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Algorithm_Guards.Kex_Reply_Consistent
           ("mlkem768x25519-sha256", "mlkem768x25519-sha256"),
         CryptoLib.Errors.Ok,
         "algorithm security", "OpenSSH ML-KEM hybrid KEX is accepted after PQ conformance gates");

      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Algorithm_Guards.Kex_Reply_Consistent
           ("mlkem768x25519-sha512", "mlkem768x25519-sha512"),
         CryptoLib.Errors.Ok,
         "algorithm security", "OpenSSH ML-KEM SHA-512 hybrid KEX is accepted after PQ conformance gates");
   end Assert_Malformed_Or_Not_Advertised_Selection_Fails;

   procedure Assert_Weak_Algorithms_Rejected is
      use SSH_Lib.Algorithms;
   begin
      Check (Support_For (Key_Exchange, "diffie-hellman-group1-sha1") = Available,
             "legacy group1 KEX retained only as final interoperability fallback");
      Check (Support_For (Key_Exchange, "sntrup761x25519-sha512@openssh.com") = Available,
             "OpenSSH SNTRUP761/X25519 hybrid PQ KEX is selectable after conformance gates");
      Check (Support_For (Key_Exchange, "sntrup761x25519-sha512") = Available,
             "OpenSSH SNTRUP761/X25519 hybrid PQ KEX alias is selectable after conformance gates");
      Check (Support_For (Key_Exchange, "mlkem768x25519-sha256") = Available,
             "OpenSSH ML-KEM768/X25519 hybrid PQ KEX is selectable after conformance gates");
      Check (Support_For (Key_Exchange, "mlkem768x25519-sha512") = Available,
             "OpenSSH ML-KEM768/X25519 SHA-512 hybrid PQ KEX is selectable after conformance gates");
      Check (Support_For (Server_Host_Key, "ssh-ed25519-cert-v01@openssh.com") = Available,
             "Ed25519 host certificates are selectable");
      Check (Support_For (Server_Host_Key, "ecdsa-sha2-nistp256-cert-v01@openssh.com") = Available,
             "ECDSA P-256 host certificates are selectable");
      Check (Support_For (Server_Host_Key, "ecdsa-sha2-nistp384-cert-v01@openssh.com") = Available,
             "ECDSA P-384 host certificates are selectable");
      Check (Support_For (Server_Host_Key, "ecdsa-sha2-nistp521-cert-v01@openssh.com") = Available,
             "ECDSA P-521 host certificates are selectable");
      Check (Support_For (Server_Host_Key, "rsa-sha2-512-cert-v01@openssh.com") = Available,
             "RSA SHA-512 host certificates are selectable");
      Check (Support_For (Server_Host_Key, "rsa-sha2-256-cert-v01@openssh.com") = Available,
             "RSA SHA-256 host certificates are selectable");
      Check (Support_For (Server_Host_Key, "ssh-rsa-cert-v01@openssh.com") = Available,
             "legacy RSA SHA-1 host certificates are selectable as fallback");
      Check (Support_For (Server_Host_Key, "sk-ssh-ed25519-cert-v01@openssh.com") = Available,
             "SK Ed25519 host certificates are selectable");
      Check (Support_For (Server_Host_Key, "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com") = Available,
             "SK ECDSA host certificates are selectable");
      Check (Support_For (Server_Host_Key, "sk-ssh-ed25519@openssh.com") = Available,
             "raw SK Ed25519 host keys are selectable");
      Check (Support_For (Server_Host_Key, "sk-ecdsa-sha2-nistp256@openssh.com") = Available,
             "raw SK ECDSA host keys are selectable");
      Check (Contains_Name (Advertised_Name_List (Key_Exchange), "sntrup761x25519-sha512@openssh.com"),
             "OpenSSH SNTRUP hybrid PQ KEX is advertised after conformance gates");
      Check (Contains_Name (Advertised_Name_List (Key_Exchange), "mlkem768x25519-sha256"),
             "OpenSSH ML-KEM hybrid PQ KEX is advertised after conformance gates");
      Check (Contains_Name (Advertised_Name_List (Key_Exchange), "mlkem768x25519-sha512"),
             "OpenSSH ML-KEM SHA-512 hybrid PQ KEX is advertised after conformance gates");
      Check (CryptoLib.Hybrid_PQ_Kex.Client_Init_Total_Length
               ("mlkem768x25519-sha256") = 1216,
             "ML-KEM768/X25519 hybrid client init is PQ public key plus 32-byte X25519 key");
      Check (CryptoLib.Hybrid_PQ_Kex.Server_Reply_Total_Length
               ("mlkem768x25519-sha256") = 1120,
             "ML-KEM768/X25519 hybrid server reply is PQ ciphertext plus 32-byte X25519 key");
      Check (CryptoLib.Hybrid_PQ_Kex.Client_Init_Total_Length
               ("sntrup761x25519-sha512@openssh.com") = 1190,
             "SNTRUP761/X25519 hybrid client init is PQ public key plus 32-byte X25519 key");
      Check (CryptoLib.Hybrid_PQ_Kex.Server_Reply_Total_Length
               ("sntrup761x25519-sha512@openssh.com") = 1071,
             "SNTRUP761/X25519 hybrid server reply is PQ ciphertext plus 32-byte X25519 key");
      Check (Support_For (Key_Exchange, "ext-info-c") = Extension_Only,
             "RFC8308 ext-info-c is advertised as extension-only and never selected as KEX");
      Check (not Is_Supported (Key_Exchange, "ext-info-c"),
             "RFC8308 ext-info-c is not a selectable KEX algorithm");
      Check (Support_For (Server_Host_Key, "ssh-rsa") = Available,
             "legacy ssh-rsa SHA-1 host-key signatures retained as last-resort interoperability fallback");
      Check (Support_For (Encryption_Client_To_Server, "3des-cbc") = Available,
             "legacy 3des-cbc retained only as last-resort cipher interoperability fallback");
      Check (Support_For (Mac_Client_To_Server, "hmac-sha1") = Available,
             "hmac-sha1 retained only as last-resort MAC interoperability fallback");
      Check (Support_For (Mac_Client_To_Server, "hmac-sha1-96-etm@openssh.com") = Available,
             "hmac-sha1-96-etm retained only as truncated SHA-1 MAC interoperability fallback");
      Check (Support_For (Mac_Client_To_Server, "hmac-sha1-96") = Available,
             "hmac-sha1-96 retained only as truncated SHA-1 MAC interoperability fallback");
      Check (Support_For (Mac_Client_To_Server, "hmac-md5") = Available,
             "hmac-md5 retained only as last-resort MAC interoperability fallback");
      Check (Support_For (Mac_Client_To_Server, "hmac-md5-96") = Available,
             "hmac-md5-96 retained only as truncated MD5 MAC interoperability fallback");
      Check (Support_For (Mac_Client_To_Server, "umac-64@openssh.com") = Available,
             "umac-64 is available through the native Ada UMAC implementation");
      Check (Support_For (Mac_Client_To_Server, "umac-128@openssh.com") = Available,
             "umac-128 is available through the native Ada UMAC implementation");
      Check (Support_For (Mac_Client_To_Server, "umac-64-etm@openssh.com") = Available,
             "umac-64-etm is available through the native Ada UMAC implementation");
      Check (Support_For (Mac_Client_To_Server, "umac-128-etm@openssh.com") = Available,
             "umac-128-etm is available through the native Ada UMAC implementation");
      Check (Contains_Name (Advertised_Name_List (Mac_Client_To_Server), "umac-64@openssh.com"),
             "umac-64 is advertised after native Ada UMAC implementation");
      Check (Contains_Name (Advertised_Name_List (Mac_Client_To_Server), "umac-128@openssh.com"),
             "umac-128 is advertised after native Ada UMAC implementation");
      Check (Contains_Name (Advertised_Name_List (Mac_Client_To_Server), "umac-64-etm@openssh.com"),
             "umac-64-etm is advertised after native Ada UMAC implementation");
      Check (Contains_Name (Advertised_Name_List (Mac_Client_To_Server), "umac-128-etm@openssh.com"),
             "umac-128-etm is advertised after native Ada UMAC implementation");
      Check (Support_For (Mac_Server_To_Client, "umac-64@openssh.com") = Available,
             "server-to-client umac-64 is available");
      Check (Support_For (Mac_Server_To_Client, "umac-128-etm@openssh.com") = Available,
             "server-to-client umac-128-etm is available");
      Check (Contains_Name (Advertised_Name_List (Mac_Server_To_Client), "umac-64@openssh.com"),
             "server-to-client umac-64 is advertised");
      Check (Contains_Name (Advertised_Name_List (Mac_Server_To_Client), "umac-128-etm@openssh.com"),
             "server-to-client umac-128-etm is advertised");
      Check (Support_For (Compression_Client_To_Server, "zlib") = Available,
             "stateful zlib compression supported through Ada zlib dependency");
      Check (Support_For (Compression_Client_To_Server, "zlib@openssh.com") = Available,
             "delayed zlib compression supported with authenticated-boundary switching");
   end Assert_Weak_Algorithms_Rejected;


   procedure Assert_SHA256_Session_Key_Derivation is
      use Ada.Streams;
      Shared_Secret : constant Stream_Element_Array (1 .. 6) :=
        [1 => 16#00#, 2 => 16#0A#, 3 => 16#0D#,
         4 => 16#7F#, 5 => 16#80#, 6 => 16#FF#];
      Exchange_Hash : constant SSH_Lib.Protocol.Exchange_Hash.Exchange_Digest :=
        [1  => 16#11#, 2  => 16#22#, 3  => 16#33#, 4  => 16#44#,
         5  => 16#55#, 6  => 16#66#, 7  => 16#77#, 8  => 16#88#,
         9  => 16#99#, 10 => 16#AA#, 11 => 16#BB#, 12 => 16#CC#,
         13 => 16#DD#, 14 => 16#EE#, 15 => 16#F0#, 16 => 16#0F#,
         17 => 16#1E#, 18 => 16#2D#, 19 => 16#3C#, 20 => 16#4B#,
         21 => 16#5A#, 22 => 16#69#, 23 => 16#78#, 24 => 16#87#,
         25 => 16#96#, 26 => 16#A5#, 27 => 16#B4#, 28 => 16#C3#,
         29 => 16#D2#, 30 => 16#E1#, 31 => 16#F1#, 32 => 16#10#];
      Other_Session_Id : constant SSH_Lib.Protocol.Exchange_Hash.Exchange_Digest :=
        [1  => 16#10#, 2  => 16#F1#, 3  => 16#E1#, 4  => 16#D2#,
         5  => 16#C3#, 6  => 16#B4#, 7  => 16#A5#, 8  => 16#96#,
         9  => 16#87#, 10 => 16#78#, 11 => 16#69#, 12 => 16#5A#,
         13 => 16#4B#, 14 => 16#3C#, 15 => 16#2D#, 16 => 16#1E#,
         17 => 16#0F#, 18 => 16#F0#, 19 => 16#EE#, 20 => 16#DD#,
         21 => 16#CC#, 22 => 16#BB#, 23 => 16#AA#, 24 => 16#99#,
         25 => 16#88#, 26 => 16#77#, 27 => 16#66#, 28 => 16#55#,
         29 => 16#44#, 30 => 16#33#, 31 => 16#22#, 32 => 16#11#];
      Key_A        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Key_B        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Keys_Item    : SSH_Lib.Protocol.Session_Keys.Derived_Keys;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Key_A := SSH_Lib.Derive.Derive_SHA256
        (Shared_Secret, Exchange_Hash, Exchange_Hash, 'A', 40);
      Key_B := SSH_Lib.Derive.Derive_SHA256
        (Shared_Secret, Exchange_Hash, Exchange_Hash, 'B', 40);
      Check (SSH_Lib.Protocol.Buffers.Length (Key_A) = 40,
             "SHA-256 key derivation extends beyond one digest block");
      Check (SSH_Lib.Protocol.Buffers.To_Array (Key_A)
             /= SSH_Lib.Protocol.Buffers.To_Array (Key_B),
             "different SSH key derivation labels produce distinct keys");

      Key_B := SSH_Lib.Derive.Derive_SHA256
        (Shared_Secret, Exchange_Hash, Exchange_Hash, 'A', 40);
      Check (SSH_Lib.Protocol.Buffers.To_Array (Key_A)
             = SSH_Lib.Protocol.Buffers.To_Array (Key_B),
             "same SSH key derivation inputs produce same key stream");

      Key_B := SSH_Lib.Derive.Derive_SHA256
        (Shared_Secret, Exchange_Hash, Other_Session_Id, 'A', 40);
      Check (SSH_Lib.Protocol.Buffers.To_Array (Key_A)
             /= SSH_Lib.Protocol.Buffers.To_Array (Key_B),
             "different SSH session identifier changes key stream");

      Key_B := SSH_Lib.Derive.Derive_SHA256
        (Shared_Secret, Exchange_Hash, Exchange_Hash, 'A', 0);
      Check (SSH_Lib.Protocol.Buffers.Length (Key_B) = 0,
             "zero-length SHA-256 key derivation is empty");

      Status_Value := SSH_Lib.Protocol.Session_Keys.Derive_SHA256_Keys
        (Shared_Secret, Exchange_Hash, Exchange_Hash, 16, 16, 32, Keys_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "SHA-256 SSH session keys derive");
      Check (SSH_Lib.Protocol.Buffers.Length
               (Keys_Item.Initial_IV_Client_To_Server) = 16,
             "client-to-server IV length follows negotiated cipher");
      Check (SSH_Lib.Protocol.Buffers.Length
               (Keys_Item.Initial_IV_Server_To_Client) = 16,
             "server-to-client IV length follows negotiated cipher");
      Check (SSH_Lib.Protocol.Buffers.Length
               (Keys_Item.Encryption_Key_Client_To_Server) = 16,
             "client-to-server encryption key length follows negotiated cipher");
      Check (SSH_Lib.Protocol.Buffers.Length
               (Keys_Item.Encryption_Key_Server_To_Client) = 16,
             "server-to-client encryption key length follows negotiated cipher");
      Check (SSH_Lib.Protocol.Buffers.Length
               (Keys_Item.Integrity_Key_Client_To_Server) = 32,
             "client-to-server integrity key length follows negotiated MAC");
      Check (SSH_Lib.Protocol.Buffers.Length
               (Keys_Item.Integrity_Key_Server_To_Client) = 32,
             "server-to-client integrity key length follows negotiated MAC");
      Check (SSH_Lib.Protocol.Buffers.To_Array
               (Keys_Item.Initial_IV_Client_To_Server)
             /= SSH_Lib.Protocol.Buffers.To_Array
                  (Keys_Item.Initial_IV_Server_To_Client),
             "SSH session key labels separate IV directions");
      Check (SSH_Lib.Protocol.Buffers.To_Array
               (Keys_Item.Encryption_Key_Client_To_Server)
             /= SSH_Lib.Protocol.Buffers.To_Array
                  (Keys_Item.Encryption_Key_Server_To_Client),
             "SSH session key labels separate encryption directions");
      Check (SSH_Lib.Protocol.Buffers.To_Array
               (Keys_Item.Integrity_Key_Client_To_Server)
             /= SSH_Lib.Protocol.Buffers.To_Array
                  (Keys_Item.Integrity_Key_Server_To_Client),
             "SSH session key labels separate integrity directions");
   end Assert_SHA256_Session_Key_Derivation;


   procedure Assert_Encrypted_State_Newkeys_Transition is
      use Ada.Streams;
      Shared_Secret : constant Stream_Element_Array (1 .. 6) :=
        [1 => 16#00#, 2 => 16#0A#, 3 => 16#0D#,
         4 => 16#7F#, 5 => 16#80#, 6 => 16#FF#];
      Exchange_Hash : constant SSH_Lib.Protocol.Exchange_Hash.Exchange_Digest :=
        [1  => 16#11#, 2  => 16#22#, 3  => 16#33#, 4  => 16#44#,
         5  => 16#55#, 6  => 16#66#, 7  => 16#77#, 8  => 16#88#,
         9  => 16#99#, 10 => 16#AA#, 11 => 16#BB#, 12 => 16#CC#,
         13 => 16#DD#, 14 => 16#EE#, 15 => 16#F0#, 16 => 16#0F#,
         17 => 16#1E#, 18 => 16#2D#, 19 => 16#3C#, 20 => 16#4B#,
         21 => 16#5A#, 22 => 16#69#, 23 => 16#78#, 24 => 16#87#,
         25 => 16#96#, 26 => 16#A5#, 27 => 16#B4#, 28 => 16#C3#,
         29 => 16#D2#, 30 => 16#E1#, 31 => 16#F1#, 32 => 16#10#];
      Algorithms_Item : SSH_Lib.Protocol.Kex.Negotiated_Algorithms;
      Keys_Item       : SSH_Lib.Protocol.Session_Keys.Derived_Keys;
      State_Item      : SSH_Lib.Protocol.Encrypted_State.Kex_State;
      Status_Value    : CryptoLib.Errors.Status;
      Bad_Newkeys     : constant Stream_Element_Array (1 .. 1) := [1 => 42];
   begin
      Status_Value := SSH_Lib.Protocol.Session_Keys.Derive_SHA256_Keys
        (Shared_Secret, Exchange_Hash, Exchange_Hash, 16, 16, 32, Keys_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "encrypted-state fixture keys derive");

      SSH_Lib.Protocol.Encrypted_State.Reset (State_Item);
      Check (not SSH_Lib.Protocol.Encrypted_State.Kex_Complete (State_Item),
             "encrypted state reset starts before KEX completion");
      Status_Value := SSH_Lib.Protocol.Encrypted_State.Receive_Newkeys
        (State_Item, SSH_Lib.Protocol.Encrypted_State.Encode_Newkeys);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "server NEWKEYS before key install is rejected");

      Algorithms_Item.Cipher_Client_To_Server := To_Unbounded_String ("aes128-ctr");
      Algorithms_Item.Cipher_Server_To_Client := To_Unbounded_String ("aes128-ctr");
      Status_Value := SSH_Lib.Protocol.Encrypted_State.Install_Derived_Keys
        (State_Item, Algorithms_Item, Exchange_Hash, Exchange_Hash, Keys_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "derived keys install into encrypted state");
      Check (SSH_Lib.Protocol.Encrypted_State.Kex_Complete (State_Item),
             "encrypted state records KEX complete after key install");

      Status_Value := SSH_Lib.Protocol.Encrypted_State.Receive_Newkeys
        (State_Item, SSH_Lib.Protocol.Encrypted_State.Encode_Newkeys);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "server NEWKEYS before client NEWKEYS is rejected");

      Status_Value := SSH_Lib.Protocol.Encrypted_State.Send_Newkeys (State_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "client NEWKEYS activates outbound cipher");
      Check (SSH_Lib.Protocol.Encrypted_State.Newkeys_Sent (State_Item),
             "encrypted state records client NEWKEYS sent");
      Check (SSH_Lib.Protocol.Encrypted_State.Outbound_Encrypted_Active (State_Item),
             "client NEWKEYS activates outbound encryption");

      Status_Value := SSH_Lib.Protocol.Encrypted_State.Send_Newkeys (State_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "duplicate client NEWKEYS is rejected");
      Status_Value := SSH_Lib.Protocol.Encrypted_State.Receive_Newkeys
        (State_Item, Bad_Newkeys);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "unexpected NEWKEYS payload is rejected");

      Status_Value := SSH_Lib.Protocol.Encrypted_State.Receive_Newkeys
        (State_Item, SSH_Lib.Protocol.Encrypted_State.Encode_Newkeys);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "server NEWKEYS activates inbound cipher");
      Check (SSH_Lib.Protocol.Encrypted_State.Newkeys_Received (State_Item),
             "encrypted state records server NEWKEYS received");
      Check (SSH_Lib.Protocol.Encrypted_State.Inbound_Encrypted_Active (State_Item),
             "server NEWKEYS activates inbound encryption");
      Status_Value := SSH_Lib.Protocol.Encrypted_State.Receive_Newkeys
        (State_Item, SSH_Lib.Protocol.Encrypted_State.Encode_Newkeys);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "duplicate server NEWKEYS is rejected");

      Check (SSH_Lib.Protocol.Encrypted_State.Outbound_Sequence (State_Item) = 0
             and then SSH_Lib.Protocol.Encrypted_State.Inbound_Sequence (State_Item) = 0,
             "encrypted packet sequence counters start at zero after NEWKEYS");
      Status_Value := SSH_Lib.Protocol.Encrypted_State.Note_Outbound_Packet (State_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "outbound encrypted packet increments sequence");
      Status_Value := SSH_Lib.Protocol.Encrypted_State.Note_Inbound_Packet (State_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "inbound encrypted packet increments sequence");
      Check (SSH_Lib.Protocol.Encrypted_State.Outbound_Sequence (State_Item) = 1
             and then SSH_Lib.Protocol.Encrypted_State.Inbound_Sequence (State_Item) = 1,
             "encrypted packet sequence counters increment independently");

      SSH_Lib.Protocol.Encrypted_State.Set_Sequences_For_Test
        (State_Item, Interfaces.Unsigned_32'Last, Interfaces.Unsigned_32'Last);
      Status_Value := SSH_Lib.Protocol.Encrypted_State.Note_Outbound_Packet (State_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "outbound encrypted sequence wraps");
      Status_Value := SSH_Lib.Protocol.Encrypted_State.Note_Inbound_Packet (State_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "inbound encrypted sequence wraps");
      Check (SSH_Lib.Protocol.Encrypted_State.Outbound_Sequence (State_Item) = 0
             and then SSH_Lib.Protocol.Encrypted_State.Inbound_Sequence (State_Item) = 0,
             "encrypted packet sequence counters wrap modulo 2**32");
   end Assert_Encrypted_State_Newkeys_Transition;


   procedure Assert_Encrypted_State_Verified_Host_Key_Storage is
      use Ada.Streams;
      State_Item    : SSH_Lib.Protocol.Encrypted_State.Kex_State;
      Invalid_Key   : SSH_Lib.Keys.Public_Key;
      Valid_Key     : SSH_Lib.Keys.Public_Key;
      Stored_Key    : SSH_Lib.Keys.Public_Key;
      Host_Key_Blob : constant Stream_Element_Array :=
        [0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57,
         0, 0, 0, 32, 0, 10, 13, 127, 128, 255, 49, 56, 63, 70, 77,
         84, 91, 98, 105, 112, 119, 126, 133, 140, 147, 154, 161,
         168, 175, 182, 189, 196, 203, 210, 217, 224];
      Status_Value : CryptoLib.Errors.Status;
   begin
      SSH_Lib.Protocol.Encrypted_State.Reset (State_Item);
      Check (not SSH_Lib.Protocol.Encrypted_State.Has_Verified_Host_Key (State_Item),
             "encrypted state reset clears verified host key");

      Status_Value := SSH_Lib.Protocol.Encrypted_State.Store_Verified_Host_Key
        (State_Item, Invalid_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "invalid verified host key is rejected");
      Check (not SSH_Lib.Protocol.Encrypted_State.Has_Verified_Host_Key (State_Item),
             "invalid verified host key leaves encrypted state empty");

      Status_Value := SSH_Lib.Keys.Internal.Set_Public_Key
        (Valid_Key, "ssh-ed25519", Host_Key_Blob);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "verified host-key fixture initializes");
      Status_Value := SSH_Lib.Protocol.Encrypted_State.Store_Verified_Host_Key
        (State_Item, Valid_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "valid verified host key stores");
      Check (SSH_Lib.Protocol.Encrypted_State.Has_Verified_Host_Key (State_Item),
             "encrypted state records verified host key presence");

      Stored_Key := SSH_Lib.Protocol.Encrypted_State.Verified_Host_Key (State_Item);
      Check (SSH_Lib.Keys.Algorithm (Stored_Key) = "ssh-ed25519",
             "encrypted state preserves verified host key algorithm");
      Check (SSH_Lib.Keys.Internal.Raw_Blob (Stored_Key) = Host_Key_Blob,
             "encrypted state preserves verified host key blob bytes");

      SSH_Lib.Protocol.Encrypted_State.Reset (State_Item);
      Check (not SSH_Lib.Protocol.Encrypted_State.Has_Verified_Host_Key (State_Item),
             "encrypted state reset drops stored verified host key");
      Check (not SSH_Lib.Keys.Is_Valid
                   (SSH_Lib.Protocol.Encrypted_State.Verified_Host_Key (State_Item)),
             "encrypted state reset clears verified host key value");
   end Assert_Encrypted_State_Verified_Host_Key_Storage;


   procedure Assert_Host_Key_Parse_Ed25519_Invariants is
      use Ada.Streams;
      Key_Item       : SSH_Lib.Keys.Public_Key;
      Good_Key_Bytes : Stream_Element_Array (1 .. 32);
      Short_Key      : constant Stream_Element_Array (1 .. 31) := [others => 16#33#];
      Long_Key       : constant Stream_Element_Array (1 .. 33) := [others => 16#44#];
      Valid_Blob     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Bad_Blob       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value   : CryptoLib.Errors.Status;
   begin
      for Index_Value in Good_Key_Bytes'Range loop
         Good_Key_Bytes (Index_Value) :=
           Stream_Element ((Integer (Index_Value) * 7) mod 256);
      end loop;
      Good_Key_Bytes (1) := 16#00#;
      Good_Key_Bytes (2) := 16#0A#;
      Good_Key_Bytes (3) := 16#0D#;
      Good_Key_Bytes (4) := 16#7F#;
      Good_Key_Bytes (5) := 16#80#;
      Good_Key_Bytes (6) := 16#FF#;

      Valid_Blob := Host_Key_Blob ("ssh-ed25519", Good_Key_Bytes);
      Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
        (SSH_Lib.Protocol.Buffers.To_Array (Valid_Blob),
         "ssh-ed25519",
         Key_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "valid Ed25519 host key parses");
      Check (SSH_Lib.Keys.Algorithm (Key_Item) = "ssh-ed25519",
             "parsed Ed25519 host key records algorithm");
      Check (SSH_Lib.Keys.Internal.Raw_Blob (Key_Item)
             = SSH_Lib.Protocol.Buffers.To_Array (Valid_Blob),
             "parsed Ed25519 host key preserves raw blob");

      Bad_Blob := Host_Key_Blob ("rsa-sha2-256", Good_Key_Bytes);
      Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
        (SSH_Lib.Protocol.Buffers.To_Array (Bad_Blob),
         "ssh-ed25519",
         Key_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "algorithm security", "unsupported host key algorithm is rejected");
      Check (not SSH_Lib.Keys.Is_Valid (Key_Item),
             "unsupported host key parse clears previous key");

      Bad_Blob := Host_Key_Blob ("ssh-ed25519", Short_Key);
      Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
        (SSH_Lib.Protocol.Buffers.To_Array (Bad_Blob),
         "ssh-ed25519",
         Key_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "short Ed25519 host key is rejected");
      Check (not SSH_Lib.Keys.Is_Valid (Key_Item),
             "short Ed25519 parse leaves no key");

      Bad_Blob := Host_Key_Blob ("ssh-ed25519", Long_Key);
      Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
        (SSH_Lib.Protocol.Buffers.To_Array (Bad_Blob),
         "ssh-ed25519",
         Key_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "long Ed25519 host key is rejected");
      Check (not SSH_Lib.Keys.Is_Valid (Key_Item),
             "long Ed25519 parse leaves no key");

      declare
         SK_Blob          : SSH_Lib.Protocol.Buffers.Packet_Buffer;
         SK_Signature     : SSH_Lib.Protocol.Buffers.Packet_Buffer;
         Parsed_Signature : SSH_Lib.Protocol.Signatures.Parsed_Signature;
         SK_Ed25519_Inner : constant Stream_Element_Array (1 .. 64) :=
           [others => 16#A5#];
         SK_ECDSA_Inner   : constant Stream_Element_Array (1 .. 73) :=
           [1 => 16#00#, 2 => 16#00#, 3 => 16#00#, 4 => 16#21#,
            5 => 16#00#, 6 => 16#EA#, 7 => 16#3A#, 8 => 16#EB#,
            9 => 16#32#, 10 => 16#2E#, 11 => 16#3D#, 12 => 16#09#,
            13 => 16#4C#, 14 => 16#7F#, 15 => 16#13#, 16 => 16#AA#,
            17 => 16#5F#, 18 => 16#D8#, 19 => 16#D2#, 20 => 16#3F#,
            21 => 16#F7#, 22 => 16#D4#, 23 => 16#59#, 24 => 16#68#,
            25 => 16#CC#, 26 => 16#C2#, 27 => 16#7A#, 28 => 16#DF#,
            29 => 16#1F#, 30 => 16#65#, 31 => 16#70#, 32 => 16#C3#,
            33 => 16#E3#, 34 => 16#8A#, 35 => 16#69#, 36 => 16#36#,
            37 => 16#1B#, 38 => 16#00#, 39 => 16#00#, 40 => 16#00#,
            41 => 16#20#, 42 => 16#5F#, 43 => 16#B9#, 44 => 16#5B#,
            45 => 16#B4#, 46 => 16#77#, 47 => 16#CF#, 48 => 16#81#,
            49 => 16#7E#, 50 => 16#A2#, 51 => 16#A6#, 52 => 16#E9#,
            53 => 16#2F#, 54 => 16#CF#, 55 => 16#B2#, 56 => 16#53#,
            57 => 16#E8#, 58 => 16#C8#, 59 => 16#94#, 60 => 16#01#,
            61 => 16#5E#, 62 => 16#09#, 63 => 16#1E#, 64 => 16#7F#,
            65 => 16#F4#, 66 => 16#5A#, 67 => 16#E0#, 68 => 16#BC#,
            69 => 16#06#, 70 => 16#EB#, 71 => 16#E7#, 72 => 16#14#,
            73 => 16#FC#];
         SK_Ed25519_Signature_Bytes : constant Stream_Element_Array :=
           Security_Key_Signature_Payload (SK_Ed25519_Inner);
         SK_ECDSA_Signature_Bytes : constant Stream_Element_Array :=
           Security_Key_Signature_Payload (SK_ECDSA_Inner);
         ECDSA_Point      : constant Stream_Element_Array (1 .. 65) :=
           [1 => 16#04#,
            2 => 16#67#, 3 => 16#AC#, 4 => 16#AD#, 5 => 16#2D#,
            6 => 16#10#, 7 => 16#08#, 8 => 16#83#, 9 => 16#67#,
            10 => 16#76#, 11 => 16#CE#, 12 => 16#44#, 13 => 16#72#,
            14 => 16#0E#, 15 => 16#8A#, 16 => 16#C9#, 17 => 16#FA#,
            18 => 16#5A#, 19 => 16#50#, 20 => 16#10#, 21 => 16#74#,
            22 => 16#2C#, 23 => 16#15#, 24 => 16#6B#, 25 => 16#D2#,
            26 => 16#B8#, 27 => 16#5D#, 28 => 16#8B#, 29 => 16#31#,
            30 => 16#68#, 31 => 16#34#, 32 => 16#74#, 33 => 16#A2#,
            34 => 16#8D#, 35 => 16#E9#, 36 => 16#88#, 37 => 16#24#,
            38 => 16#F7#, 39 => 16#26#, 40 => 16#C9#, 41 => 16#F4#,
            42 => 16#B0#, 43 => 16#F5#, 44 => 16#88#, 45 => 16#A7#,
            46 => 16#41#, 47 => 16#9D#, 48 => 16#D9#, 49 => 16#E4#,
            50 => 16#A1#, 51 => 16#8D#, 52 => 16#F6#, 53 => 16#B8#,
            54 => 16#2A#, 55 => 16#DC#, 56 => 16#B7#, 57 => 16#0D#,
            58 => 16#0F#, 59 => 16#6D#, 60 => 16#D4#, 61 => 16#AB#,
            62 => 16#31#, 63 => 16#CA#, 64 => 16#CE#, 65 => 16#9D#];
      begin
         SK_Blob := SK_Ed25519_Host_Key_Blob (Good_Key_Bytes, "ssh:fixture");
         Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
           (SSH_Lib.Protocol.Buffers.To_Array (SK_Blob),
            "sk-ssh-ed25519@openssh.com",
            Key_Item);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "algorithm security", "valid SK Ed25519 host key parses");
         Check (SSH_Lib.Keys.Algorithm (Key_Item) = "sk-ssh-ed25519@openssh.com",
                "parsed SK Ed25519 host key records algorithm");

         SK_Signature := Signature_Blob
           ("sk-ssh-ed25519@openssh.com", SK_Ed25519_Signature_Bytes);
         Status_Value := SSH_Lib.Protocol.Signatures.Parse
           (SSH_Lib.Protocol.Buffers.To_Array (SK_Signature),
            "sk-ssh-ed25519@openssh.com",
            Parsed_Signature);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "algorithm security", "SK Ed25519 signature payload parses");
         Check (SSH_Lib.Protocol.Signatures.Algorithm (Parsed_Signature) =
                  "sk-ssh-ed25519@openssh.com",
                "SK Ed25519 signature parse records algorithm");

         SK_Blob := SK_Ed25519_Host_Key_Blob (Good_Key_Bytes, "https://example.invalid");
         Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
           (SSH_Lib.Protocol.Buffers.To_Array (SK_Blob),
            "sk-ssh-ed25519@openssh.com",
            Key_Item);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Handshake_Failed,
            "algorithm security", "non-SSH SK Ed25519 application string is rejected");
         Check (not SSH_Lib.Keys.Is_Valid (Key_Item),
                "rejected SK Ed25519 application string leaves no key");

         SK_Blob := SK_ECDSA_Nistp256_Host_Key_Blob (ECDSA_Point, "ssh:fixture");
         Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
           (SSH_Lib.Protocol.Buffers.To_Array (SK_Blob),
            "sk-ecdsa-sha2-nistp256@openssh.com",
            Key_Item);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "algorithm security", "valid SK ECDSA host key parses");
         Check (SSH_Lib.Keys.Algorithm (Key_Item) = "sk-ecdsa-sha2-nistp256@openssh.com",
                "parsed SK ECDSA host key records algorithm");

         SK_Signature := Signature_Blob
           ("sk-ecdsa-sha2-nistp256@openssh.com", SK_ECDSA_Signature_Bytes);
         Status_Value := SSH_Lib.Protocol.Signatures.Parse
           (SSH_Lib.Protocol.Buffers.To_Array (SK_Signature),
            "sk-ecdsa-sha2-nistp256@openssh.com",
            Parsed_Signature);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Ok,
            "algorithm security", "SK ECDSA signature payload parses");
         Check (SSH_Lib.Protocol.Signatures.Algorithm (Parsed_Signature) =
                  "sk-ecdsa-sha2-nistp256@openssh.com",
                "SK ECDSA signature parse records algorithm");

         SK_Blob := SK_ECDSA_Nistp256_Host_Key_Blob
           (ECDSA_Point, "https://example.invalid");
         Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
           (SSH_Lib.Protocol.Buffers.To_Array (SK_Blob),
            "sk-ecdsa-sha2-nistp256@openssh.com",
            Key_Item);
         SSH_Lib.Tests.Assertions.Check_Status
           (Status_Value, CryptoLib.Errors.Handshake_Failed,
            "algorithm security", "non-SSH SK ECDSA application string is rejected");
         Check (not SSH_Lib.Keys.Is_Valid (Key_Item),
                "rejected SK ECDSA application string leaves no key");
      end;

      declare
         Valid_Data : constant Stream_Element_Array :=
           SSH_Lib.Protocol.Buffers.To_Array (Valid_Blob);
      begin
         Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
           (Valid_Data (Valid_Data'First .. Valid_Data'Last - 1),
            "ssh-ed25519",
            Key_Item);
      end;
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "truncated Ed25519 host key blob is rejected");
      Check (not SSH_Lib.Keys.Is_Valid (Key_Item),
             "truncated Ed25519 parse leaves no key");
   end Assert_Host_Key_Parse_Ed25519_Invariants;


   procedure Assert_Host_Key_Parse_RSA_Invariants is
      use Ada.Streams;
      Key_Item        : SSH_Lib.Keys.Public_Key;
      RSA_Exponent    : constant Stream_Element_Array (1 .. 3) :=
        [1 => 16#01#, 2 => 16#00#, 3 => 16#01#];
      RSA_Modulus     : constant Stream_Element_Array (1 .. 5) :=
        [1 => 16#00#, 2 => 16#80#, 3 => 16#01#, 4 => 16#02#, 5 => 16#03#];
      RSA_Zero        : constant Stream_Element_Array (1 .. 1) := [1 => 0];
      RSA_Negative    : constant Stream_Element_Array (1 .. 1) := [1 => 16#80#];
      RSA_Nonminimal  : constant Stream_Element_Array (1 .. 2) :=
        [1 => 16#00#, 2 => 16#01#];
      Valid_Blob      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Bad_Blob        : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value    : CryptoLib.Errors.Status;
   begin
      Valid_Blob := RSA_Host_Key_Blob (RSA_Exponent, RSA_Modulus);
      Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
        (SSH_Lib.Protocol.Buffers.To_Array (Valid_Blob),
         "rsa-sha2-256",
         Key_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "valid RSA host key parses for rsa-sha2-256");
      Check (SSH_Lib.Keys.Algorithm (Key_Item) = "ssh-rsa",
             "parsed RSA host key records key format algorithm");
      Check (SSH_Lib.Keys.Internal.Raw_Blob (Key_Item)
             = SSH_Lib.Protocol.Buffers.To_Array (Valid_Blob),
             "parsed RSA host key preserves raw blob");

      Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
        (SSH_Lib.Protocol.Buffers.To_Array (Valid_Blob),
         "rsa-sha2-512",
         Key_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "valid RSA host key parses for rsa-sha2-512");
      Check (SSH_Lib.Keys.Algorithm (Key_Item) = "ssh-rsa",
             "rsa-sha2-512 parse preserves RSA key format algorithm");
      Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
        (SSH_Lib.Protocol.Buffers.To_Array (Valid_Blob),
         "ssh-rsa",
         Key_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "valid RSA host key parses for ssh-rsa fallback");
      Check (SSH_Lib.Keys.Algorithm (Key_Item) = "ssh-rsa",
             "ssh-rsa fallback parse records RSA key format algorithm");

      Bad_Blob := RSA_Host_Key_Blob (RSA_Zero, RSA_Modulus);
      Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
        (SSH_Lib.Protocol.Buffers.To_Array (Bad_Blob),
         "rsa-sha2-256",
         Key_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "zero RSA exponent is rejected");
      Check (not SSH_Lib.Keys.Is_Valid (Key_Item),
             "zero RSA exponent parse leaves no key");

      Bad_Blob := RSA_Host_Key_Blob (RSA_Exponent, RSA_Zero);
      Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
        (SSH_Lib.Protocol.Buffers.To_Array (Bad_Blob),
         "rsa-sha2-256",
         Key_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "zero RSA modulus is rejected");
      Check (not SSH_Lib.Keys.Is_Valid (Key_Item),
             "zero RSA modulus parse leaves no key");

      Bad_Blob := RSA_Host_Key_Blob (RSA_Negative, RSA_Modulus);
      Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
        (SSH_Lib.Protocol.Buffers.To_Array (Bad_Blob),
         "rsa-sha2-256",
         Key_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "negative RSA exponent is rejected");
      Check (not SSH_Lib.Keys.Is_Valid (Key_Item),
             "negative RSA exponent parse leaves no key");

      Bad_Blob := RSA_Host_Key_Blob (RSA_Exponent, RSA_Negative);
      Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
        (SSH_Lib.Protocol.Buffers.To_Array (Bad_Blob),
         "rsa-sha2-256",
         Key_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "negative RSA modulus is rejected");
      Check (not SSH_Lib.Keys.Is_Valid (Key_Item),
             "negative RSA modulus parse leaves no key");

      Bad_Blob := RSA_Host_Key_Blob (RSA_Nonminimal, RSA_Modulus);
      Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
        (SSH_Lib.Protocol.Buffers.To_Array (Bad_Blob),
         "rsa-sha2-256",
         Key_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "nonminimal RSA exponent is rejected");
      Check (not SSH_Lib.Keys.Is_Valid (Key_Item),
             "nonminimal RSA exponent parse leaves no key");
   end Assert_Host_Key_Parse_RSA_Invariants;


   procedure Assert_RSA_Known_Host_Material is
      use Ada.Streams;
      Key_Item        : SSH_Lib.Keys.Public_Key;
      Known_Host_Item : SSH_Lib.Known_Hosts.Host_Key;
      Known_Host_Copy : SSH_Lib.Known_Hosts.Host_Key;
      Fingerprint     : SSH_Lib.Keys.Fingerprint;
      RSA_Exponent    : constant Stream_Element_Array (1 .. 3) :=
        [1 => 16#01#, 2 => 16#00#, 3 => 16#01#];
      RSA_Modulus     : constant Stream_Element_Array (1 .. 6) :=
        [1 => 16#00#, 2 => 16#80#, 3 => 16#01#,
         4 => 16#02#, 5 => 16#03#, 6 => 16#04#];
      Valid_Blob      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value    : CryptoLib.Errors.Status;
   begin
      Valid_Blob := RSA_Host_Key_Blob (RSA_Exponent, RSA_Modulus);
      Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
        (SSH_Lib.Protocol.Buffers.To_Array (Valid_Blob),
         "rsa-sha2-512",
         Key_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "RSA known-host fixture key parses");

      Status_Value := SSH_Lib.Known_Hosts.From_Public_Key
        (Key_Item, Known_Host_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "RSA known-host material exports from parsed key");
      Check (SSH_Lib.Known_Hosts.Is_Valid (Known_Host_Item),
             "RSA known-host material exported from parsed key is valid");
      Check (SSH_Lib.Known_Hosts.Algorithm (Known_Host_Item) = "ssh-rsa",
             "RSA known-host material uses key format algorithm");
      Check (SSH_Lib.Known_Hosts.Encoded (Known_Host_Item)
             = "AAAAB3NzaC1yc2EAAAADAQABAAAABgCAAQIDBA==",
             "RSA known-host material preserves padded base64 encoding");

      Status_Value := SSH_Lib.Known_Hosts.SHA256_Fingerprint
        (Known_Host_Item, Fingerprint);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "RSA known-host fingerprint computes");
      Check (SSH_Lib.Keys.Image (Fingerprint)'Length > 7
             and then SSH_Lib.Keys.Image (Fingerprint) (1 .. 7) = "SHA256:",
             "RSA known-host fingerprint has SHA256 prefix");
      Check (SSH_Lib.Keys.Image (Fingerprint)
             (SSH_Lib.Keys.Image (Fingerprint)'Last) /= '=',
             "RSA known-host fingerprint omits base64 padding");

      Known_Host_Copy := SSH_Lib.Known_Hosts.Create_Host_Key
        ("ssh-ed25519", SSH_Lib.Known_Hosts.Encoded (Known_Host_Item));
      Check (not SSH_Lib.Known_Hosts.Is_Valid (Known_Host_Copy),
             "known-host constructor rejects RSA blob under Ed25519 label");
      Known_Host_Copy := SSH_Lib.Known_Hosts.Create_Host_Key
        ("rsa-sha2-512", SSH_Lib.Known_Hosts.Encoded (Known_Host_Item));
      Check (not SSH_Lib.Known_Hosts.Is_Valid (Known_Host_Copy),
             "known-host constructor rejects RSA signature algorithm as key format");
      Check (SSH_Lib.Known_Hosts.Algorithm (Known_Host_Copy) = ""
             and then SSH_Lib.Known_Hosts.Encoded (Known_Host_Copy) = "",
             "invalid RSA known-host constructor output is cleared");
   end Assert_RSA_Known_Host_Material;


   procedure Assert_Host_Key_Known_Host_Material is
      use Ada.Streams;
      Key_Item        : SSH_Lib.Keys.Public_Key;
      Known_Host_Item : SSH_Lib.Known_Hosts.Host_Key;
      Known_Host_Copy : SSH_Lib.Known_Hosts.Host_Key;
      Fingerprint_A   : SSH_Lib.Keys.Fingerprint;
      Fingerprint_B   : SSH_Lib.Keys.Fingerprint;
      Good_Key_Bytes  : Stream_Element_Array (1 .. 32);
      Valid_Blob      : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Status_Value    : CryptoLib.Errors.Status;
   begin
      for Index_Value in Good_Key_Bytes'Range loop
         Good_Key_Bytes (Index_Value) :=
           Stream_Element ((Integer (Index_Value) * 7) mod 256);
      end loop;
      Good_Key_Bytes (1) := 16#00#;
      Good_Key_Bytes (2) := 16#0A#;
      Good_Key_Bytes (3) := 16#0D#;
      Good_Key_Bytes (4) := 16#7F#;
      Good_Key_Bytes (5) := 16#80#;
      Good_Key_Bytes (6) := 16#FF#;

      Valid_Blob := Host_Key_Blob ("ssh-ed25519", Good_Key_Bytes);
      Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
        (SSH_Lib.Protocol.Buffers.To_Array (Valid_Blob),
         "ssh-ed25519",
         Key_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "known-host fixture key parses");

      Status_Value := SSH_Lib.Known_Hosts.From_Public_Key
        (Key_Item, Known_Host_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "known-host material exports from parsed key");
      Check (SSH_Lib.Known_Hosts.Is_Valid (Known_Host_Item),
             "known-host material exported from parsed key is valid");
      Check (SSH_Lib.Known_Hosts.Algorithm (Known_Host_Item) = "ssh-ed25519",
             "known-host material preserves key algorithm");
      Check (SSH_Lib.Known_Hosts.Encoded (Known_Host_Item)
             = "AAAAC3NzaC1lZDI1NTE5AAAAIAAKDX+A/zE4P0ZNVFtiaXB3foWMk5qhqK+2vcTL0tng",
             "known-host material preserves exact encoded key blob");

      Known_Host_Copy := SSH_Lib.Known_Hosts.Create_Host_Key
        ("ssh-ed25519", SSH_Lib.Known_Hosts.Encoded (Known_Host_Item));
      Check (SSH_Lib.Known_Hosts.Equal (Known_Host_Item, Known_Host_Copy),
             "known-host material round-trips through constructor");
      Known_Host_Copy := SSH_Lib.Known_Hosts.Create_Host_Key
        ("ssh-rsa", SSH_Lib.Known_Hosts.Encoded (Known_Host_Item));
      Check (not SSH_Lib.Known_Hosts.Is_Valid (Known_Host_Copy),
             "known-host constructor rejects decoded algorithm mismatch");

      Status_Value := SSH_Lib.Keys.SHA256_Fingerprint (Key_Item, Fingerprint_A);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "parsed public key fingerprint computes");
      Check (SSH_Lib.Keys.Image (Fingerprint_A)
             = "SHA256:nNhTJzRSh2u00NJYpP6u43hJLhpfeWewTGqfPV3NRPs",
             "parsed public key fingerprint matches exact vector");

      Status_Value := SSH_Lib.Known_Hosts.SHA256_Fingerprint
        (Known_Host_Item, Fingerprint_B);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "known-host fingerprint computes");
      Check (SSH_Lib.Keys.Image (Fingerprint_B) = SSH_Lib.Keys.Image (Fingerprint_A),
             "known-host fingerprint matches parsed public key fingerprint");
      Check (SSH_Lib.Keys.Equal (Fingerprint_A, Fingerprint_B),
             "known-host and parsed-key fingerprints compare equal");
   end Assert_Host_Key_Known_Host_Material;


   procedure Assert_Verify_And_Store_Failure_Preserves_Key is
      use Ada.Streams;
      State_Item     : SSH_Lib.Protocol.Encrypted_State.Kex_State;
      Existing_Key   : SSH_Lib.Keys.Public_Key;
      Stored_Key     : SSH_Lib.Keys.Public_Key;
      Good_Key_Bytes : Stream_Element_Array (1 .. 32);
      Existing_Blob  : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Bad_Blob       : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Empty_Signature : constant Stream_Element_Array (1 .. 0) := [others => 0];
      Exchange_Hash  : constant Stream_Element_Array (1 .. 6) :=
        [1 => 16#00#, 2 => 16#0A#, 3 => 16#0D#,
         4 => 16#7F#, 5 => 16#80#, 6 => 16#FF#];
      Status_Value   : CryptoLib.Errors.Status;
   begin
      for Index_Value in Good_Key_Bytes'Range loop
         Good_Key_Bytes (Index_Value) :=
           Stream_Element ((Integer (Index_Value) * 7) mod 256);
      end loop;
      Good_Key_Bytes (1) := 16#00#;
      Good_Key_Bytes (2) := 16#0A#;
      Good_Key_Bytes (3) := 16#0D#;
      Good_Key_Bytes (4) := 16#7F#;
      Good_Key_Bytes (5) := 16#80#;
      Good_Key_Bytes (6) := 16#FF#;

      Existing_Blob := Host_Key_Blob ("ssh-ed25519", Good_Key_Bytes);
      Status_Value := SSH_Lib.Protocol.Host_Keys.Parse
        (SSH_Lib.Protocol.Buffers.To_Array (Existing_Blob),
         "ssh-ed25519",
         Existing_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "existing verified key parses for atomicity test");

      SSH_Lib.Protocol.Encrypted_State.Reset (State_Item);
      Status_Value := SSH_Lib.Protocol.Encrypted_State.Store_Verified_Host_Key
        (State_Item, Existing_Key);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "existing verified key stores for atomicity test");

      Bad_Blob := Host_Key_Blob ("rsa-sha2-256", Good_Key_Bytes);
      Status_Value := SSH_Lib.Protocol.Host_Keys.Verify_And_Store
        (SSH_Lib.Protocol.Buffers.To_Array (Bad_Blob),
         Empty_Signature,
         "ssh-ed25519",
         Exchange_Hash,
         State_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "algorithm security", "failed verify-and-store returns deterministic failure");
      Check (SSH_Lib.Protocol.Encrypted_State.Has_Verified_Host_Key (State_Item),
             "failed verify-and-store keeps preexisting verified key");

      Stored_Key := SSH_Lib.Protocol.Encrypted_State.Verified_Host_Key (State_Item);
      Check (SSH_Lib.Keys.Algorithm (Stored_Key) = "ssh-ed25519",
             "failed verify-and-store keeps preexisting key algorithm");
      Check (SSH_Lib.Keys.Internal.Raw_Blob (Stored_Key)
             = SSH_Lib.Protocol.Buffers.To_Array (Existing_Blob),
             "failed verify-and-store keeps preexisting key blob");
   end Assert_Verify_And_Store_Failure_Preserves_Key;


   procedure Assert_Curve25519_Exchange_Hash_Wire_Bytes is
      use Ada.Streams;
      Client_Kexinit : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Server_Kexinit : SSH_Lib.Protocol.Buffers.Packet_Buffer;
      Digest_A       : SSH_Lib.Protocol.Exchange_Hash.Exchange_Digest;
      Digest_B       : SSH_Lib.Protocol.Exchange_Hash.Exchange_Digest;
      Status_Value   : CryptoLib.Errors.Status;
      Binary_Field   : constant Stream_Element_Array (1 .. 6) :=
        [1 => 16#00#, 2 => 16#0A#, 3 => 16#0D#,
         4 => 16#7F#, 5 => 16#80#, 6 => 16#FF#];
      Server_Public  : constant Stream_Element_Array (1 .. 32) :=
        [1  => 16#DE#, 2  => 16#9E#, 3  => 16#DB#, 4  => 16#7D#,
         5  => 16#7B#, 6  => 16#7D#, 7  => 16#C1#, 8  => 16#B4#,
         9  => 16#D3#, 10 => 16#5B#, 11 => 16#61#, 12 => 16#C2#,
         13 => 16#EC#, 14 => 16#E4#, 15 => 16#35#, 16 => 16#37#,
         17 => 16#3F#, 18 => 16#83#, 19 => 16#43#, 20 => 16#C8#,
         21 => 16#5B#, 22 => 16#78#, 23 => 16#67#, 24 => 16#4D#,
         25 => 16#AD#, 26 => 16#FC#, 27 => 16#7E#, 28 => 16#14#,
         29 => 16#6F#, 30 => 16#88#, 31 => 16#2B#, 32 => 16#4F#];
      Server_Public_High_Bit : Stream_Element_Array (1 .. 32) := Server_Public;
      Empty_Host_Key : constant Stream_Element_Array (1 .. 0) := [others => 0];
   begin
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Buffers.Set
           (Client_Kexinit, Bytes_From_String ("client-kexinit-wire")),
         CryptoLib.Errors.Ok,
         "algorithm security", "client KEXINIT fixture bytes set");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Protocol.Buffers.Set
           (Server_Kexinit, Bytes_From_String ("server-kexinit-wire")),
         CryptoLib.Errors.Ok,
         "algorithm security", "server KEXINIT fixture bytes set");

      Status_Value := SSH_Lib.Protocol.Exchange_Hash.Compute_Curve25519_SHA256
        ("SSH-2.0-SSH_Lib_Test_Client",
         "SSH-2.0-SSH_Lib_Test_Server",
         Client_Kexinit,
         Server_Kexinit,
         Binary_Field,
         Bytes_From_String ("client-public"),
         Server_Public,
         Binary_Field,
         Digest_A);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "Curve25519 exchange hash computes");

      Status_Value := SSH_Lib.Protocol.Exchange_Hash.Compute_Curve25519_SHA256
        ("SSH-2.0-SSH_Lib_Test_Client",
         "SSH-2.0-SSH_Lib_Test_Server",
         Client_Kexinit,
         Server_Kexinit,
         Binary_Field,
         Bytes_From_String ("client-public"),
         Server_Public,
         Binary_Field,
         Digest_B);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "Curve25519 exchange hash recomputes");
      Check (Digest_A = Digest_B,
             "same Curve25519 transcript produces same exchange hash");

      Status_Value := SSH_Lib.Protocol.Exchange_Hash.Compute_Curve25519_SHA256
        ("SSH-2.0-SSH_Lib_Test_Client_Changed",
         "SSH-2.0-SSH_Lib_Test_Server",
         Client_Kexinit,
         Server_Kexinit,
         Binary_Field,
         Bytes_From_String ("client-public"),
         Server_Public,
         Binary_Field,
         Digest_B);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "changed Curve25519 exchange hash computes");
      Check (Digest_A /= Digest_B,
             "changed identification changes Curve25519 exchange hash");

      Server_Public_High_Bit (32) :=
        Server_Public_High_Bit (32) or Stream_Element'(16#80#);
      Status_Value := SSH_Lib.Protocol.Exchange_Hash.Compute_Curve25519_SHA256
        ("SSH-2.0-SSH_Lib_Test_Client",
         "SSH-2.0-SSH_Lib_Test_Server",
         Client_Kexinit,
         Server_Kexinit,
         Binary_Field,
         Bytes_From_String ("client-public"),
         Server_Public_High_Bit,
         Binary_Field,
         Digest_B);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "high-bit Curve25519 exchange hash computes");
      Check (Digest_A /= Digest_B,
             "Curve25519 exchange hash preserves exact server public bytes");

      Status_Value := SSH_Lib.Protocol.Exchange_Hash.Compute_Curve25519_SHA256
        ("SSH-2.0-SSH_Lib_Test_Client",
         "SSH-2.0-SSH_Lib_Test_Server",
         Client_Kexinit,
         Server_Kexinit,
         Empty_Host_Key,
         Bytes_From_String ("client-public"),
         Server_Public,
         Binary_Field,
         Digest_B);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "empty host key fails Curve25519 exchange hash");
      Check (Digest_B = [Digest_B'Range => 0],
             "failed Curve25519 exchange hash clears digest output");
   end Assert_Curve25519_Exchange_Hash_Wire_Bytes;


   procedure Assert_Mixed_Chacha_And_AES_Protected_State is
      use Ada.Streams;
      State_Item : SSH_Lib.Protocol.Protected_Packets.Protected_State;
      Chacha_Key : Stream_Element_Array (1 .. 64) := [others => 0];
      AES_Key    : Stream_Element_Array (1 .. 32) := [others => 0];
      AES_IV     : Stream_Element_Array (1 .. 16) := [others => 0];
      Mac_Key    : Stream_Element_Array (1 .. 64) := [others => 0];
      Empty_IV   : Stream_Element_Array (1 .. 0);
   begin
      for Index_Value in Chacha_Key'Range loop
         Chacha_Key (Index_Value) := Stream_Element (Index_Value mod 251);
      end loop;
      for Index_Value in AES_Key'Range loop
         AES_Key (Index_Value) := Stream_Element ((Natural (Index_Value) * 3) mod 251);
      end loop;
      for Index_Value in AES_IV'Range loop
         AES_IV (Index_Value) := Stream_Element ((Natural (Index_Value) * 5) mod 251);
      end loop;
      for Index_Value in Mac_Key'Range loop
         Mac_Key (Index_Value) := Stream_Element ((Natural (Index_Value) * 7) mod 251);
      end loop;

      SSH_Lib.Protocol.Protected_Packets.Reset_With_Ciphers
        (State_Item,
         "chacha20-poly1305@openssh.com",
         "aes256-ctr",
         "hmac-sha2-256",
         "hmac-sha2-256",
         Mac_Key,
         Mac_Key,
         Chacha_Key,
         Empty_IV,
         AES_Key,
         AES_IV);
      Check (not SSH_Lib.Protocol.Protected_Packets.Is_Dirty (State_Item),
             "mixed outbound chacha20-poly1305 and inbound AES-CTR protected state initializes");
      Check (SSH_Lib.Protocol.Protected_Packets.Outbound_Mac_Size (State_Item) = 16,
             "outbound chacha20-poly1305 uses AEAD tag length");
      Check (SSH_Lib.Protocol.Protected_Packets.Inbound_Mac_Size (State_Item) = 32,
             "inbound AES-CTR keeps negotiated HMAC length");

      SSH_Lib.Protocol.Protected_Packets.Reset_With_Ciphers
        (State_Item,
         "aes256-ctr",
         "chacha20-poly1305@openssh.com",
         "hmac-sha2-256",
         "hmac-sha2-256",
         Mac_Key,
         Mac_Key,
         AES_Key,
         AES_IV,
         Chacha_Key,
         Empty_IV);
      Check (not SSH_Lib.Protocol.Protected_Packets.Is_Dirty (State_Item),
             "mixed outbound AES-CTR and inbound chacha20-poly1305 protected state initializes");
      Check (SSH_Lib.Protocol.Protected_Packets.Outbound_Mac_Size (State_Item) = 32,
             "outbound AES-CTR keeps negotiated HMAC length");
      Check (SSH_Lib.Protocol.Protected_Packets.Inbound_Mac_Size (State_Item) = 16,
             "inbound chacha20-poly1305 uses AEAD tag length");


      SSH_Lib.Protocol.Protected_Packets.Reset_With_Ciphers
        (State_Item,
         "aes256-gcm@openssh.com",
         "aes128-gcm@openssh.com",
         "hmac-sha2-256",
         "hmac-sha2-256",
         Mac_Key,
         Mac_Key,
         AES_Key,
         AES_IV,
         AES_Key,
         AES_IV);
      Check (not SSH_Lib.Protocol.Protected_Packets.Is_Dirty (State_Item),
             "AES-GCM protected state initializes in both directions");
      Check (SSH_Lib.Protocol.Protected_Packets.Outbound_Mac_Size (State_Item) = 16,
             "outbound AES-GCM uses AEAD tag length");
      Check (SSH_Lib.Protocol.Protected_Packets.Inbound_Mac_Size (State_Item) = 16,
             "inbound AES-GCM uses AEAD tag length");

      SSH_Lib.Protocol.Protected_Packets.Reset_With_Ciphers
        (State_Item,
         "aes256-gcm@openssh.com",
         "aes256-ctr",
         "hmac-sha2-256",
         "hmac-sha2-256",
         Mac_Key,
         Mac_Key,
         AES_Key,
         AES_IV,
         AES_Key,
         AES_IV);
      Check (not SSH_Lib.Protocol.Protected_Packets.Is_Dirty (State_Item),
             "mixed outbound AES-GCM and inbound AES-CTR protected state initializes");
      Check (SSH_Lib.Protocol.Protected_Packets.Outbound_Mac_Size (State_Item) = 16,
             "outbound AES-GCM uses AEAD tag length in mixed mode");
      Check (SSH_Lib.Protocol.Protected_Packets.Inbound_Mac_Size (State_Item) = 32,
             "inbound AES-CTR keeps negotiated HMAC length in mixed mode");
   end Assert_Mixed_Chacha_And_AES_Protected_State;

   procedure Assert_Kex_Negotiation_Clears_On_Failure is
      Client_Item : SSH_Lib.Protocol.Kexinit.Kexinit_Message;
      Server_Item : SSH_Lib.Protocol.Kexinit.Kexinit_Message;
      Result_Item : SSH_Lib.Protocol.Kex.Negotiated_Algorithms;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Client_Item.Kex_Algorithms := To_Unbounded_String ("curve25519-sha256");
      Client_Item.Server_Host_Key_Algorithms := To_Unbounded_String (Host_Key_List);
      Client_Item.Encryption_Algorithms_Client_To_Server := To_Unbounded_String (Cipher_List);
      Client_Item.Encryption_Algorithms_Server_To_Client := To_Unbounded_String (Cipher_List);
      Client_Item.Mac_Algorithms_Client_To_Server := To_Unbounded_String (Mac_List);
      Client_Item.Mac_Algorithms_Server_To_Client := To_Unbounded_String (Mac_List);
      Client_Item.Compression_Algorithms_Client_To_Server := To_Unbounded_String ("zlib@openssh.com,zlib,none");
      Client_Item.Compression_Algorithms_Server_To_Client := To_Unbounded_String ("zlib@openssh.com,zlib,none");

      Server_Item := Client_Item;
      Server_Item.Kex_Algorithms := To_Unbounded_String ("diffie-hellman-group14-sha256");
      Status_Value := SSH_Lib.Protocol.Kex.Negotiate
        (Client_Item, Server_Item, Result_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Unsupported_Feature,
         "algorithm security", "full negotiation fails when no supported KEX intersection exists");
      Check (To_String (Result_Item.Key_Exchange) = ""
             and then To_String (Result_Item.Mac_Client_To_Server) = "",
             "failed full negotiation clears partial algorithm state");

      Server_Item := Client_Item;
      Status_Value := SSH_Lib.Protocol.Kex.Negotiate
        (Client_Item, Server_Item, Result_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "algorithm security", "full implemented negotiation succeeds");
      Check (To_String (Result_Item.Key_Exchange) = "curve25519-sha256"
             and then To_String (Result_Item.Server_Host_Key) = "ssh-ed25519-cert-v01@openssh.com"
             and then To_String (Result_Item.Cipher_Client_To_Server) = "chacha20-poly1305@openssh.com"
             and then To_String (Result_Item.Mac_Client_To_Server) = "umac-128-etm@openssh.com",
             "full negotiation records implemented algorithms");

      Server_Item := Client_Item;
      Server_Item.Compression_Algorithms_Client_To_Server :=
        To_Unbounded_String ("none,,zlib@openssh.com");
      Status_Value := SSH_Lib.Protocol.Kex.Negotiate
        (Client_Item, Server_Item, Result_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Handshake_Failed,
         "algorithm security", "malformed algorithm name-list fails before selection");
      Check (To_String (Result_Item.Key_Exchange) = ""
             and then To_String (Result_Item.Mac_Client_To_Server) = "",
             "malformed full negotiation clears partial algorithm state");
   end Assert_Kex_Negotiation_Clears_On_Failure;

   procedure Assert_Algorithm_Negotiation_Security is
   begin
      Assert_Advertised_Algorithms_Are_Implemented;
      Assert_Selection_Preserves_Client_Preference;
      Assert_Unsupported_Intersections_Fail;
      Assert_Malformed_Or_Not_Advertised_Selection_Fails;
      Assert_Weak_Algorithms_Rejected;
      Assert_SHA256_Session_Key_Derivation;
      Assert_Encrypted_State_Newkeys_Transition;
      Assert_Encrypted_State_Verified_Host_Key_Storage;
      Assert_Host_Key_Parse_Ed25519_Invariants;
      Assert_Host_Key_Parse_RSA_Invariants;
      Assert_RSA_Known_Host_Material;
      Assert_Host_Key_Known_Host_Material;
      Assert_Verify_And_Store_Failure_Preserves_Key;
      Assert_Curve25519_Exchange_Hash_Wire_Bytes;
      Assert_Mixed_Chacha_And_AES_Protected_State;
      Assert_Kex_Negotiation_Clears_On_Failure;
   end Assert_Algorithm_Negotiation_Security;
end SSH_Lib.Tests.Fixtures.Algorithm_Security;
