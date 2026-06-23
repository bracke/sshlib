with Interfaces;
with SSH_Lib.ECDSA;
with SSH_Lib.Protocol.Numbers;

package body SSH_Lib.Protocol.Exchange_Hash is

   use Ada.Streams;
   use CryptoLib.Errors;
   use SSH_Lib.Protocol.Buffers;

   function Bytes_From_String (Value : String) return Stream_Element_Array is
      Result :
        Stream_Element_Array
          (Stream_Element_Offset'(1) .. Stream_Element_Offset (Value'Length));
      Cursor : Stream_Element_Offset := 1;
   begin
      for Character_Value of Value loop
         Result (Cursor) := Stream_Element (Character'Pos (Character_Value));
         Cursor := Cursor + 1;
      end loop;
      return Result;
   end Bytes_From_String;

   function Append_SSH_String
     (Work_Item : in out Packet_Buffer; Payload : Stream_Element_Array)
      return Status
   is
      Encoded : constant Packet_Buffer :=
        SSH_Lib.Protocol.Numbers.Encode_SSH_String (Payload);
   begin
      return Append (Work_Item, To_Array (Encoded));
   end Append_SSH_String;

   function Append_Mpint
     (Work_Item : in out Packet_Buffer; Payload : Stream_Element_Array)
      return Status
   is
      First_Nonzero    : Stream_Element_Offset := Payload'First;
      Need_Zero_Prefix : Boolean := False;
      Encoded          : Packet_Buffer;
      Status_Value     : Status;
   begin
      if Payload'Length = 0 then
         return Append (Work_Item, SSH_Lib.Protocol.Numbers.Encode_Uint32 (0));
      end if;

      while First_Nonzero <= Payload'Last and then Payload (First_Nonzero) = 0
      loop
         First_Nonzero := First_Nonzero + 1;
      end loop;

      if First_Nonzero > Payload'Last then
         return Append (Work_Item, SSH_Lib.Protocol.Numbers.Encode_Uint32 (0));
      end if;

      Need_Zero_Prefix := Payload (First_Nonzero) >= 16#80#;
      Clear (Encoded);
      if Need_Zero_Prefix then
         Status_Value := Append_Byte (Encoded, 0);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end if;
      Status_Value :=
        Append (Encoded, Payload (First_Nonzero .. Payload'Last));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      return Append_SSH_String (Work_Item, To_Array (Encoded));
   end Append_Mpint;

   function Compute_Common_SHA1
     (Client_Identification    : String;
      Server_Identification    : String;
      Client_Kexinit           : Packet_Buffer;
      Server_Kexinit           : Packet_Buffer;
      Server_Host_Key          : Stream_Element_Array;
      First_Public_Value       : Stream_Element_Array;
      Second_Public_Value      : Stream_Element_Array;
      Shared_Secret            : Stream_Element_Array;
      Public_Values_Are_Mpints : Boolean;
      Result_Digest            : out Exchange_SHA1_Digest) return Status
   is
      Work_Item    : Packet_Buffer;
      Status_Value : Status;
   begin
      Result_Digest := [others => 0];
      Clear (Work_Item);

      if Length (Client_Kexinit) = 0
        or else Length (Server_Kexinit) = 0
        or else Server_Host_Key'Length = 0
        or else First_Public_Value'Length = 0
        or else Second_Public_Value'Length = 0
        or else Shared_Secret'Length = 0
      then
         return Handshake_Failed;
      end if;

      Status_Value :=
        Append_SSH_String
          (Work_Item, Bytes_From_String (Client_Identification));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Append_SSH_String
          (Work_Item, Bytes_From_String (Server_Identification));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, To_Array (Client_Kexinit));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, To_Array (Server_Kexinit));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, Server_Host_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Public_Values_Are_Mpints then
         Status_Value := Append_Mpint (Work_Item, First_Public_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         Status_Value := Append_Mpint (Work_Item, Second_Public_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      else
         Status_Value := Append_SSH_String (Work_Item, First_Public_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         Status_Value := Append_SSH_String (Work_Item, Second_Public_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end if;

      Status_Value := Append_Mpint (Work_Item, Shared_Secret);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Result_Digest := CryptoLib.Hashes.SHA1 (To_Array (Work_Item));
      return Ok;
   exception
      when others =>
         Result_Digest := [others => 0];
         return Internal_Error;
   end Compute_Common_SHA1;

   function Compute_Common_SHA256
     (Client_Identification    : String;
      Server_Identification    : String;
      Client_Kexinit           : Packet_Buffer;
      Server_Kexinit           : Packet_Buffer;
      Server_Host_Key          : Stream_Element_Array;
      First_Public_Value       : Stream_Element_Array;
      Second_Public_Value      : Stream_Element_Array;
      Shared_Secret            : Stream_Element_Array;
      Public_Values_Are_Mpints : Boolean;
      Result_Digest            : out Exchange_Digest) return Status
   is
      Work_Item    : Packet_Buffer;
      Status_Value : Status;
   begin
      Result_Digest := [others => 0];
      Clear (Work_Item);

      if Length (Client_Kexinit) = 0
        or else Length (Server_Kexinit) = 0
        or else Server_Host_Key'Length = 0
        or else First_Public_Value'Length = 0
        or else Second_Public_Value'Length = 0
        or else Shared_Secret'Length = 0
      then
         return Handshake_Failed;
      end if;

      Status_Value :=
        Append_SSH_String
          (Work_Item, Bytes_From_String (Client_Identification));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Append_SSH_String
          (Work_Item, Bytes_From_String (Server_Identification));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, To_Array (Client_Kexinit));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, To_Array (Server_Kexinit));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, Server_Host_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Public_Values_Are_Mpints then
         Status_Value := Append_Mpint (Work_Item, First_Public_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         Status_Value := Append_Mpint (Work_Item, Second_Public_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      else
         Status_Value := Append_SSH_String (Work_Item, First_Public_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         Status_Value := Append_SSH_String (Work_Item, Second_Public_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end if;

      Status_Value := Append_Mpint (Work_Item, Shared_Secret);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Result_Digest := CryptoLib.Hashes.SHA256 (To_Array (Work_Item));
      return Ok;
   exception
      when others =>
         Result_Digest := [others => 0];
         return Internal_Error;
   end Compute_Common_SHA256;

   function Compute_Common_SHA512
     (Client_Identification    : String;
      Server_Identification    : String;
      Client_Kexinit           : Packet_Buffer;
      Server_Kexinit           : Packet_Buffer;
      Server_Host_Key          : Stream_Element_Array;
      First_Public_Value       : Stream_Element_Array;
      Second_Public_Value      : Stream_Element_Array;
      Shared_Secret            : Stream_Element_Array;
      Public_Values_Are_Mpints : Boolean;
      Result_Digest            : out Exchange_SHA512_Digest) return Status
   is
      Work_Item    : Packet_Buffer;
      Status_Value : Status;
   begin
      Result_Digest := [others => 0];
      Clear (Work_Item);

      if Length (Client_Kexinit) = 0
        or else Length (Server_Kexinit) = 0
        or else Server_Host_Key'Length = 0
        or else First_Public_Value'Length = 0
        or else Second_Public_Value'Length = 0
        or else Shared_Secret'Length = 0
      then
         return Handshake_Failed;
      end if;

      Status_Value :=
        Append_SSH_String
          (Work_Item, Bytes_From_String (Client_Identification));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Append_SSH_String
          (Work_Item, Bytes_From_String (Server_Identification));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, To_Array (Client_Kexinit));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, To_Array (Server_Kexinit));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, Server_Host_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if Public_Values_Are_Mpints then
         Status_Value := Append_Mpint (Work_Item, First_Public_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         Status_Value := Append_Mpint (Work_Item, Second_Public_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      else
         Status_Value := Append_SSH_String (Work_Item, First_Public_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
         Status_Value := Append_SSH_String (Work_Item, Second_Public_Value);
         if Status_Value /= Ok then
            return Status_Value;
         end if;
      end if;

      Status_Value := Append_Mpint (Work_Item, Shared_Secret);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Result_Digest := CryptoLib.Hashes.SHA512 (To_Array (Work_Item));
      return Ok;
   exception
      when others =>
         Result_Digest := [others => 0];
         return Internal_Error;
   end Compute_Common_SHA512;

   function Compute_Curve25519_SHA256
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : Packet_Buffer;
      Server_Kexinit        : Packet_Buffer;
      Server_Host_Key       : Stream_Element_Array;
      Client_Public_Key     : Stream_Element_Array;
      Server_Public_Key     : Stream_Element_Array;
      Shared_Secret         : Stream_Element_Array;
      Result_Digest         : out Exchange_Digest) return Status is
   begin
      return
        Compute_Common_SHA256
          (Client_Identification,
           Server_Identification,
           Client_Kexinit,
           Server_Kexinit,
           Server_Host_Key,
           Client_Public_Key,
           Server_Public_Key,
           Shared_Secret,
           False,
           Result_Digest);
   end Compute_Curve25519_SHA256;

   function Compute_Hybrid_PQ_SHA256
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : Packet_Buffer;
      Server_Kexinit        : Packet_Buffer;
      Server_Host_Key       : Stream_Element_Array;
      Client_Init           : Stream_Element_Array;
      Server_Reply          : Stream_Element_Array;
      Shared_Secret         : Stream_Element_Array;
      Result_Digest         : out Exchange_Digest) return Status
   is
      Work_Item    : Packet_Buffer;
      Status_Value : Status;
   begin
      Result_Digest := [others => 0];
      Clear (Work_Item);

      if Length (Client_Kexinit) = 0
        or else Length (Server_Kexinit) = 0
        or else Server_Host_Key'Length = 0
        or else Client_Init'Length = 0
        or else Server_Reply'Length = 0
        or else Shared_Secret'Length = 0
      then
         return Handshake_Failed;
      end if;

      Status_Value :=
        Append_SSH_String
          (Work_Item, Bytes_From_String (Client_Identification));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Append_SSH_String
          (Work_Item, Bytes_From_String (Server_Identification));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, To_Array (Client_Kexinit));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, To_Array (Server_Kexinit));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, Server_Host_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, Client_Init);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, Server_Reply);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, Shared_Secret);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Result_Digest := CryptoLib.Hashes.SHA256 (To_Array (Work_Item));
      return Ok;
   exception
      when others =>
         Result_Digest := [others => 0];
         return Internal_Error;
   end Compute_Hybrid_PQ_SHA256;

   function Compute_Hybrid_PQ_SHA512
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : Packet_Buffer;
      Server_Kexinit        : Packet_Buffer;
      Server_Host_Key       : Stream_Element_Array;
      Client_Init           : Stream_Element_Array;
      Server_Reply          : Stream_Element_Array;
      Shared_Secret         : Stream_Element_Array;
      Result_Digest         : out Exchange_SHA512_Digest) return Status
   is
      Work_Item    : Packet_Buffer;
      Status_Value : Status;
   begin
      Result_Digest := [others => 0];
      Clear (Work_Item);

      if Length (Client_Kexinit) = 0
        or else Length (Server_Kexinit) = 0
        or else Server_Host_Key'Length = 0
        or else Client_Init'Length = 0
        or else Server_Reply'Length = 0
        or else Shared_Secret'Length = 0
      then
         return Handshake_Failed;
      end if;

      Status_Value :=
        Append_SSH_String
          (Work_Item, Bytes_From_String (Client_Identification));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Append_SSH_String
          (Work_Item, Bytes_From_String (Server_Identification));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, To_Array (Client_Kexinit));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, To_Array (Server_Kexinit));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, Server_Host_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, Client_Init);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, Server_Reply);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, Shared_Secret);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Result_Digest := CryptoLib.Hashes.SHA512 (To_Array (Work_Item));
      return Ok;
   exception
      when others =>
         Result_Digest := [others => 0];
         return Internal_Error;
   end Compute_Hybrid_PQ_SHA512;

   function Compute_ECDH_SHA256
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : Packet_Buffer;
      Server_Kexinit        : Packet_Buffer;
      Server_Host_Key       : Stream_Element_Array;
      Client_Public_Key     : Stream_Element_Array;
      Server_Public_Key     : Stream_Element_Array;
      Shared_Secret         : Stream_Element_Array;
      Result_Digest         : out Exchange_Digest) return Status
   is
      Status_Value : Status;
   begin
      Result_Digest := [others => 0];

      --  RFC 5656 ECDH exchange-hash inputs Q_C and Q_S are SEC1 encoded
      --  public points carried as SSH strings.  The live packet parser already
      --  validates these values before the shared secret is computed; repeat
      --  the check here so direct exchange-hash callers and future tests cannot
      --  accidentally hash malformed or cross-curve point material.
      Status_Value :=
        SSH_Lib.ECDSA.Validate_Raw_Point_Nistp256 (Client_Public_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value :=
        SSH_Lib.ECDSA.Validate_Raw_Point_Nistp256 (Server_Public_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      --  RFC 5656 defines the ECDH shared secret K as the x-coordinate of
      --  the shared point, later encoded as an SSH mpint for the exchange
      --  hash.  Reuse the same nistp256 shared-secret boundary validator used
      --  by the live primitive so direct exchange-hash callers cannot hash an
      --  incorrectly sized or degenerate K value.
      Status_Value :=
        SSH_Lib.ECDSA.Validate_ECDH_Nistp256_Shared_Secret
          (Shared_Secret);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      return
        Compute_Common_SHA256
          (Client_Identification,
           Server_Identification,
           Client_Kexinit,
           Server_Kexinit,
           Server_Host_Key,
           Client_Public_Key,
           Server_Public_Key,
           Shared_Secret,
           False,
           Result_Digest);
   end Compute_ECDH_SHA256;

   function Compute_Group14_SHA1
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : Packet_Buffer;
      Server_Kexinit        : Packet_Buffer;
      Server_Host_Key       : Stream_Element_Array;
      Client_Public_Value   : Stream_Element_Array;
      Server_Public_Value   : Stream_Element_Array;
      Shared_Secret         : Stream_Element_Array;
      Result_Digest         : out Exchange_SHA1_Digest) return Status is
   begin
      return
        Compute_Common_SHA1
          (Client_Identification,
           Server_Identification,
           Client_Kexinit,
           Server_Kexinit,
           Server_Host_Key,
           Client_Public_Value,
           Server_Public_Value,
           Shared_Secret,
           True,
           Result_Digest);
   end Compute_Group14_SHA1;

   function Compute_Group_Exchange_SHA1
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : Packet_Buffer;
      Server_Kexinit        : Packet_Buffer;
      Server_Host_Key       : Stream_Element_Array;
      Minimum_Bits          : Natural;
      Preferred_Bits        : Natural;
      Maximum_Bits          : Natural;
      Prime_Value           : Stream_Element_Array;
      Generator_Value       : Stream_Element_Array;
      Client_Public_Value   : Stream_Element_Array;
      Server_Public_Value   : Stream_Element_Array;
      Shared_Secret         : Stream_Element_Array;
      Result_Digest         : out Exchange_SHA1_Digest) return Status
   is
      Work_Item    : Packet_Buffer;
      Status_Value : Status;
   begin
      Result_Digest := [others => 0];
      Clear (Work_Item);
      if Length (Client_Kexinit) = 0
        or else Length (Server_Kexinit) = 0
        or else Server_Host_Key'Length = 0
        or else Prime_Value'Length = 0
        or else Generator_Value'Length = 0
        or else Client_Public_Value'Length = 0
        or else Server_Public_Value'Length = 0
        or else Shared_Secret'Length = 0
        or else Minimum_Bits < 1024
        or else Preferred_Bits < Minimum_Bits
        or else Maximum_Bits < Preferred_Bits
      then
         return Handshake_Failed;
      end if;
      Status_Value :=
        Append_SSH_String
          (Work_Item, Bytes_From_String (Client_Identification));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Append_SSH_String
          (Work_Item, Bytes_From_String (Server_Identification));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, To_Array (Client_Kexinit));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, To_Array (Server_Kexinit));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, Server_Host_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Append
          (Work_Item,
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32 (Minimum_Bits)));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Append
          (Work_Item,
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32 (Preferred_Bits)));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Append
          (Work_Item,
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32 (Maximum_Bits)));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Mpint (Work_Item, Prime_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Mpint (Work_Item, Generator_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Mpint (Work_Item, Client_Public_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Mpint (Work_Item, Server_Public_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Mpint (Work_Item, Shared_Secret);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Result_Digest := CryptoLib.Hashes.SHA1 (To_Array (Work_Item));
      return Ok;
   exception
      when others =>
         Result_Digest := [others => 0];
         return Internal_Error;
   end Compute_Group_Exchange_SHA1;

   function Compute_Group_Exchange_SHA256
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : Packet_Buffer;
      Server_Kexinit        : Packet_Buffer;
      Server_Host_Key       : Stream_Element_Array;
      Minimum_Bits          : Natural;
      Preferred_Bits        : Natural;
      Maximum_Bits          : Natural;
      Prime_Value           : Stream_Element_Array;
      Generator_Value       : Stream_Element_Array;
      Client_Public_Value   : Stream_Element_Array;
      Server_Public_Value   : Stream_Element_Array;
      Shared_Secret         : Stream_Element_Array;
      Result_Digest         : out Exchange_Digest) return Status
   is
      Work_Item    : Packet_Buffer;
      Status_Value : Status;
   begin
      Result_Digest := [others => 0];
      Clear (Work_Item);
      if Length (Client_Kexinit) = 0
        or else Length (Server_Kexinit) = 0
        or else Server_Host_Key'Length = 0
        or else Prime_Value'Length = 0
        or else Generator_Value'Length = 0
        or else Client_Public_Value'Length = 0
        or else Server_Public_Value'Length = 0
        or else Shared_Secret'Length = 0
        or else Minimum_Bits < 1024
        or else Preferred_Bits < Minimum_Bits
        or else Maximum_Bits < Preferred_Bits
      then
         return Handshake_Failed;
      end if;
      Status_Value :=
        Append_SSH_String
          (Work_Item, Bytes_From_String (Client_Identification));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Append_SSH_String
          (Work_Item, Bytes_From_String (Server_Identification));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, To_Array (Client_Kexinit));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, To_Array (Server_Kexinit));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_SSH_String (Work_Item, Server_Host_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Append
          (Work_Item,
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32 (Minimum_Bits)));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Append
          (Work_Item,
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32 (Preferred_Bits)));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        Append
          (Work_Item,
           SSH_Lib.Protocol.Numbers.Encode_Uint32
             (Interfaces.Unsigned_32 (Maximum_Bits)));
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Mpint (Work_Item, Prime_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Mpint (Work_Item, Generator_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Mpint (Work_Item, Client_Public_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Mpint (Work_Item, Server_Public_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Append_Mpint (Work_Item, Shared_Secret);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Result_Digest := CryptoLib.Hashes.SHA256 (To_Array (Work_Item));
      return Ok;
   exception
      when others =>
         Result_Digest := [others => 0];
         return Internal_Error;
   end Compute_Group_Exchange_SHA256;

   function Compute_Group14_SHA256
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : Packet_Buffer;
      Server_Kexinit        : Packet_Buffer;
      Server_Host_Key       : Stream_Element_Array;
      Client_Public_Value   : Stream_Element_Array;
      Server_Public_Value   : Stream_Element_Array;
      Shared_Secret         : Stream_Element_Array;
      Result_Digest         : out Exchange_Digest) return Status is
   begin
      return
        Compute_Common_SHA256
          (Client_Identification,
           Server_Identification,
           Client_Kexinit,
           Server_Kexinit,
           Server_Host_Key,
           Client_Public_Value,
           Server_Public_Value,
           Shared_Secret,
           True,
           Result_Digest);
   end Compute_Group14_SHA256;

   function Compute_Group16_SHA512
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : Packet_Buffer;
      Server_Kexinit        : Packet_Buffer;
      Server_Host_Key       : Stream_Element_Array;
      Client_Public_Value   : Stream_Element_Array;
      Server_Public_Value   : Stream_Element_Array;
      Shared_Secret         : Stream_Element_Array;
      Result_Digest         : out Exchange_SHA512_Digest) return Status is
   begin
      return
        Compute_Common_SHA512
          (Client_Identification,
           Server_Identification,
           Client_Kexinit,
           Server_Kexinit,
           Server_Host_Key,
           Client_Public_Value,
           Server_Public_Value,
           Shared_Secret,
           True,
           Result_Digest);
   end Compute_Group16_SHA512;

   function Compute_Group18_SHA512
     (Client_Identification : String;
      Server_Identification : String;
      Client_Kexinit        : Packet_Buffer;
      Server_Kexinit        : Packet_Buffer;
      Server_Host_Key       : Stream_Element_Array;
      Client_Public_Value   : Stream_Element_Array;
      Server_Public_Value   : Stream_Element_Array;
      Shared_Secret         : Stream_Element_Array;
      Result_Digest         : out Exchange_SHA512_Digest) return Status is
   begin
      return
        Compute_Common_SHA512
          (Client_Identification,
           Server_Identification,
           Client_Kexinit,
           Server_Kexinit,
           Server_Host_Key,
           Client_Public_Value,
           Server_Public_Value,
           Shared_Secret,
           True,
           Result_Digest);
   end Compute_Group18_SHA512;

end SSH_Lib.Protocol.Exchange_Hash;
