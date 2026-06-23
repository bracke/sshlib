with CryptoLib.Buffers;
with SSH_Lib.Protocol.Numbers;
with SSH_Lib.Protocol.Validation;

package body SSH_Lib.Public_Key_Blobs is
   use Ada.Streams;
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;

   function Algorithm_Name
     (Key_Blob : Stream_Element_Array;
      Name     : out Unbounded_String)
      return Status
   is
      Name_Buffer  : CryptoLib.Buffers.Packet_Buffer;
      Next_Index   : Stream_Element_Offset;
      Status_Value : Status;
   begin
      Name := Null_Unbounded_String;
      Status_Value := SSH_Lib.Protocol.Numbers.Decode_SSH_String
        (Key_Blob, Key_Blob'First, Name_Buffer, Next_Index);
      if Status_Value /= Ok then
         return Authentication_Failed;
      end if;

      declare
         Data : constant Stream_Element_Array :=
           CryptoLib.Buffers.To_Array (Name_Buffer);
      begin
         if Data'Length = 0 then
            return Authentication_Failed;
         end if;

         for Byte_Value of Data loop
            if Byte_Value > 127 then
               Name := Null_Unbounded_String;
               return Authentication_Failed;
            end if;
            Append (Name, Character'Val (Natural (Byte_Value)));
         end loop;
      end;

      if not SSH_Lib.Protocol.Validation.Is_ASCII_Protocol_Name (To_String (Name)) then
         Name := Null_Unbounded_String;
         return Authentication_Failed;
      end if;

      return Ok;
   exception
      when others =>
         Name := Null_Unbounded_String;
         return Internal_Error;
   end Algorithm_Name;

   function Is_Default_Userauth_Algorithm
     (Name : String)
      return Boolean
   is
   begin
      return Name = "ssh-ed25519"
        or else Name = "ecdsa-sha2-nistp256"
        or else Name = "sk-ssh-ed25519@openssh.com"
        or else Name = "sk-ecdsa-sha2-nistp256@openssh.com"
        or else Name = "sk-ssh-ed25519-cert-v01@openssh.com"
        or else Name = "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"
        or else Name = "rsa-sha2-256"
        or else Name = "rsa-sha2-512"
        or else Name = "ssh-rsa";
   end Is_Default_Userauth_Algorithm;
end SSH_Lib.Public_Key_Blobs;
