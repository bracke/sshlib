with SSH_Lib.Algorithms;

package body SSH_Lib.Protocol.Kex is
   use Ada.Strings.Unbounded;
   use CryptoLib.Errors;

   procedure Clear (Item : out Negotiated_Algorithms) is
   begin
      Item.Key_Exchange := Null_Unbounded_String;
      Item.Server_Host_Key := Null_Unbounded_String;
      Item.Cipher_Client_To_Server := Null_Unbounded_String;
      Item.Cipher_Server_To_Client := Null_Unbounded_String;
      Item.Mac_Client_To_Server := Null_Unbounded_String;
      Item.Mac_Server_To_Client := Null_Unbounded_String;
      Item.Compression_Client_To_Server := Null_Unbounded_String;
      Item.Compression_Server_To_Client := Null_Unbounded_String;
   end Clear;

   function Validate_All_Lists
     (Client_Item : SSH_Lib.Protocol.Kexinit.Kexinit_Message;
      Server_Item : SSH_Lib.Protocol.Kexinit.Kexinit_Message)
      return Status
   is
      function Valid
        (List_Item : Unbounded_String)
         return Boolean
      is
      begin
         return SSH_Lib.Algorithms.Validate_Name_List (To_String (List_Item));
      end Valid;
   begin
      if not Valid (Client_Item.Kex_Algorithms)
        or else not Valid (Server_Item.Kex_Algorithms)
        or else not Valid (Client_Item.Server_Host_Key_Algorithms)
        or else not Valid (Server_Item.Server_Host_Key_Algorithms)
        or else not Valid (Client_Item.Encryption_Algorithms_Client_To_Server)
        or else not Valid (Server_Item.Encryption_Algorithms_Client_To_Server)
        or else not Valid (Client_Item.Encryption_Algorithms_Server_To_Client)
        or else not Valid (Server_Item.Encryption_Algorithms_Server_To_Client)
        or else not Valid (Client_Item.Mac_Algorithms_Client_To_Server)
        or else not Valid (Server_Item.Mac_Algorithms_Client_To_Server)
        or else not Valid (Client_Item.Mac_Algorithms_Server_To_Client)
        or else not Valid (Server_Item.Mac_Algorithms_Server_To_Client)
        or else not Valid (Client_Item.Compression_Algorithms_Client_To_Server)
        or else not Valid (Server_Item.Compression_Algorithms_Client_To_Server)
        or else not Valid (Client_Item.Compression_Algorithms_Server_To_Client)
        or else not Valid (Server_Item.Compression_Algorithms_Server_To_Client)
        or else not Valid (Client_Item.Languages_Client_To_Server)
        or else not Valid (Server_Item.Languages_Client_To_Server)
        or else not Valid (Client_Item.Languages_Server_To_Client)
        or else not Valid (Server_Item.Languages_Server_To_Client)
      then
         return Handshake_Failed;
      end if;

      return Ok;
   end Validate_All_Lists;

   function Select_Required
     (Class_Item : SSH_Lib.Algorithms.Algorithm_Class;
      Local_Text : String;
      Remote_Text : String;
      Result_Text : out Unbounded_String)
      return Status
   is
   begin
      return SSH_Lib.Algorithms.Select_Algorithm
        (Class_Item, Local_Text, Remote_Text, Result_Text);
   end Select_Required;

   function Negotiate
     (Client_Item : SSH_Lib.Protocol.Kexinit.Kexinit_Message;
      Server_Item : SSH_Lib.Protocol.Kexinit.Kexinit_Message;
      Result_Item : out Negotiated_Algorithms)
      return Status
   is
      Status_Value : Status;
   begin
      Clear (Result_Item);

      Status_Value := Validate_All_Lists (Client_Item, Server_Item);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Status_Value := Select_Required
        (SSH_Lib.Algorithms.Key_Exchange,
         To_String (Client_Item.Kex_Algorithms),
         To_String (Server_Item.Kex_Algorithms),
         Result_Item.Key_Exchange);
      if Status_Value /= Ok then
         Clear (Result_Item);
         return Status_Value;
      end if;

      Status_Value := Select_Required
        (SSH_Lib.Algorithms.Server_Host_Key,
         To_String (Client_Item.Server_Host_Key_Algorithms),
         To_String (Server_Item.Server_Host_Key_Algorithms),
         Result_Item.Server_Host_Key);
      if Status_Value /= Ok then
         Clear (Result_Item);
         return Status_Value;
      end if;

      Status_Value := Select_Required
        (SSH_Lib.Algorithms.Encryption_Client_To_Server,
         To_String (Client_Item.Encryption_Algorithms_Client_To_Server),
         To_String (Server_Item.Encryption_Algorithms_Client_To_Server),
         Result_Item.Cipher_Client_To_Server);
      if Status_Value /= Ok then
         Clear (Result_Item);
         return Status_Value;
      end if;

      Status_Value := Select_Required
        (SSH_Lib.Algorithms.Encryption_Server_To_Client,
         To_String (Client_Item.Encryption_Algorithms_Server_To_Client),
         To_String (Server_Item.Encryption_Algorithms_Server_To_Client),
         Result_Item.Cipher_Server_To_Client);
      if Status_Value /= Ok then
         Clear (Result_Item);
         return Status_Value;
      end if;

      Status_Value := Select_Required
        (SSH_Lib.Algorithms.Mac_Client_To_Server,
         To_String (Client_Item.Mac_Algorithms_Client_To_Server),
         To_String (Server_Item.Mac_Algorithms_Client_To_Server),
         Result_Item.Mac_Client_To_Server);
      if Status_Value /= Ok then
         Clear (Result_Item);
         return Status_Value;
      end if;

      Status_Value := Select_Required
        (SSH_Lib.Algorithms.Mac_Server_To_Client,
         To_String (Client_Item.Mac_Algorithms_Server_To_Client),
         To_String (Server_Item.Mac_Algorithms_Server_To_Client),
         Result_Item.Mac_Server_To_Client);
      if Status_Value /= Ok then
         Clear (Result_Item);
         return Status_Value;
      end if;

      Status_Value := Select_Required
        (SSH_Lib.Algorithms.Compression_Client_To_Server,
         To_String (Client_Item.Compression_Algorithms_Client_To_Server),
         To_String (Server_Item.Compression_Algorithms_Client_To_Server),
         Result_Item.Compression_Client_To_Server);
      if Status_Value /= Ok then
         Clear (Result_Item);
         return Status_Value;
      end if;

      Status_Value := Select_Required
        (SSH_Lib.Algorithms.Compression_Server_To_Client,
         To_String (Client_Item.Compression_Algorithms_Server_To_Client),
         To_String (Server_Item.Compression_Algorithms_Server_To_Client),
         Result_Item.Compression_Server_To_Client);
      if Status_Value /= Ok then
         Clear (Result_Item);
         return Status_Value;
      end if;

      return Ok;
   exception
      when others =>
         Clear (Result_Item);
         return Internal_Error;
   end Negotiate;
end SSH_Lib.Protocol.Kex;
