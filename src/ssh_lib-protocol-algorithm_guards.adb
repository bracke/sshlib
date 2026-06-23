with CryptoLib.Hybrid_PQ_Kex;
with CryptoLib.UMAC;

package body SSH_Lib.Protocol.Algorithm_Guards is
   use type SSH_Lib.Algorithms.Support_Status;
   use type SSH_Lib.Algorithms.Algorithm_Class;

   function Contains_Name
     (List_Text : String;
      Name_Text : String)
      return Boolean
   is
      Start_Index : Positive := List_Text'First;
      Stop_Index  : Natural;
   begin
      if List_Text'Length = 0 or else Name_Text'Length = 0 then
         return False;
      end if;

      loop
         Stop_Index := Start_Index;
         while Stop_Index <= List_Text'Last
           and then List_Text (Stop_Index) /= ','
         loop
            Stop_Index := Stop_Index + 1;
         end loop;

         if List_Text (Start_Index .. Stop_Index - 1) = Name_Text then
            return True;
         end if;

         exit when Stop_Index > List_Text'Last;
         Start_Index := Stop_Index + 1;
      end loop;

      return False;
   exception
      when others =>
         return False;
   end Contains_Name;

   function Selected_Algorithm_Accepted
     (Class_Item        : SSH_Lib.Algorithms.Algorithm_Class;
      Client_Advertised : String;
      Selected_Name     : String)
      return CryptoLib.Errors.Status
   is
   begin
      if not SSH_Lib.Algorithms.Validate_Name_List (Client_Advertised)
        or else not SSH_Lib.Algorithms.Is_Valid_Algorithm_Name (Selected_Name)
      then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      if not Contains_Name (Client_Advertised, Selected_Name) then
         --  A peer may not switch to an algorithm outside the list that this
         --  client advertised for the negotiated direction/class.
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      if CryptoLib.UMAC.Is_OpenSSH_UMAC_Name (Selected_Name)
        and then Class_Item in SSH_Lib.Algorithms.Mac_Client_To_Server
                           | SSH_Lib.Algorithms.Mac_Server_To_Client
        and then not CryptoLib.UMAC.Is_Implemented (Selected_Name)
      then
         return CryptoLib.UMAC.Fail_Closed_Status (Selected_Name);
      end if;

      if not SSH_Lib.Algorithms.Is_Supported (Class_Item, Selected_Name) then
         --  The client must not accept legacy or unimplemented algorithms even
         --  if a malformed peer claims they were selected.
         return CryptoLib.Errors.Unsupported_Feature;
      end if;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Selected_Algorithm_Accepted;

   function Kex_Reply_Consistent
     (Negotiated_Key_Exchange : String;
      Reply_Key_Exchange      : String)
      return CryptoLib.Errors.Status
   is
   begin
      if Negotiated_Key_Exchange'Length = 0
        or else Reply_Key_Exchange'Length = 0
        or else not SSH_Lib.Algorithms.Is_Valid_Algorithm_Name (Negotiated_Key_Exchange)
        or else not SSH_Lib.Algorithms.Is_Valid_Algorithm_Name (Reply_Key_Exchange)
      then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      if Negotiated_Key_Exchange /= Reply_Key_Exchange then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      if CryptoLib.Hybrid_PQ_Kex.Is_OpenSSH_Hybrid_PQ_Kex_Name
        (Negotiated_Key_Exchange)
        and then not CryptoLib.Hybrid_PQ_Kex.Is_Implemented
          (Negotiated_Key_Exchange)
      then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;

      if not SSH_Lib.Algorithms.Is_Supported
        (SSH_Lib.Algorithms.Key_Exchange, Negotiated_Key_Exchange)
      then
         return CryptoLib.Errors.Unsupported_Feature;
      end if;

      return CryptoLib.Errors.Ok;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Kex_Reply_Consistent;

   function Compression_Is_None
     (Selected_Name : String)
      return CryptoLib.Errors.Status
   is
   begin
      if not SSH_Lib.Algorithms.Is_Valid_Algorithm_Name (Selected_Name) then
         return CryptoLib.Errors.Handshake_Failed;
      end if;

      if SSH_Lib.Algorithms.Support_For
        (SSH_Lib.Algorithms.Compression_Client_To_Server, Selected_Name)
        = SSH_Lib.Algorithms.Available
      then
         return CryptoLib.Errors.Ok;
      end if;

      return CryptoLib.Errors.Unsupported_Feature;
   exception
      when others =>
         return CryptoLib.Errors.Internal_Error;
   end Compression_Is_None;
end SSH_Lib.Protocol.Algorithm_Guards;
