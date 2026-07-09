with Ada.Strings.Unbounded;
with CryptoLib.Errors;

--  @summary SSH transport algorithm advertisement and negotiation (KEX,
--  host-key, cipher, MAC, and compression name lists): the default offered
--  set plus recognition of algorithms usable when re-enabled by config.
package SSH_Lib.Algorithms is

   type Algorithm_Class is
     (Key_Exchange,
      Server_Host_Key,
      Encryption_Client_To_Server,
      Encryption_Server_To_Client,
      Mac_Client_To_Server,
      Mac_Server_To_Client,
      Compression_Client_To_Server,
      Compression_Server_To_Client);

   type Support_Status is
     (Unsupported,
      Extension_Only,
      Available);

   --  Test whether a string is a syntactically valid SSH algorithm name token.
   --  @param Name_Text the candidate algorithm name
   --  @return True if it is non-empty and contains only allowed printable characters (no comma)
   function Is_Valid_Algorithm_Name (Name_Text : String) return Boolean;

   --  Classify how an algorithm name is supported within a given algorithm class.
   --  @param Class_Item the algorithm class the name belongs to
   --  @param Name_Text  the algorithm name to classify
   --  @return Available if usable, Extension_Only for negotiation markers, Unsupported otherwise
   function Support_For
     (Class_Item : Algorithm_Class;
      Name_Text  : String)
      return Support_Status;

   --  Test whether an algorithm name is usable (Available) in a given class.
   --  @param Class_Item the algorithm class the name belongs to
   --  @param Name_Text  the algorithm name to test
   --  @return True if Support_For returns Available
   function Is_Supported
     (Class_Item : Algorithm_Class;
      Name_Text  : String)
      return Boolean;

   --  Return this library's advertised name-list for a class, in preference order.
   --  @param Class_Item the algorithm class to advertise
   --  @return the comma-separated name-list to send in KEXINIT
   function Advertised_Name_List
     (Class_Item : Algorithm_Class)
      return String;

   --  Test whether a comma-separated name-list is syntactically well-formed.
   --  @param List_Text the comma-separated name-list to validate
   --  @return True if every element is a valid algorithm name
   function Validate_Name_List (List_Text : String) return Boolean;

   --  Test whether a comma-separated name-list contains a specific name.
   --  @param List_Text the comma-separated name-list to search
   --  @param Name_Text the algorithm name to look for
   --  @return True if Name_Text appears as an element of List_Text
   function Contains_Name
     (List_Text : String;
      Name_Text : String)
      return Boolean;

   --  Negotiate the first locally preferred name that the remote peer also offers.
   --  @param Class_Item        the algorithm class being negotiated
   --  @param Local_Preferences the local name-list in preference order
   --  @param Remote_Offered    the remote peer's offered name-list
   --  @param Result_Name       the selected algorithm name on success
   --  @return Ok on a match, an error status if no mutually supported algorithm exists
   function Select_Algorithm
     (Class_Item        : Algorithm_Class;
      Local_Preferences : String;
      Remote_Offered    : String;
      Result_Name       : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;
end SSH_Lib.Algorithms;
