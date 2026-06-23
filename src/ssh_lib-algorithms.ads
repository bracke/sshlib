with Ada.Strings.Unbounded;
with CryptoLib.Errors;

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

   function Is_Valid_Algorithm_Name (Name_Text : String) return Boolean;

   function Support_For
     (Class_Item : Algorithm_Class;
      Name_Text  : String)
      return Support_Status;

   function Is_Supported
     (Class_Item : Algorithm_Class;
      Name_Text  : String)
      return Boolean;

   function Advertised_Name_List
     (Class_Item : Algorithm_Class)
      return String;

   function Validate_Name_List (List_Text : String) return Boolean;

   function Contains_Name
     (List_Text : String;
      Name_Text : String)
      return Boolean;

   function Select_Algorithm
     (Class_Item        : Algorithm_Class;
      Local_Preferences : String;
      Remote_Offered    : String;
      Result_Name       : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;
end SSH_Lib.Algorithms;
