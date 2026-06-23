with Ada.Streams;
with Ada.Strings.Unbounded;
with CryptoLib.Errors;

package SSH_Lib.Public_Key_Blobs is
   function Algorithm_Name
     (Key_Blob : Ada.Streams.Stream_Element_Array;
      Name     : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   function Is_Default_Userauth_Algorithm
     (Name : String)
      return Boolean;
end SSH_Lib.Public_Key_Blobs;
