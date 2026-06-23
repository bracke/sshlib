with Ada.Streams;
with Ada.Strings.Unbounded;
with SSH_Lib.Channels;
with CryptoLib.Errors;
with SSH_Lib.Sessions;

package SSH_Lib.SCP is
   Maximum_Remote_Path_Length : constant Natural := 65_536;
   Maximum_File_Name_Length : constant Natural := 255;
   --  Maximum local file bytes read and written per streamed upload chunk.
   Upload_Chunk_Size : constant Natural := 32_768;

   --  Build an OpenSSH-compatible SCP sink command for an exact remote path.
   --  Remote_Path is emitted as one POSIX-style single-quoted remote command
   --  argument after "scp -t --". Empty paths, NUL, CR, LF, oversized paths,
   --  and commands that exceed SSH_Lib.Protocol.Channels limits are rejected.
   function Build_Upload_Command
     (Remote_Path : String;
      Command     : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Build the SCP "C<mode> <size> <name>\n" header for one regular file.
   --  File_Name is the protocol filename, not a path. It must be non-empty,
   --  not "." or "..", at most Maximum_File_Name_Length bytes, and must
   --  not contain '/', NUL, CR, or LF. Mode must be four octal digits.
   function Build_File_Header
     (File_Name : String;
      Size      : Natural;
      Mode      : String;
      Header    : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Upload one regular file over an already-open SCP sink channel. The
   --  channel must be an accepted exec channel running an SCP sink command
   --  such as Build_Upload_Command's result. File_Name and Mode follow
   --  Build_File_Header validation. The operation consumes the initial SCP
   --  ACK, writes one complete file frame, consumes the final ACK, and sends
   --  SSH EOF.
   function Upload_Data
     (Channel   : in out SSH_Lib.Channels.Channel;
      File_Name : String;
      Data      : Ada.Streams.Stream_Element_Array;
      Mode      : String := "0644")
      return CryptoLib.Errors.Status;

   --  Open an SCP sink command on Session and upload one regular file.
   --  Remote_Path follows Build_Upload_Command validation, and File_Name and
   --  Mode follow Build_File_Header validation. The opened channel is closed
   --  before this function returns.
   function Upload_Data
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      File_Name   : String;
      Data        : Ada.Streams.Stream_Element_Array;
      Mode        : String := "0644")
      return CryptoLib.Errors.Status;

   --  Stream Local_Path as binary data over an already-open SCP sink channel.
   --  The remote protocol filename is derived from the local path's simple
   --  name and follows Build_File_Header filename validation.
   function Upload_File
     (Channel    : in out SSH_Lib.Channels.Channel;
      Local_Path : String;
      Mode       : String := "0644")
      return CryptoLib.Errors.Status;

   --  Stream Local_Path as binary data using an explicit remote protocol
   --  filename over an already-open SCP sink channel. File_Name and Mode
   --  follow Build_File_Header validation.
   function Upload_File
     (Channel    : in out SSH_Lib.Channels.Channel;
      Local_Path : String;
      File_Name  : String;
      Mode       : String := "0644")
      return CryptoLib.Errors.Status;

   --  Open an SCP sink command on Session, stream Local_Path as binary data,
   --  and upload it using the local path's simple name as the protocol name.
   --  Remote_Path follows Build_Upload_Command validation, and the derived
   --  name follows Build_File_Header filename validation.
   function Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      Mode        : String := "0644")
      return CryptoLib.Errors.Status;

   --  Open an SCP sink command on Session, stream Local_Path as binary data,
   --  and upload it using an explicit remote protocol filename. Remote_Path
   --  follows Build_Upload_Command validation, and File_Name and Mode follow
   --  Build_File_Header validation.
   function Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      File_Name   : String;
      Mode        : String := "0644")
      return CryptoLib.Errors.Status;
end SSH_Lib.SCP;
