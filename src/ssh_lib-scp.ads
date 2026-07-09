with Ada.Streams;
with Ada.Strings.Unbounded;
with SSH_Lib.Channels;
with CryptoLib.Errors;
with SSH_Lib.Sessions;

--  @summary OpenSSH-compatible SCP (sink protocol) file uploads over an SSH channel.
--
--  Builds the "scp -t --" sink command and the "C<mode> <size> <name>" file
--  headers, and streams regular files to a remote path either over an already
--  open exec channel or by opening one on a session.  All names and modes are
--  validated to reject path traversal and control characters.
package SSH_Lib.SCP is
   Maximum_Remote_Path_Length : constant Natural := 65_536;
   Maximum_File_Name_Length : constant Natural := 255;
   --  Maximum local file bytes read and written per streamed upload chunk.
   Upload_Chunk_Size : constant Natural := 32_768;

   --  Build an OpenSSH-compatible SCP sink command for an exact remote path.
   --  Remote_Path is emitted as one POSIX-style single-quoted remote command
   --  argument after "scp -t --". Empty paths, NUL, CR, LF, oversized paths,
   --  and commands that exceed SSH_Lib.Protocol.Channels limits are rejected.
   --  @param Remote_Path the exact destination path on the remote host
   --  @param Command     the built "scp -t --" sink command line
   --  @return Ok on success, an error status if Remote_Path is invalid or too long
   function Build_Upload_Command
     (Remote_Path : String;
      Command     : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   --  Build the SCP "C<mode> <size> <name>\n" header for one regular file.
   --  File_Name is the protocol filename, not a path. It must be non-empty,
   --  not "." or "..", at most Maximum_File_Name_Length bytes, and must
   --  not contain '/', NUL, CR, or LF. Mode must be four octal digits.
   --  @param File_Name the protocol filename (not a path)
   --  @param Size      the file size in bytes announced in the header
   --  @param Mode      the four-octal-digit file mode
   --  @param Header    the built "C<mode> <size> <name>\n" header line
   --  @return Ok on success, an error status if File_Name, Size, or Mode is invalid
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
   --  @param Channel   the open SCP sink exec channel to write to
   --  @param File_Name the remote protocol filename
   --  @param Data      the file contents to upload
   --  @param Mode      the four-octal-digit file mode
   --  @return Ok on success, an error status on validation or channel failure
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
   --  @param Session     the open session on which to open the SCP sink channel
   --  @param Remote_Path the exact destination path on the remote host
   --  @param File_Name   the remote protocol filename
   --  @param Data        the file contents to upload
   --  @param Mode        the four-octal-digit file mode
   --  @return Ok on success, an error status on validation or transfer failure
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
   --  @param Channel    the open SCP sink exec channel to write to
   --  @param Local_Path the local file to read and stream
   --  @param Mode       the four-octal-digit file mode
   --  @return Ok on success, an error status on validation, read, or channel failure
   function Upload_File
     (Channel    : in out SSH_Lib.Channels.Channel;
      Local_Path : String;
      Mode       : String := "0644")
      return CryptoLib.Errors.Status;

   --  Stream Local_Path as binary data using an explicit remote protocol
   --  filename over an already-open SCP sink channel. File_Name and Mode
   --  follow Build_File_Header validation.
   --  @param Channel    the open SCP sink exec channel to write to
   --  @param Local_Path the local file to read and stream
   --  @param File_Name  the remote protocol filename to use
   --  @param Mode       the four-octal-digit file mode
   --  @return Ok on success, an error status on validation, read, or channel failure
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
   --  @param Session     the open session on which to open the SCP sink channel
   --  @param Remote_Path the exact destination path on the remote host
   --  @param Local_Path  the local file to read and stream
   --  @param Mode        the four-octal-digit file mode
   --  @return Ok on success, an error status on validation or transfer failure
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
   --  @param Session     the open session on which to open the SCP sink channel
   --  @param Remote_Path the exact destination path on the remote host
   --  @param Local_Path  the local file to read and stream
   --  @param File_Name   the remote protocol filename to use
   --  @param Mode        the four-octal-digit file mode
   --  @return Ok on success, an error status on validation or transfer failure
   function Upload_File
     (Session     : in out SSH_Lib.Sessions.Session;
      Remote_Path : String;
      Local_Path  : String;
      File_Name   : String;
      Mode        : String := "0644")
      return CryptoLib.Errors.Status;
end SSH_Lib.SCP;
