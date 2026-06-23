with Ada.Strings.Unbounded;
with Ada.Streams;
with SSH_Lib.Config;
with CryptoLib.Errors;
with SSH_Lib.Channels;
with SSH_Lib.Git;
with SSH_Lib.Sessions;

package SSH_Lib.Git_Transport is
   type Service is
     (Upload_Pack,
      Receive_Pack);

   type Git_Workflow_Summary is record
      Requested            : Service := Upload_Pack;
      Request_Bytes        : Natural := 0;
      Response_Bytes       : Natural := 0;
      Exit_Code            : Integer := 0;
      Remote_Exit_Observed : Boolean := False;
      Response_Validated   : Boolean := False;
      Upload_Response      : SSH_Lib.Git.Upload_Pack_Response_Summary;
      Receive_Report       : SSH_Lib.Git.Receive_Pack_Report_Summary;
   end record;

   function Prepare
     (Remote_Text  : String;
      Config       : SSH_Lib.Config.Host_Config;
      Default_User : String;
      Requested    : Service;
      Options      : out SSH_Lib.Sessions.Session_Options;
      Command      : out Ada.Strings.Unbounded.Unbounded_String)
      return CryptoLib.Errors.Status;

   function Open_Service
     (Session   : in out SSH_Lib.Sessions.Session;
      Requested : Service;
      Command   : String;
      Channel   : in out SSH_Lib.Channels.Channel)
      return CryptoLib.Errors.Status;

   function Complete_Service
     (Channel  : in out SSH_Lib.Channels.Channel;
      Requested : Service;
      Request  : Ada.Streams.Stream_Element_Array;
      Response : out Ada.Streams.Stream_Element_Array;
      Last     : out Ada.Streams.Stream_Element_Offset;
      Summary  : out Git_Workflow_Summary)
      return CryptoLib.Errors.Status;

   function Run_Service
     (Session   : in out SSH_Lib.Sessions.Session;
      Requested : Service;
      Command   : String;
      Request   : Ada.Streams.Stream_Element_Array;
      Response  : out Ada.Streams.Stream_Element_Array;
      Last      : out Ada.Streams.Stream_Element_Offset;
      Summary   : out Git_Workflow_Summary)
      return CryptoLib.Errors.Status;
end SSH_Lib.Git_Transport;
