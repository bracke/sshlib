with CryptoLib.Errors;
with SSH_Lib.Channels;
with SSH_Lib.Forwarding;
with SSH_Lib.Sessions;

package SSH_Lib.Config_Apply is
   Max_Configured_Forwards : constant Positive := 16;

   type Managed_Forward_Service_Array is array (Positive range <>)
     of SSH_Lib.Forwarding.Managed_Forward_Service;

   type Bound_Port_Array is array (Positive range <>) of Natural;

   function Start_Configured_Local_Forwards
     (Session  : in out SSH_Lib.Sessions.Session;
      Options  : SSH_Lib.Sessions.Session_Options;
      Services : in out Managed_Forward_Service_Array;
      Started  : out Natural)
      return CryptoLib.Errors.Status;

   function Start_Configured_Dynamic_Forwards
     (Session  : in out SSH_Lib.Sessions.Session;
      Options  : SSH_Lib.Sessions.Session_Options;
      Services : in out Managed_Forward_Service_Array;
      Started  : out Natural)
      return CryptoLib.Errors.Status;

   function Request_Configured_Remote_Forwards
     (Session     : in out SSH_Lib.Sessions.Session;
      Options     : SSH_Lib.Sessions.Session_Options;
      Bound_Ports : out Bound_Port_Array;
      Requested   : out Natural)
      return CryptoLib.Errors.Status;

   function Apply_Configured_Environment
     (Session : in out SSH_Lib.Sessions.Session;
      Channel : in out SSH_Lib.Channels.Channel;
      Options : SSH_Lib.Sessions.Session_Options)
      return CryptoLib.Errors.Status;
end SSH_Lib.Config_Apply;
