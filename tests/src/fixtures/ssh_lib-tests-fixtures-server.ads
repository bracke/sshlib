with Ada.Streams;
with Interfaces;
with SSH_Lib.Channels;
with CryptoLib.Errors;
with SSH_Lib.Sessions;
with SSH_Lib.Tests.Fixtures.Protocol_Scripts;

package SSH_Lib.Tests.Fixtures.Server is
   subtype Scenario is SSH_Lib.Tests.Fixtures.Protocol_Scripts.Scenario;

   type Fixture is private;

   procedure Start (Item : out Fixture; Selected_Scenario : Scenario);

   function Scenario_Name (Item : Fixture) return String;

   procedure Prepare_Authenticated_Session
     (Item    : Fixture;
      Session : in out SSH_Lib.Sessions.Session);

   function Open_Exec
     (Item    : Fixture;
      Session : in out SSH_Lib.Sessions.Session;
      Command : String;
      Channel : out SSH_Lib.Channels.Channel) return CryptoLib.Errors.Status;

   function Feed_Stdout
     (Item    : Fixture;
      Channel : in out SSH_Lib.Channels.Channel;
      Data    : Ada.Streams.Stream_Element_Array) return CryptoLib.Errors.Status;

   function Feed_Stderr
     (Item    : Fixture;
      Channel : in out SSH_Lib.Channels.Channel;
      Data    : Ada.Streams.Stream_Element_Array) return CryptoLib.Errors.Status;

   function Feed_EOF
     (Item    : Fixture;
      Channel : in out SSH_Lib.Channels.Channel) return CryptoLib.Errors.Status;

   function Feed_Window_Adjust
     (Item         : Fixture;
      Channel      : in out SSH_Lib.Channels.Channel;
      Bytes_To_Add : Interfaces.Unsigned_32) return CryptoLib.Errors.Status;

   function Feed_Close
     (Item    : Fixture;
      Channel : in out SSH_Lib.Channels.Channel) return CryptoLib.Errors.Status;

   function Feed_Exit_Status
     (Item    : Fixture;
      Channel : in out SSH_Lib.Channels.Channel;
      Code    : Natural) return CryptoLib.Errors.Status;

   function Last_Exec_Command
     (Session : SSH_Lib.Sessions.Session) return String;

private
   type Fixture is record
      Active_Scenario : Scenario := SSH_Lib.Tests.Fixtures.Protocol_Scripts.Happy_Path;
   end record;
end SSH_Lib.Tests.Fixtures.Server;
