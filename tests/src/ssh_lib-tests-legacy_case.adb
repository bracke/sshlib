with SSH_Lib.Tests.Legacy;

package body SSH_Lib.Tests.Legacy_Case is
   procedure Run_Error (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Session (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Channel (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Git_Helper (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Remote_Name (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Config (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Placeholder_Packages (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Identification (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Numbers (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Packets (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Algorithms (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Random (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Hashes (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_HMAC (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Constant_Time (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Ciphers (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Host_Keys (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Known_Hosts (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Kex (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Agent_Userauth (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Identity_Files (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Session_Lifecycle (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Channel_Protocol (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Channel_Stream (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Failure_Hygiene (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Local_Fixtures (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Version_Integration (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Version_Adapter (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Live_Channel_Transport (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Agent_Transport (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Host_Key_Security (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Algorithm_Security (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Crypto_Primitives (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Binary_Matrix (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Resource_Bounds (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Timeout_Dirty (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Exception_Containment (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Command_Quoting (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Config_Security (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Auth_Security (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Fuzz_Lite (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Hostile_Transcripts (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Session_Open_Success (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Open_Runtime (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Packet_Protection (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Context_Compliance (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Transport_Messages (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Side_Channel_Assurance (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Hybrid_PQ_OpenSSH_Transcripts (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_PQ_External_KATs (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Open_Option_Preflight (Item : in out AUnit.Test_Cases.Test_Case'Class);
   procedure Run_Security_Audit (Item : in out AUnit.Test_Cases.Test_Case'Class);

   procedure Run_Error (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Error_Tests;
   end Run_Error;

   procedure Run_Session (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Session_Tests;
   end Run_Session;

   procedure Run_Channel (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Channel_Tests;
   end Run_Channel;

   procedure Run_Git_Helper (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Git_Helper_Tests;
   end Run_Git_Helper;

   procedure Run_Remote_Name (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Remote_Name_Tests;
   end Run_Remote_Name;

   procedure Run_Config (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_14_Config_Tests;
   end Run_Config;

   procedure Run_Placeholder_Packages (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Placeholder_Package_Tests;
   end Run_Placeholder_Packages;

   procedure Run_Identification (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Identification_Tests;
   end Run_Identification;

   procedure Run_Numbers (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Number_Tests;
   end Run_Numbers;

   procedure Run_Packets (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Packet_Tests;
   end Run_Packets;

   procedure Run_Algorithms (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_4_Algorithm_Tests;
   end Run_Algorithms;

   procedure Run_Random (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_4_Random_Tests;
   end Run_Random;

   procedure Run_Hashes (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_4_Hash_Tests;
   end Run_Hashes;

   procedure Run_HMAC (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_4_HMAC_Tests;
   end Run_HMAC;

   procedure Run_Constant_Time (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_4_Constant_Time_Tests;
   end Run_Constant_Time;

   procedure Run_Ciphers (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_4_Cipher_Tests;
   end Run_Ciphers;

   procedure Run_Host_Keys (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_6_Host_Key_Tests;
   end Run_Host_Keys;

   procedure Run_Known_Hosts (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_7_Known_Hosts_Tests;
   end Run_Known_Hosts;

   procedure Run_Kex (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_5_Kex_Tests;
   end Run_Kex;

   procedure Run_Agent_Userauth (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_8_Agent_Userauth_Tests;
   end Run_Agent_Userauth;

   procedure Run_Identity_Files (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_9_Identity_File_Tests;
   end Run_Identity_Files;

   procedure Run_Session_Lifecycle (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_10_Session_Lifecycle_Tests;
   end Run_Session_Lifecycle;

   procedure Run_Channel_Protocol (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_11_Channel_Tests;
   end Run_Channel_Protocol;

   procedure Run_Channel_Stream (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_12_Channel_Stream_Tests;
   end Run_Channel_Stream;

   procedure Run_Failure_Hygiene (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_15_Failure_Hygiene_Tests;
   end Run_Failure_Hygiene;

   procedure Run_Local_Fixtures (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_16_Local_Fixture_Tests;
   end Run_Local_Fixtures;

   procedure Run_Version_Integration (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_18_Version_Integration_Tests;
   end Run_Version_Integration;

   procedure Run_Version_Adapter (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Version_Adapter_Consumption_Tests;
   end Run_Version_Adapter;

   procedure Run_Live_Channel_Transport (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Live_Channel_Transport_Fixture_Tests;
   end Run_Live_Channel_Transport;

   procedure Run_Agent_Transport (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Agent_Transport_Fixture_Tests;
   end Run_Agent_Transport;

   procedure Run_Host_Key_Security (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Host_Key_Security_Fixture_Tests;
   end Run_Host_Key_Security;

   procedure Run_Algorithm_Security (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Algorithm_Security_Fixture_Tests;
   end Run_Algorithm_Security;

   procedure Run_Crypto_Primitives (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Crypto_Primitive_Fixture_Tests;
   end Run_Crypto_Primitives;

   procedure Run_Binary_Matrix (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Binary_Matrix_Fixture_Tests;
   end Run_Binary_Matrix;

   procedure Run_Resource_Bounds (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Resource_Bounds_Fixture_Tests;
   end Run_Resource_Bounds;

   procedure Run_Timeout_Dirty (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Timeout_Dirty_Fixture_Tests;
   end Run_Timeout_Dirty;

   procedure Run_Exception_Containment (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Exception_Containment_Fixture_Tests;
   end Run_Exception_Containment;

   procedure Run_Command_Quoting (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Command_Quoting_Fixture_Tests;
   end Run_Command_Quoting;

   procedure Run_Config_Security (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Config_Security_Fixture_Tests;
   end Run_Config_Security;

   procedure Run_Auth_Security (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Auth_Security_Fixture_Tests;
   end Run_Auth_Security;

   procedure Run_Fuzz_Lite (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Fuzz_Lite_Fixture_Tests;
   end Run_Fuzz_Lite;

   procedure Run_Hostile_Transcripts (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Hostile_Transcript_Fixture_Tests;
   end Run_Hostile_Transcripts;

   procedure Run_Session_Open_Success (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Session_Open_Success_Fixture_Tests;
   end Run_Session_Open_Success;

   procedure Run_Open_Runtime (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Open_Runtime_Fixture_Tests;
   end Run_Open_Runtime;

   procedure Run_Packet_Protection (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Packet_Protection_Fixture_Tests;
   end Run_Packet_Protection;

   procedure Run_Context_Compliance (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Context_Compliance_Tests;
   end Run_Context_Compliance;

   procedure Run_Transport_Messages (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Transport_Message_Fixture_Tests;
   end Run_Transport_Messages;

   procedure Run_Side_Channel_Assurance (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Side_Channel_Assurance_Fixture_Tests;
   end Run_Side_Channel_Assurance;

   procedure Run_Hybrid_PQ_OpenSSH_Transcripts (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Hybrid_PQ_OpenSSH_Transcript_Fixture_Tests;
   end Run_Hybrid_PQ_OpenSSH_Transcripts;

   procedure Run_PQ_External_KATs (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_PQ_External_KAT_Fixture_Tests;
   end Run_PQ_External_KATs;

   procedure Run_Open_Option_Preflight (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Open_Option_Preflight_Tests;
   end Run_Open_Option_Preflight;

   procedure Run_Security_Audit (Item : in out AUnit.Test_Cases.Test_Case'Class) is
      pragma Unreferenced (Item);
   begin
      SSH_Lib.Tests.Legacy.Run_Phase_19_Security_Audit_Tests;
   end Run_Security_Audit;

   overriding procedure Register_Tests (Item : in out Test_Case) is
      use AUnit.Test_Cases.Registration;
   begin
      Register_Routine (Item, Run_Error'Access, "errors/status model");
      Register_Routine (Item, Run_Session'Access, "sessions public API");
      Register_Routine (Item, Run_Channel'Access, "channels public API");
      Register_Routine (Item, Run_Git_Helper'Access, "git helpers");
      Register_Routine (Item, Run_Remote_Name'Access, "remote names");
      Register_Routine (Item, Run_Config'Access, "config resolution");
      Register_Routine (Item, Run_Placeholder_Packages'Access, "placeholder packages");
      Register_Routine (Item, Run_Identification'Access, "identification protocol");
      Register_Routine (Item, Run_Numbers'Access, "protocol numbers");
      Register_Routine (Item, Run_Packets'Access, "packet framing");
      Register_Routine (Item, Run_Algorithms'Access, "algorithms");
      Register_Routine (Item, Run_Random'Access, "random source");
      Register_Routine (Item, Run_Hashes'Access, "hash primitives");
      Register_Routine (Item, Run_HMAC'Access, "hmac primitives");
      Register_Routine (Item, Run_Constant_Time'Access, "constant-time helpers");
      Register_Routine (Item, Run_Ciphers'Access, "cipher primitives");
      Register_Routine (Item, Run_Host_Keys'Access, "host key protocol");
      Register_Routine (Item, Run_Known_Hosts'Access, "known hosts");
      Register_Routine (Item, Run_Kex'Access, "key exchange");
      Register_Routine (Item, Run_Agent_Userauth'Access, "agent and userauth");
      Register_Routine (Item, Run_Identity_Files'Access, "identity files");
      Register_Routine (Item, Run_Session_Lifecycle'Access, "session lifecycle");
      Register_Routine (Item, Run_Channel_Protocol'Access, "channel protocol");
      Register_Routine (Item, Run_Channel_Stream'Access, "channel streams");
      Register_Routine (Item, Run_Failure_Hygiene'Access, "failure hygiene");
      Register_Routine (Item, Run_Local_Fixtures'Access, "local fixtures");
      Register_Routine (Item, Run_Version_Integration'Access, "version integration");
      Register_Routine (Item, Run_Version_Adapter'Access, "version adapter consumption");
      Register_Routine (Item, Run_Live_Channel_Transport'Access, "live channel transport fixture");
      Register_Routine (Item, Run_Agent_Transport'Access, "agent transport fixture");
      Register_Routine (Item, Run_Host_Key_Security'Access, "host-key security fixture");
      Register_Routine (Item, Run_Algorithm_Security'Access, "algorithm security fixture");
      Register_Routine (Item, Run_Crypto_Primitives'Access, "crypto primitive fixture");
      Register_Routine (Item, Run_Binary_Matrix'Access, "binary matrix fixture");
      Register_Routine (Item, Run_Resource_Bounds'Access, "resource bounds fixture");
      Register_Routine (Item, Run_Timeout_Dirty'Access, "timeout dirty fixture");
      Register_Routine (Item, Run_Exception_Containment'Access, "exception containment fixture");
      Register_Routine (Item, Run_Command_Quoting'Access, "command quoting fixture");
      Register_Routine (Item, Run_Config_Security'Access, "config security fixture");
      Register_Routine (Item, Run_Auth_Security'Access, "auth security fixture");
      Register_Routine (Item, Run_Fuzz_Lite'Access, "fuzz lite fixture");
      Register_Routine (Item, Run_Hostile_Transcripts'Access, "hostile transcript fixture");
      Register_Routine (Item, Run_Session_Open_Success'Access, "session open success fixture");
      Register_Routine (Item, Run_Open_Runtime'Access, "open runtime fixture");
      Register_Routine (Item, Run_Packet_Protection'Access, "packet protection fixture");
      Register_Routine (Item, Run_Context_Compliance'Access, "phase19 context compliance");
      Register_Routine (Item, Run_Transport_Messages'Access, "transport message fixture");
      Register_Routine (Item, Run_Side_Channel_Assurance'Access, "side-channel assurance fixture");
      Register_Routine (Item, Run_Hybrid_PQ_OpenSSH_Transcripts'Access, "hybrid PQ OpenSSH transcript fixture");
      Register_Routine (Item, Run_PQ_External_KATs'Access, "PQ external KAT fixture");
      Register_Routine (Item, Run_Open_Option_Preflight'Access, "open option preflight");
      Register_Routine (Item, Run_Security_Audit'Access, "security audit matrix");
   end Register_Tests;

   overriding function Name (Item : Test_Case) return AUnit.Message_String is
      pragma Unreferenced (Item);
   begin
      return AUnit.Format ("SSH_Lib legacy compatibility tests");
   end Name;
end SSH_Lib.Tests.Legacy_Case;
