with SSH_Lib.Known_Hosts;

package SSH_Lib.Tests.Fixtures.Known_Hosts is
   procedure Write_Matching_File
     (Path : String;
      Host : String;
      Port : Natural := 22);

   procedure Write_Changed_File
     (Path : String;
      Host : String;
      Port : Natural := 22);

   function Fixture_Host_Key return SSH_Lib.Known_Hosts.Host_Key;
end SSH_Lib.Tests.Fixtures.Known_Hosts;
