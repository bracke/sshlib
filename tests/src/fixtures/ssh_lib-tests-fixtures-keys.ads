package SSH_Lib.Tests.Fixtures.Keys is
   Test_Host_Key_Algorithm : constant String := "ssh-ed25519";
   Test_Host_Key_Blob      : constant String :=
     "AAAAC3NzaC1lZDI1NTE5AAAAIAAKDX+A/zE4P0ZNVFtiaXB3foWMk5qhqK+2vcTL0tng";
   Alternate_Host_Key_Blob : constant String :=
     "AAAAC3NzaC1lZDI1NTE5AAAAIAAKDX+A/zE4P0ZNVFtiaXB3foWMk5qhqK+2vcTL0tnh";
   Test_Client_Key_Algorithm : constant String := "ssh-ed25519";
   Test_Client_Key_Comment   : constant String := "ada-ssh-public-test-fixture-only";
end SSH_Lib.Tests.Fixtures.Keys;
