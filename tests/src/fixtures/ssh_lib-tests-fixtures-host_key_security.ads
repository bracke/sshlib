package SSH_Lib.Tests.Fixtures.Host_Key_Security is
   procedure Assert_Host_Key_Verification_Order_And_Trust;
   procedure Assert_Known_Hosts_Record_Matching_Matrix;
   procedure Assert_Known_Hosts_Fail_Closed_Matching_Records;
   procedure Assert_Known_Hosts_Wildcard_And_Hashed_Matrix;
   procedure Assert_Known_Hosts_Load_And_Key_Normalization;
   procedure Assert_OpenSSH_Certificate_Critical_Option_Policy;
   procedure Assert_Host_Certificate_Revocation_Edges;
end SSH_Lib.Tests.Fixtures.Host_Key_Security;
