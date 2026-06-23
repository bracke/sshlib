package SSH_Lib.Tests.Fixtures.Manual_Interop is
   type Interop_Policy is record
      Enabled_By_Default       : Boolean := False;
      Uses_Public_Network      : Boolean := False;
      Uses_Real_Home           : Boolean := False;
      Uses_Real_Known_Hosts    : Boolean := False;
      Uses_Real_SSH_Agent      : Boolean := False;
      Mutates_Real_Known_Hosts : Boolean := False;
   end record;

   -- function Default_Policy return Interop_Policy;
  -- function Safe_For_Default_Run (Item : Interop_Policy) return Boolean;
end SSH_Lib.Tests.Fixtures.Manual_Interop;
