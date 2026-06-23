package body SSH_Lib.Tests.Fixtures.Manual_Interop is

   function Default_Policy return Interop_Policy is
   begin
      return
        (Enabled_By_Default       => False,
         Uses_Public_Network      => False,
         Uses_Real_Home           => False,
         Uses_Real_Known_Hosts    => False,
         Uses_Real_SSH_Agent      => False,
         Mutates_Real_Known_Hosts => False);
   end Default_Policy;

   function Safe_For_Default_Run (Item : Interop_Policy) return Boolean is
   begin
      return not Item.Enabled_By_Default
        and then not Item.Uses_Public_Network
        and then not Item.Uses_Real_Home
        and then not Item.Uses_Real_Known_Hosts
        and then not Item.Uses_Real_SSH_Agent
        and then not Item.Mutates_Real_Known_Hosts;
   end Safe_For_Default_Run;
end SSH_Lib.Tests.Fixtures.Manual_Interop;
