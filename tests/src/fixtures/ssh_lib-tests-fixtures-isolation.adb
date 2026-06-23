package body SSH_Lib.Tests.Fixtures.Isolation is

   function Default_Policy return Fixture_Policy is
   begin
      return
        (Uses_Public_Network    => False,
         Uses_Real_Home         => False,
         Uses_Real_Known_Hosts  => False,
         Uses_Real_SSH_Agent    => False,
         Uses_Real_Private_Keys => False,
         Executes_Subprocesses  => False,
         Executes_Received_Exec => False,
         Uses_C_Fixture_Code    => False);
   end Default_Policy;

   function Is_Isolated (Item : Fixture_Policy) return Boolean is
   begin
      return not Item.Uses_Public_Network
        and then not Item.Uses_Real_Home
        and then not Item.Uses_Real_Known_Hosts
        and then not Item.Uses_Real_SSH_Agent
        and then not Item.Uses_Real_Private_Keys
        and then not Item.Executes_Subprocesses
        and then not Item.Executes_Received_Exec
        and then not Item.Uses_C_Fixture_Code;
   end Is_Isolated;

   function Policy_Name (Item : Fixture_Policy) return String is
   begin
      if Is_Isolated (Item) then
         return "default-local-ada-fixture-policy";
      end if;
      return "unsafe-fixture-policy";
   end Policy_Name;
end SSH_Lib.Tests.Fixtures.Isolation;
