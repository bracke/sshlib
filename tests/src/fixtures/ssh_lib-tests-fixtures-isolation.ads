package SSH_Lib.Tests.Fixtures.Isolation is
   type Fixture_Policy is record
      Uses_Public_Network      : Boolean := False;
      Uses_Real_Home           : Boolean := False;
      Uses_Real_Known_Hosts    : Boolean := False;
      Uses_Real_SSH_Agent      : Boolean := False;
      Uses_Real_Private_Keys   : Boolean := False;
      Executes_Subprocesses    : Boolean := False;
      Executes_Received_Exec   : Boolean := False;
      Uses_C_Fixture_Code      : Boolean := False;
   end record;

   function Default_Policy return Fixture_Policy;
   function Is_Isolated (Item : Fixture_Policy) return Boolean;
   function Policy_Name (Item : Fixture_Policy) return String;
end SSH_Lib.Tests.Fixtures.Isolation;
