with AUnit.Test_Cases;

package SSH_Lib.Tests.Legacy_Case is
   type Test_Case is new AUnit.Test_Cases.Test_Case with null record;

   overriding procedure Register_Tests (Item : in out Test_Case);
   overriding function Name (Item : Test_Case) return AUnit.Message_String;
end SSH_Lib.Tests.Legacy_Case;
