package body SSH_Lib.Tests.Fixtures.Temp_Paths is

   function Path (Name : String) return String is
   begin
      return "/tmp/ssh_lib_phase16_" & Name;
   end Path;
end SSH_Lib.Tests.Fixtures.Temp_Paths;
