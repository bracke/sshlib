package body SSH_Lib.Clients is
   function Create return Client is
   begin
      return Result : Client do
         Result.Initialized := True;
      end return;
   end Create;
end SSH_Lib.Clients;
