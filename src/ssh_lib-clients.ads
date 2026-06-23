package SSH_Lib.Clients is
   type Client is tagged limited private;

   function Create return Client;

private
   type Client is tagged limited record
      Initialized : Boolean := True;
   end record;
end SSH_Lib.Clients;
