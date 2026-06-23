with Ada.Text_IO;
with CryptoLib.Errors;
with SSH_Lib.Clients;

procedure Package_Smoke_Main is
   Client_Item : SSH_Lib.Clients.Client := SSH_Lib.Clients.Create;
   pragma Unreferenced (Client_Item);
begin
   if not CryptoLib.Errors.Is_Success (CryptoLib.Errors.Ok) then
      raise Program_Error;
   end if;

   Ada.Text_IO.Put_Line ("ssh_lib package smoke check");
end Package_Smoke_Main;
