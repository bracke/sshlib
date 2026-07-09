--  @summary High-level SSH client handle.
--
--  A lightweight tagged, limited container that anchors the client-side API;
--  create one with Create before opening sessions and channels through it.
package SSH_Lib.Clients is
   type Client is tagged limited private;

   --  Create a new, initialized SSH client handle.
   --  @return a freshly initialized Client value
   function Create return Client;

private
   type Client is tagged limited record
      Initialized : Boolean := True;
   end record;
end SSH_Lib.Clients;
