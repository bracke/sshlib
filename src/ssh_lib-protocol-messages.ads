package SSH_Lib.Protocol.Messages is
   pragma Pure;

   SSH_MSG_DISCONNECT      : constant Natural := 1;
   SSH_MSG_IGNORE          : constant Natural := 2;
   SSH_MSG_UNIMPLEMENTED   : constant Natural := 3;
   SSH_MSG_DEBUG           : constant Natural := 4;
   SSH_MSG_SERVICE_REQUEST : constant Natural := 5;
   SSH_MSG_SERVICE_ACCEPT  : constant Natural := 6;
   SSH_MSG_EXT_INFO        : constant Natural := 7;
   SSH_MSG_KEXINIT         : constant Natural := 20;
   SSH_MSG_NEWKEYS         : constant Natural := 21;
end SSH_Lib.Protocol.Messages;
