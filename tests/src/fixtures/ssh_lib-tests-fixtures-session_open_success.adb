with Ada.Text_IO;
with SSH_Lib.Channels;
with CryptoLib.Errors;
with SSH_Lib.Sessions;
with SSH_Lib.Sessions.Open_Guards;
with SSH_Lib.Sessions.Test_Support;
with SSH_Lib.Tests.Assertions;

package body SSH_Lib.Tests.Fixtures.Session_Open_Success is

   use type CryptoLib.Errors.Status;
   use type SSH_Lib.Sessions.Open_Guards.Open_Success_Gate;

   procedure Check (Condition : Boolean; Label_Text : String) is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("FAILED: " & Label_Text);
         raise Program_Error;
      end if;
   end Check;

   procedure Assert_Session_Open_Success_Gates is
      Session_Item : SSH_Lib.Sessions.Session;
      Channel_Item : SSH_Lib.Channels.Channel;
      Status_Value : CryptoLib.Errors.Status;
   begin
      Status_Value :=
        SSH_Lib.Sessions.Test_Support.Run_Hostile_Open_Transcript_For_Test
          (Session_Item,
           SSH_Lib.Sessions.Test_Support.Transcript_Happy_Path);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Ok,
         "session open success gate", "happy transcript completes");

      Check
        (SSH_Lib.Sessions.Open_Guards.Success_Gates_Complete (Session_Item),
         "Sessions.Open success gate requires transport, kex, encryption, host trust, and authentication");
      Check
        (SSH_Lib.Sessions.Open_Guards.Public_Open_State_Consistent (Session_Item),
         "Sessions.Open Ok state is public-open only after all security gates complete");
      SSH_Lib.Tests.Assertions.Check_Status
        (SSH_Lib.Sessions.Open_Guards.Status_For_Incomplete_Gates (Session_Item),
         CryptoLib.Errors.Ok,
         "session open success gate", "complete gate status is Ok");

      Status_Value := SSH_Lib.Channels.Open_Exec
        (Session_Item, "git-upload-pack 'repo.git'", Channel_Item);
      SSH_Lib.Tests.Assertions.Check_Status
        (Status_Value, CryptoLib.Errors.Channel_Open_Failed,
         "session open success gate",
         "fully open authenticated session reaches channel-open boundary");

      for Gate in SSH_Lib.Sessions.Open_Guards.Open_Success_Gate loop
         SSH_Lib.Sessions.Test_Support.Mark_Open_Success_Gates_For_Test (Session_Item);
         SSH_Lib.Sessions.Test_Support.Clear_Open_Success_Gate_For_Test
           (Session_Item, Gate);

         Check
           (not SSH_Lib.Sessions.Open_Guards.Success_Gates_Complete (Session_Item),
            "missing gate blocks Sessions.Open Ok: "
            & SSH_Lib.Sessions.Open_Guards.Gate_Label (Gate));
         Check
           (not SSH_Lib.Sessions.Open_Guards.Public_Open_State_Consistent (Session_Item),
            "public open state rejects incomplete security gate: "
            & SSH_Lib.Sessions.Open_Guards.Gate_Label (Gate));
         Check
           (SSH_Lib.Sessions.Open_Guards.First_Missing_Gate (Session_Item) = Gate,
            "first missing gate reports exact incomplete gate: "
            & SSH_Lib.Sessions.Open_Guards.Gate_Label (Gate));
         Check
           (SSH_Lib.Sessions.Open_Guards.Status_For_Incomplete_Gates (Session_Item)
            /= CryptoLib.Errors.Ok,
            "incomplete Sessions.Open security gate cannot map to Ok: "
            & SSH_Lib.Sessions.Open_Guards.Gate_Label (Gate));
      end loop;
   end Assert_Session_Open_Success_Gates;
end SSH_Lib.Tests.Fixtures.Session_Open_Success;
