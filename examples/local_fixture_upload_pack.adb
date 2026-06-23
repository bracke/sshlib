with Ada.Command_Line;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with SSH_Lib.Channels;
with CryptoLib.Errors;
with SSH_Lib.Git;
with SSH_Lib.Sessions;

procedure Local_Fixture_Upload_Pack is
   use Ada.Strings.Unbounded;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.Errors.Status;

   Request_Bytes : constant Ada.Streams.Stream_Element_Array (1 .. 54) :=
     [16#30#, 16#30#, 16#33#, 16#32#, 16#77#, 16#61#, 16#6E#, 16#74#,
      16#20#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#,
      16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#,
      16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#,
      16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#,
      16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#,
      16#31#, 16#0A#, 16#30#, 16#30#, 16#30#, 16#30#];

   Response_Bytes : constant Ada.Streams.Stream_Element_Array (1 .. 64) :=
     [16#30#, 16#30#, 16#33#, 16#66#, 16#31#, 16#31#, 16#31#, 16#31#,
      16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#,
      16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#,
      16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#,
      16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#,
      16#31#, 16#31#, 16#31#, 16#31#, 16#20#, 16#48#, 16#45#, 16#41#,
      16#44#, 16#00#, 16#6D#, 16#75#, 16#6C#, 16#74#, 16#69#, 16#5F#,
      16#61#, 16#63#, 16#6B#, 16#0A#, 16#30#, 16#30#, 16#30#, 16#30#];

   Pack_Like_Bytes : constant Ada.Streams.Stream_Element_Array (1 .. 12) :=
     [16#50#, 16#41#, 16#43#, 16#4B#, 16#00#, 16#00#, 16#00#, 16#02#,
      16#00#, 16#00#, 16#00#, 16#00#];

   Binary_Probe : constant Ada.Streams.Stream_Element_Array (1 .. 6) :=
     [16#00#, 16#0A#, 16#0D#, 16#7F#, 16#80#, 16#FF#];

   Options_Item : SSH_Lib.Sessions.Session_Options;
   Session_Item : SSH_Lib.Sessions.Session;
   Channel_Item : SSH_Lib.Channels.Channel;
   Buffer_Item  : Ada.Streams.Stream_Element_Array (1 .. 4096);
   Last_Index   : Ada.Streams.Stream_Element_Offset;
   Exit_Code    : Integer := 0;
   Status_Value : CryptoLib.Errors.Status;
   Command_Item : Unbounded_String;

   procedure Require_Status
     (Value        : CryptoLib.Errors.Status;
      Allowed      : CryptoLib.Errors.Status;
      Message_Text : String)
   is
   begin
      if Value /= Allowed then
         raise Program_Error with Message_Text;
      end if;
   end Require_Status;

   pragma Unreferenced (Response_Bytes, Pack_Like_Bytes, Binary_Probe);
begin
   Status_Value := SSH_Lib.Git.Build_Upload_Pack_Command ("repo.git", Command_Item);
   if Status_Value /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("command preparation failed");
      return;
   end if;

   Ada.Text_IO.Put_Line ("fixture command: " & To_String (Command_Item));
   Ada.Text_IO.Put_Line
     ("request/response buffers use Ada.Streams.Stream_Element_Array");
   Ada.Text_IO.Put_Line
     ("default host-key verification: " & Boolean'Image (Options_Item.Verify_Known_Host));

   --  This example is compiled by default but intentionally does not open a
   --  public-network connection.  The branch below is not taken in default
   --  runs, but keeps the exact version-facing byte-stream sequence
   --  compile-checked in example code: Sessions.Open, Open_Exec, Write,
   --  Send_EOF, Read_Some, Exit_Status, Close.
   if Ada.Command_Line.Argument_Count = Natural'Last then
      Status_Value := SSH_Lib.Sessions.Open (Options_Item, Session_Item);
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Channels.Open_Exec
           (Session_Item, To_String (Command_Item), Channel_Item);
         if Status_Value = CryptoLib.Errors.Ok then
            Status_Value := SSH_Lib.Channels.Write (Channel_Item, Request_Bytes);
            if Status_Value = CryptoLib.Errors.Ok then
               Status_Value := SSH_Lib.Channels.Send_EOF (Channel_Item);
               Require_Status
                 (Status_Value, CryptoLib.Errors.Ok, "send EOF failed");
            end if;

            loop
               Status_Value := SSH_Lib.Channels.Read_Some
                 (Channel_Item, Buffer_Item, Last_Index);
               exit when Status_Value = CryptoLib.Errors.End_Of_Stream;
               exit when Status_Value /= CryptoLib.Errors.Ok;
               if Last_Index >= Buffer_Item'First
                 and then Buffer_Item (Buffer_Item'First) = 16#FF#
               then
                  raise Program_Error with "unexpected response sentinel";
               end if;
            end loop;

            Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
            if Status_Value /= CryptoLib.Errors.Ok
              and then Status_Value /= CryptoLib.Errors.Remote_Exit_Nonzero
            then
               raise Program_Error with "exit status query failed";
            end if;
            if Exit_Code = Integer'First then
               raise Program_Error with "unreadable exit code";
            end if;

            Status_Value := SSH_Lib.Channels.Close (Channel_Item);
            Require_Status
              (Status_Value, CryptoLib.Errors.Ok, "channel close failed");
         end if;

         Status_Value := SSH_Lib.Sessions.Close (Session_Item);
         Require_Status
           (Status_Value, CryptoLib.Errors.Ok, "session close failed");
      end if;
   end if;

end Local_Fixture_Upload_Pack;
