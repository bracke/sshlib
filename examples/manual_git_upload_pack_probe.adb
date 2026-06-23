with Ada.Command_Line;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with SSH_Lib.Channels;
with CryptoLib.Errors;
with SSH_Lib.Git;
with SSH_Lib.Sessions;

procedure Manual_Git_Upload_Pack_Probe is
   use Ada.Strings.Unbounded;

   Options      : SSH_Lib.Sessions.Session_Options;
   Session_Item : SSH_Lib.Sessions.Session;
   Channel_Item : SSH_Lib.Channels.Channel;
   Status_Value : CryptoLib.Errors.Status;
   Command_Item : Unbounded_String;
   Read_Buffer  : Ada.Streams.Stream_Element_Array (1 .. 4096);
   Last_Index   : Ada.Streams.Stream_Element_Offset;
   Exit_Code    : Integer := -1;
   Byte_Count   : Natural := 0;

   Probe_Request : constant Ada.Streams.Stream_Element_Array (1 .. 54) :=
     (16#30#, 16#30#, 16#33#, 16#32#, 16#77#, 16#61#, 16#6E#, 16#74#,
      16#20#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#,
      16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#,
      16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#,
      16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#,
      16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#, 16#31#,
      16#31#, 16#0A#, 16#30#, 16#30#, 16#30#, 16#30#);

   function Image (Value : CryptoLib.Errors.Status) return String is
      use type CryptoLib.Errors.Status;
begin
      return CryptoLib.Errors.Status'Image (Value);
   end Image;
begin
   if Ada.Command_Line.Argument_Count /= 3 then
      Ada.Text_IO.Put_Line
        ("usage: manual_git_upload_pack_probe HOST USER REPO");
      Ada.Text_IO.Put_Line
        ("requires user-supplied host, user, repository path, trusted known_hosts entry,");
      Ada.Text_IO.Put_Line
        ("and working identity-file or ssh-agent authentication");
      Ada.Text_IO.Put_Line
        ("manual example only: excluded from default tests and keeps host-key verification enabled");
      return;
   end if;

   Options.Host := To_Unbounded_String (Ada.Command_Line.Argument (1));
   Options.User := To_Unbounded_String (Ada.Command_Line.Argument (2));

   Status_Value := SSH_Lib.Git.Build_Upload_Pack_Command
     (Ada.Command_Line.Argument (3), Command_Item);
   if Status_Value /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("command preparation failed: " & Image (Status_Value));
      return;
   end if;

   Status_Value := SSH_Lib.Sessions.Open (Options, Session_Item);
   if Status_Value /= CryptoLib.Errors.Ok then
      Ada.Text_IO.Put_Line ("session open failed: " & Image (Status_Value));
      return;
   end if;

   Status_Value := SSH_Lib.Channels.Open_Exec
     (Session_Item, To_String (Command_Item), Channel_Item);
   Ada.Text_IO.Put_Line ("open exec status: " & Image (Status_Value));
   if Status_Value = CryptoLib.Errors.Ok then
      Status_Value := SSH_Lib.Channels.Write (Channel_Item, Probe_Request);
      Ada.Text_IO.Put_Line ("write request status: " & Image (Status_Value));
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Channels.Send_EOF (Channel_Item);
         Ada.Text_IO.Put_Line ("send eof status: " & Image (Status_Value));
      end if;

      loop
         Status_Value := SSH_Lib.Channels.Read_Some
           (Channel_Item, Read_Buffer, Last_Index);
         exit when Status_Value = CryptoLib.Errors.End_Of_Stream;
         exit when Status_Value /= CryptoLib.Errors.Ok;
         if Last_Index >= Read_Buffer'First then
            Byte_Count := Byte_Count + Natural (Last_Index - Read_Buffer'First + 1);
         end if;
      end loop;
      Ada.Text_IO.Put_Line
        ("read status: " & Image (Status_Value) &
         ", opaque byte count: " & Natural'Image (Byte_Count));

      Status_Value := SSH_Lib.Channels.Exit_Status (Channel_Item, Exit_Code);
      Ada.Text_IO.Put_Line
        ("exit status query: " & Image (Status_Value) &
         ", remote exit code: " & Integer'Image (Exit_Code));

      Status_Value := SSH_Lib.Channels.Close (Channel_Item);
      Ada.Text_IO.Put_Line ("channel close status: " & Image (Status_Value));
   end if;

   Status_Value := SSH_Lib.Sessions.Close (Session_Item);
   Ada.Text_IO.Put_Line ("session close status: " & Image (Status_Value));
end Manual_Git_Upload_Pack_Probe;
