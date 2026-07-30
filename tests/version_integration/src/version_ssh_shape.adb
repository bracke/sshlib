with Ada.Command_Line;
with Ada.Directories;
with Ada.Streams;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Hostkit.Fs;
with SSH_Lib.Channels;
with SSH_Lib.Config;
with CryptoLib.Errors;
with SSH_Lib.Git;
with SSH_Lib.Git_Transport;
with SSH_Lib.Remote_Names;
with SSH_Lib.Sessions;

procedure Version_Ssh_Shape is
   use Ada.Strings.Unbounded;
   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type CryptoLib.Errors.Status;

   Remote_Item  : SSH_Lib.Remote_Names.Parsed_Remote;
   --  Under the host's temporary directory, not the working one. These
   --  names used to be relative, so they were written wherever the test
   --  happened to be started from -- a run launched from a sibling crate
   --  left six of them in that crate's repository root, where sshlib's
   --  .gitignore does not reach.
   Config_Path  : constant String :=
     Ada.Directories.Compose
       (Hostkit.Fs.Temp_Directory, "version_ssh_shape_empty_config.tmp");
   Config_File  : Ada.Text_IO.File_Type;
   Config_Item  : SSH_Lib.Config.Host_Config;
   Options_Item : SSH_Lib.Sessions.Session_Options;
   Session_Item : SSH_Lib.Sessions.Session;
   Channel_Item : SSH_Lib.Channels.Channel;
   Command_Item : Unbounded_String;
   Status_Value : CryptoLib.Errors.Status;
   Request_Bytes : constant Ada.Streams.Stream_Element_Array (1 .. 6) :=

     [16#00#, 16#0A#, 16#0D#, 16#7F#, 16#80#, 16#FF#];
   Buffer_Item : Ada.Streams.Stream_Element_Array (1 .. 4096);
   Last_Index  : Ada.Streams.Stream_Element_Offset;
   Exit_Code   : Integer := 0;

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
begin
   Ada.Text_IO.Create (Config_File, Ada.Text_IO.Out_File, Config_Path);
   Ada.Text_IO.Close (Config_File);
   Status_Value := SSH_Lib.Config.Load (Config_Path, Config_Item);
   if Status_Value /= CryptoLib.Errors.Ok then
      raise Program_Error with "empty config load failed";
   end if;

   Status_Value := SSH_Lib.Remote_Names.Parse
     ("git@example.invalid:repo.git", Remote_Item);
   if Status_Value /= CryptoLib.Errors.Ok then
      raise Program_Error with "remote parse failed";
   end if;

   Status_Value := SSH_Lib.Git_Transport.Prepare
     (Remote_Text  => "git@example.invalid:repo.git",
      Config       => Config_Item,
      Default_User => "git",
      Requested    => SSH_Lib.Git_Transport.Upload_Pack,
      Options      => Options_Item,
      Command      => Command_Item);
   if Status_Value /= CryptoLib.Errors.Ok then
      raise Program_Error with "transport preparation failed";
   end if;

   Status_Value := SSH_Lib.Git.Build_Upload_Pack_Command
     (SSH_Lib.Remote_Names.Repository_Path (Remote_Item), Command_Item);
   if Status_Value /= CryptoLib.Errors.Ok then
      raise Program_Error with "upload-pack command failed";
   end if;

   --  This branch is deliberately unreachable in normal test runs, but it is
   --  real Ada code rather than a comment, so the intended version adapter
   --  call sequence remains compile-checked without contacting the network by
   --  default.
   if Ada.Command_Line.Argument_Count = Natural'Last then
      Status_Value := SSH_Lib.Sessions.Open (Options_Item, Session_Item);
      if Status_Value = CryptoLib.Errors.Ok then
         Status_Value := SSH_Lib.Channels.Open_Exec
           (Session_Item, To_String (Command_Item), Channel_Item);
         if Status_Value = CryptoLib.Errors.Ok then
            Status_Value := SSH_Lib.Channels.Write
              (Channel_Item, Request_Bytes);
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

            Status_Value := SSH_Lib.Channels.Exit_Status
              (Channel_Item, Exit_Code);
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

   Ada.Text_IO.Put_Line ("version SSH shape compiled");
end Version_Ssh_Shape;
