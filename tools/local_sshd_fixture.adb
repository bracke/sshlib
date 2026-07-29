with Ada.Command_Line;
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.Strings.Fixed;
with Ada.Text_IO;
with GNAT.OS_Lib;
with GNAT.Sockets;
with GNAT.Strings;

procedure Local_SSHD_Fixture is
   use type GNAT.OS_Lib.Process_Id;
   use type GNAT.Strings.String_Access;

   Root : constant String :=
     (if Ada.Environment_Variables.Exists ("SSH_LIB_TEST_SSHD_ROOT")
      then Ada.Environment_Variables.Value ("SSH_LIB_TEST_SSHD_ROOT")
      else "/tmp/ssh_lib_local_sshd");
   Env_File : constant String := Root & "/env";

   procedure Fail (Message_Text : String; Status : Ada.Command_Line.Exit_Status := Ada.Command_Line.Failure) is
   begin
      Ada.Text_IO.Put_Line (Ada.Text_IO.Standard_Error, Message_Text);
      Ada.Command_Line.Set_Exit_Status (Status);
   end Fail;

   function Env (Name : String; Default_Value : String := "") return String is
   begin
      if Ada.Environment_Variables.Exists (Name) then
         return Ada.Environment_Variables.Value (Name);
      else
         return Default_Value;
      end if;
   end Env;

   function Resolve_Program (Name : String) return String is
      Located : GNAT.Strings.String_Access := null;
   begin
      if Ada.Strings.Fixed.Index (Name, "/") /= 0
        or else Ada.Strings.Fixed.Index (Name, "\") /= 0
      then
         return Name;
      end if;

      Located := GNAT.OS_Lib.Locate_Exec_On_Path (Name);
      if Located = null then
         return "";
      else
         declare
            Result : constant String := Located.all;
         begin
            GNAT.Strings.Free (Located);
            return Result;
         end;
      end if;
   end Resolve_Program;

   function Run_Command (Program_Name : String; Args : GNAT.OS_Lib.Argument_List) return Boolean is
      Program_Path : constant String := Resolve_Program (Program_Name);
   begin
      if Program_Path'Length = 0 then
         return False;
      end if;
      return GNAT.OS_Lib.Spawn (Program_Path, Args) = 0;
   end Run_Command;

   procedure Write_File (Path : String; Content : String) is
      File_Item : Ada.Text_IO.File_Type;
   begin
      Ada.Text_IO.Create (File_Item, Ada.Text_IO.Out_File, Path);
      Ada.Text_IO.Put (File_Item, Content);
      Ada.Text_IO.Close (File_Item);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         raise;
   end Write_File;

   function Read_File (Path : String) return String is
      File_Item : Ada.Text_IO.File_Type;
      Result    : GNAT.Strings.String_Access := new String'("");
   begin
      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
            Old       : GNAT.Strings.String_Access := Result;
         begin
            Result := new String'(Old.all & Line_Text & Character'Val (10));
            GNAT.Strings.Free (Old);
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
      declare
         Text : constant String := Result.all;
      begin
         GNAT.Strings.Free (Result);
         return Text;
      end;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         if Result /= null then
            GNAT.Strings.Free (Result);
         end if;
         return "";
   end Read_File;

   function Choose_Port return Natural is
      Socket : GNAT.Sockets.Socket_Type;
      Addr   : GNAT.Sockets.Sock_Addr_Type;
      Port   : Natural := 0;
   begin
      GNAT.Sockets.Create_Socket (Socket);
      Addr.Addr := GNAT.Sockets.Inet_Addr ("127.0.0.1");
      Addr.Port := 0;
      GNAT.Sockets.Bind_Socket (Socket, Addr);
      Addr := GNAT.Sockets.Get_Socket_Name (Socket);
      Port := Natural (Addr.Port);
      GNAT.Sockets.Close_Socket (Socket);
      return Port;
   exception
      when others =>
         return 22022;
   end Choose_Port;

   function User_Name return String is
   begin
      if Env ("SSH_LIB_TEST_SSHD_USER")'Length > 0 then
         return Env ("SSH_LIB_TEST_SSHD_USER");
      elsif Env ("USER")'Length > 0 then
         return Env ("USER");
      elsif Env ("USERNAME")'Length > 0 then
         return Env ("USERNAME");
      else
         return "unknown";
      end if;
   end User_Name;

   function Port_Text return String is
   begin
      if Env ("SSH_LIB_TEST_SSHD_PORT")'Length > 0 then
         return Env ("SSH_LIB_TEST_SSHD_PORT");
      else
         return Ada.Strings.Fixed.Trim (Natural'Image (Choose_Port), Ada.Strings.Both);
      end if;
   end Port_Text;

   procedure Stop_Fixture is
      procedure Kill_From_File (Path : String) is
         Raw_Text : constant String := Read_File (Path);
      begin
         if Raw_Text'Length > 0 then
            declare
               Last : Natural := Raw_Text'First - 1;
            begin
               for Index in Raw_Text'Range loop
                  exit when Raw_Text (Index) = Character'Val (10)
                    or else Raw_Text (Index) = Character'Val (13);
                  Last := Index;
               end loop;

               if Last >= Raw_Text'First then
                  declare
                     Text    : constant String := Raw_Text (Raw_Text'First .. Last);
                     Ignored : constant Boolean :=
                       Run_Command ("kill", [1 => new String'(Text)]);
                  begin
                     null;
                  end;
               end if;
            end;
         end if;
      exception
         when others =>
            null;
      end Kill_From_File;
   begin
      Kill_From_File (Root & "/sshd.pid");
      Kill_From_File (Root & "/launcher.pid");
   end Stop_Fixture;

   procedure Start_Fixture is
      SSHD_Bin       : constant String :=
        (if Env ("SSHD_BIN")'Length > 0 then Env ("SSHD_BIN") else Resolve_Program ("sshd"));
      SSH_Keygen_Bin : constant String :=
        (if Env ("SSH_KEYGEN_BIN")'Length > 0 then Env ("SSH_KEYGEN_BIN") else Resolve_Program ("ssh-keygen"));
      Port           : constant String := Port_Text;
      User           : constant String := User_Name;
      Pid            : GNAT.OS_Lib.Process_Id;
   begin
      if SSHD_Bin'Length = 0 or else SSH_Keygen_Bin'Length = 0 then
         Fail ("sshd and ssh-keygen are required");
         return;
      end if;

      if Ada.Directories.Exists (Root) then
         Stop_Fixture;
         Ada.Directories.Delete_Tree (Root);
      end if;
      Ada.Directories.Create_Path (Root);
      if not Run_Command ("chmod", [1 => new String'("700"), 2 => new String'(Root)]) then
         Fail ("failed to chmod fixture root");
         return;
      end if;

      if not Run_Command
        (SSH_Keygen_Bin,
         [1 => new String'("-q"),
          2 => new String'("-t"),
          3 => new String'("ecdsa"),
          4 => new String'("-b"),
          5 => new String'("256"),
          6 => new String'("-N"),
          7 => new String'(""),
          8 => new String'("-f"),
          9 => new String'(Root & "/host_ecdsa")])
      then
         Fail ("failed to generate sshd host key");
         return;
      end if;

      if not Run_Command
        (SSH_Keygen_Bin,
         [1 => new String'("-q"),
          2 => new String'("-t"),
          3 => new String'("ed25519"),
          4 => new String'("-N"),
          5 => new String'(""),
          6 => new String'("-f"),
          7 => new String'(Root & "/client_ed25519")])
      then
         Fail ("failed to generate sshd client key");
         return;
      end if;

      Ada.Directories.Copy_File (Root & "/client_ed25519.pub", Root & "/authorized_keys");
      if not Run_Command
        ("chmod",
         [1 => new String'("600"),
          2 => new String'(Root & "/authorized_keys"),
          3 => new String'(Root & "/client_ed25519")])
      then
         Fail ("failed to chmod fixture keys");
         return;
      end if;

      Write_File
        (Root & "/sshd_config",
         "Port " & Port & Character'Val (10)
         & "ListenAddress 127.0.0.1" & Character'Val (10)
         & "Protocol 2" & Character'Val (10)
         & "HostKey " & Root & "/host_ecdsa" & Character'Val (10)
         & "KexAlgorithms curve25519-sha256" & Character'Val (10)
         & "HostKeyAlgorithms ecdsa-sha2-nistp256" & Character'Val (10)
         & "Ciphers aes128-ctr" & Character'Val (10)
         & "MACs hmac-sha2-256" & Character'Val (10)
         & "Compression no" & Character'Val (10)
         & "PidFile " & Root & "/sshd.pid" & Character'Val (10)
         & "AuthorizedKeysFile " & Root & "/authorized_keys" & Character'Val (10)
         & "PubkeyAuthentication yes" & Character'Val (10)
         & "PasswordAuthentication no" & Character'Val (10)
         & "KbdInteractiveAuthentication no" & Character'Val (10)
         & "ChallengeResponseAuthentication no" & Character'Val (10)
         & "UsePAM no" & Character'Val (10)
         & "StrictModes no" & Character'Val (10)
         & "PermitRootLogin no" & Character'Val (10)
         & "AllowUsers " & User & Character'Val (10)
         & "LogLevel VERBOSE" & Character'Val (10)
         & "Subsystem sftp internal-sftp" & Character'Val (10));

      declare
         Setsid_Bin : constant String := Resolve_Program ("setsid");
      begin
         if Setsid_Bin'Length > 0 then
            Pid := GNAT.OS_Lib.Non_Blocking_Spawn
              (Setsid_Bin,
               [1 => new String'(SSHD_Bin),
                2 => new String'("-D"),
                3 => new String'("-e"),
                4 => new String'("-f"),
                5 => new String'(Root & "/sshd_config")],
               Root & "/sshd.log");
         else
            Pid := GNAT.OS_Lib.Non_Blocking_Spawn
              (SSHD_Bin,
               [1 => new String'("-D"),
                2 => new String'("-e"),
                3 => new String'("-f"),
                4 => new String'(Root & "/sshd_config")],
               Root & "/sshd.log");
         end if;
      end;
      if Pid = GNAT.OS_Lib.Invalid_Pid then
         Fail ("failed to start sshd");
         return;
      end if;
      Write_File
           (Root & "/launcher.pid",
            Ada.Strings.Fixed.Trim (GNAT.OS_Lib.Process_Id'Image (Pid), Ada.Strings.Both));

      for Attempt in 1 .. 50 loop
         exit when Ada.Directories.Exists (Root & "/sshd.pid")
           or else Ada.Strings.Fixed.Index (Read_File (Root & "/sshd.log"), "Server listening") /= 0;
         delay 0.1;
      end loop;

      if not Ada.Directories.Exists (Root & "/sshd.pid")
        and then Ada.Strings.Fixed.Index (Read_File (Root & "/sshd.log"), "Server listening") = 0
      then
         Ada.Text_IO.Put (Ada.Text_IO.Standard_Error, Read_File (Root & "/sshd.log"));
         Fail ("sshd did not become ready");
         return;
      end if;

      Write_File
        (Env_File,
         "export SSH_LIB_TEST_SSHD_ENABLE=1" & Character'Val (10)
         & "export SSH_LIB_TEST_SSHD_HOST=127.0.0.1" & Character'Val (10)
         & "export SSH_LIB_TEST_SSHD_PORT=" & Port & Character'Val (10)
         & "export SSH_LIB_TEST_SSHD_USER=" & User & Character'Val (10)
         & "export SSH_LIB_TEST_SSHD_IDENTITY_FILE=" & Root & "/client_ed25519" & Character'Val (10));

      Ada.Text_IO.Put (Read_File (Env_File));
      Ada.Text_IO.Put_Line ("# run: source " & Env_File & " && cd tests && alr exec -- ./bin/main");
      Ada.Text_IO.Put_Line ("# strict success mode: export SSH_LIB_TEST_SSHD_STRICT=1 before running");
      Ada.Text_IO.Put_Line ("# stop: ../ssh_lib_build/bin/tools/local_sshd_fixture stop");
   end Start_Fixture;

   Command : constant String :=
     (if Ada.Command_Line.Argument_Count = 0 then "start" else Ada.Command_Line.Argument (1));
begin
   if Command = "start" then
      Start_Fixture;
   elsif Command = "stop" then
      Stop_Fixture;
   elsif Command = "env" then
      Ada.Text_IO.Put (Read_File (Env_File));
   else
      Fail ("usage: local_sshd_fixture [start|stop|env]", Ada.Command_Line.Failure);
   end if;
end Local_SSHD_Fixture;
