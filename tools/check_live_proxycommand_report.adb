with Ada.Command_Line;
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.Strings.Fixed;
with Ada.Text_IO;

procedure Check_Live_Proxycommand_Report is
   use Ada.Strings.Fixed;
   Failure_Count : Natural := 0;

   type Scenario_Name is (Basic, Token, Ipv6, Fails_Early, Hangs);
   type Scenario_State is record
      Declared : Boolean := False;
      Records  : Natural := 0;
      Passes   : Natural := 0;
   end record;
   type Scenario_State_Array is array (Scenario_Name) of Scenario_State;

   Required : Scenario_State_Array := [others => <>];
   Seen     : Scenario_State_Array := [others => <>];

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   function Env (Name : String) return String is
   begin
      if Ada.Environment_Variables.Exists (Name) then
         return Ada.Environment_Variables.Value (Name);
      end if;
      return "";
   end Env;

   function Enabled (Text : String) return Boolean is
   begin
      return Text = "1" or else Text = "true" or else Text = "TRUE";
   end Enabled;

   function Parse_Scenario (Text : String; Item : out Scenario_Name) return Boolean is
      Name_Text : constant String := Ada.Strings.Fixed.Trim (Text, Ada.Strings.Both);
   begin
      if Name_Text = "BASIC" then
         Item := Basic;
      elsif Name_Text = "TOKEN" then
         Item := Token;
      elsif Name_Text = "IPV6" then
         Item := Ipv6;
      elsif Name_Text = "FAILS_EARLY" then
         Item := Fails_Early;
      elsif Name_Text = "HANGS" then
         Item := Hangs;
      else
         return False;
      end if;
      return True;
   end Parse_Scenario;

   function Has (Line_Text : String; Needle : String) return Boolean is
   begin
      return Index (Line_Text, Needle) /= 0;
   end Has;

   function Has_Field (Line_Text : String; Field_Text : String) return Boolean is
   begin
      return Has (" " & Line_Text & " ", " " & Field_Text & " ");
   end Has_Field;

   function Field_Value (Line_Text : String; Prefix : String) return String is
      Start_Index : constant Natural := Index (Line_Text, Prefix);
      Stop_Index  : Natural;
   begin
      if Start_Index = 0 then
         return "";
      end if;

      Stop_Index := Start_Index + Prefix'Length;
      while Stop_Index <= Line_Text'Last and then Line_Text (Stop_Index) /= ' ' loop
         Stop_Index := Stop_Index + 1;
      end loop;
      return Line_Text (Start_Index + Prefix'Length .. Stop_Index - 1);
   end Field_Value;

   function Positive_Bytes_Field (Line_Text : String; Prefix : String) return Boolean is
      Text : constant String := Field_Value (Line_Text, Prefix);
   begin
      if Text'Length = 0 then
         return False;
      end if;
      return Natural'Value (Text) > 0;
   exception
      when others =>
         return False;
   end Positive_Bytes_Field;

   function Report_Declares_Scenario
     (Path          : String;
      Scenario_Item : Scenario_Name) return Boolean
   is
      pragma Unreferenced (Path);
   begin
      return Seen (Scenario_Item).Declared;
   end Report_Declares_Scenario;

   procedure Require_Exact_Line (Path : String; Needle : String) is
      File_Item : Ada.Text_IO.File_Type;
      Found     : Boolean := False;
   begin
      if not Ada.Directories.Exists (Path) then
         Fail ("missing live ProxyCommand report: " & Path);
         return;
      end if;
      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         if Ada.Text_IO.Get_Line (File_Item) = Needle then
            Found := True;
         end if;
      end loop;
      Ada.Text_IO.Close (File_Item);
      if not Found then
         Fail ("missing exact report line: " & Needle);
      end if;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         Fail ("could not read live ProxyCommand report: " & Path);
   end Require_Exact_Line;

   procedure Reject_Text (Path : String; Needle : String) is
      File_Item : Ada.Text_IO.File_Type;
   begin
      if not Ada.Directories.Exists (Path) then
         return;
      end if;
      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
         begin
            if Index (Line_Text, Needle) /= 0 then
               Ada.Text_IO.Close (File_Item);
               Fail ("forbidden report text: " & Needle);
               return;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         Fail ("could not scan live ProxyCommand report: " & Path);
   end Reject_Text;

   procedure Scenario_List_Line_Declares (Scenario_List : String) is
      Start_Index : Positive := Scenario_List'First;
      Stop_Index  : Natural;
      Item        : Scenario_Name;
   begin
      if Scenario_List'Length = 0 then
         Seen (Basic).Declared := True;
         return;
      end if;

      if Scenario_List = "ALL" then
         for Scenario_Item in Scenario_Name loop
            Seen (Scenario_Item).Declared := True;
         end loop;
         return;
      end if;

      while Start_Index <= Scenario_List'Last loop
         Stop_Index := Start_Index;
         while Stop_Index <= Scenario_List'Last and then Scenario_List (Stop_Index) /= ',' loop
            Stop_Index := Stop_Index + 1;
         end loop;

         if Stop_Index = Start_Index then
            Fail ("empty scenario in scenario_list");
         elsif Parse_Scenario (Scenario_List (Start_Index .. Stop_Index - 1), Item) then
            if Seen (Item).Declared then
               Fail ("no duplicate scenario names");
            end if;
            Seen (Item).Declared := True;
         else
            Fail ("unknown scenario in scenario_list");
         end if;

         Start_Index := Stop_Index + 1;
      end loop;
   end Scenario_List_Line_Declares;

   function Scenario_List_Line_Is_Well_Formed (Line_Text : String) return Boolean is
   begin
      return Index (Line_Text, "scenario_list=") = Line_Text'First;
   end Scenario_List_Line_Is_Well_Formed;

   procedure Scenario_Metadata_Matches (Line_Text : String; Scenario_Item : Scenario_Name) is
   begin
      if not Has_Field (Line_Text, "verify_known_host=true") then
         Fail ("scenario record is missing verify_known_host=true");
      end if;
      if not Has_Field (Line_Text, "strict_host_key=true") then
         Fail ("scenario record is missing strict_host_key=true");
      end if;
      if not Has_Field (Line_Text, "proxy_command_configured=true") then
         Fail ("scenario record is missing proxy_command_configured=true");
      end if;
      if Field_Value (Line_Text, "proxy_child_started=")'Length = 0
        or else Field_Value (Line_Text, "proxy_child_open=")'Length = 0
        or else Field_Value (Line_Text, "proxy_close_attempted=")'Length = 0
        or else Field_Value (Line_Text, "proxy_close_completed=")'Length = 0
        or else Field_Value (Line_Text, "proxy_exit_status_known=")'Length = 0
        or else Field_Value (Line_Text, "proxy_exit_status=")'Length = 0
        or else Field_Value (Line_Text, "proxy_shell=")'Length = 0
        or else Field_Value (Line_Text, "proxy_lifecycle=")'Length = 0
        or else Field_Value (Line_Text, "proxy_spawn_status=")'Length = 0
        or else Field_Value (Line_Text, "proxy_last_io_status=")'Length = 0
        or else Field_Value (Line_Text, "proxy_close_status=")'Length = 0
      then
         Fail ("scenario record is missing ProxyCommand lifecycle diagnostics");
      end if;

      case Scenario_Item is
         when Token =>
            if not Has_Field (Line_Text, "token_expansion=true") then
               Fail ("TOKEN scenario record is missing token_expansion=true");
            end if;
         when Fails_Early =>
            if not Has_Field (Line_Text, "stage=expected_failure")
              or else not Has_Field (Line_Text, "expected_failure=true")
              or else not Has_Field (Line_Text, "session_opened=false")
              or else not Has_Field (Line_Text, "channel_opened=false")
              or else not Has_Field (Line_Text, "proxy_child_started=true")
              or else Field_Value (Line_Text, "open_status=")'Length = 0
              or else Field_Value (Line_Text, "proxy_last_io_status=")'Length = 0
              or else not Has_Field (Line_Text, "proxy_exit_status_known=true")
              or else Field_Value (Line_Text, "proxy_exit_status=")'Length = 0
              or else Field_Value (Line_Text, "diagnostic=")'Length = 0
            then
               Fail ("FAILS_EARLY scenario record is missing expected-failure diagnostics");
            end if;
         when Hangs =>
            if not Has_Field (Line_Text, "stage=timeout_cleanup")
              or else not Has_Field (Line_Text, "expected_failure=true")
              or else not Has_Field (Line_Text, "session_opened=false")
              or else not Has_Field (Line_Text, "channel_opened=false")
              or else not Has_Field (Line_Text, "open_status=TIMEOUT")
              or else not Has_Field (Line_Text, "proxy_child_started=true")
              or else not Has_Field (Line_Text, "proxy_close_attempted=true")
              or else not Has_Field (Line_Text, "proxy_close_completed=true")
              or else not Has_Field (Line_Text, "proxy_exit_status_known=true")
              or else Field_Value (Line_Text, "proxy_exit_status=")'Length = 0
              or else not Has_Field (Line_Text, "proxy_last_io_status=TIMEOUT")
              or else not Has_Field (Line_Text, "proxy_close_status=OK")
              or else not Has_Field (Line_Text, "diagnostic=proxy_command_timeout")
            then
               Fail ("HANGS scenario record is missing timeout cleanup diagnostics");
            end if;
         when others =>
            if not Has_Field (Line_Text, "stage=complete")
              or else not Has_Field (Line_Text, "session_opened=true")
              or else not Has_Field (Line_Text, "channel_opened=true")
              or else not Has_Field (Line_Text, "expected_failure=false")
              or else not Has_Field (Line_Text, "proxy_child_started=true")
              or else not Has_Field (Line_Text, "proxy_child_open=false")
              or else not Has_Field (Line_Text, "proxy_close_attempted=true")
              or else not Has_Field (Line_Text, "proxy_close_completed=true")
              or else not Has_Field (Line_Text, "proxy_close_status=OK")
              or else not Has_Field (Line_Text, "proxy_exit_status_known=true")
              or else Field_Value (Line_Text, "proxy_exit_status=")'Length = 0
              or else not Positive_Bytes_Field (Line_Text, "bytes=")
            then
               Fail ("normal scenario record is missing completed transport metadata");
            end if;
      end case;
   end Scenario_Metadata_Matches;

   procedure Report_Has_One_Well_Formed_Scenario_List (Path : String) is
      File_Item  : Ada.Text_IO.File_Type;
      Line_Count : Natural := 0;
   begin
      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
         begin
            if Index (Line_Text, "scenario_list=") = Line_Text'First then
               Line_Count := Line_Count + 1;
               if not Scenario_List_Line_Is_Well_Formed (Line_Text) then
                  Fail ("scenario_list line is malformed");
               end if;
               Scenario_List_Line_Declares
                 (Line_Text (Line_Text'First + String'("scenario_list=")'Length .. Line_Text'Last));
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
      if Line_Count /= 1 then
         Fail ("exactly one well-formed scenario_list line is required");
      end if;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         Fail ("could not validate scenario_list line");
   end Report_Has_One_Well_Formed_Scenario_List;

   procedure Report_Scenario_Lines_Are_Declared (Path : String) is
      File_Item : Ada.Text_IO.File_Type;
      Item      : Scenario_Name;
   begin
      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
            Name_Text : constant String := Field_Value (Line_Text, "scenario=");
         begin
            if Index (Line_Text, "scenario=") = Line_Text'First then
               if not Parse_Scenario (Name_Text, Item) then
                  Fail ("scenario records must be known and declared by scenario_list");
               elsif not Report_Declares_Scenario (Path, Item) then
                  Fail ("scenario records must be known and declared by scenario_list");
               else
                  Seen (Item).Records := Seen (Item).Records + 1;
                  if Has_Field (Line_Text, "result=PASS") then
                     Seen (Item).Passes := Seen (Item).Passes + 1;
                  end if;
                  Scenario_Metadata_Matches (Line_Text, Item);
               end if;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         Fail ("could not validate scenario records");
   end Report_Scenario_Lines_Are_Declared;

   procedure Report_Declared_Scenarios_Have_Exactly_One_Record is
   begin
      for Item in Scenario_Name loop
         if Seen (Item).Declared and then Seen (Item).Records /= 1 then
            Fail ("exactly one record for every declared scenario and none for undeclared scenarios");
         elsif (not Seen (Item).Declared) and then Seen (Item).Records /= 0 then
            Fail ("exactly one record for every declared scenario and none for undeclared scenarios");
         end if;
      end loop;
   end Report_Declared_Scenarios_Have_Exactly_One_Record;

   procedure Parse_Required_Scenarios (Scenario_List : String) is
      Start_Index : Positive := Scenario_List'First;
      Stop_Index  : Natural;
      Item        : Scenario_Name;
   begin
      if Scenario_List'Length = 0 then
         Required (Basic).Declared := True;
         return;
      end if;

      if Scenario_List = "ALL" then
         for Scenario_Item in Scenario_Name loop
            Required (Scenario_Item).Declared := True;
         end loop;
         return;
      end if;

      while Start_Index <= Scenario_List'Last loop
         Stop_Index := Start_Index;
         while Stop_Index <= Scenario_List'Last and then Scenario_List (Stop_Index) /= ',' loop
            Stop_Index := Stop_Index + 1;
         end loop;

         if Stop_Index = Start_Index then
            Fail ("empty required ProxyCommand scenario");
         elsif Parse_Scenario (Scenario_List (Start_Index .. Stop_Index - 1), Item) then
            Required (Item).Declared := True;
         else
            Fail ("unknown required ProxyCommand scenario");
         end if;
         Start_Index := Stop_Index + 1;
      end loop;
   end Parse_Required_Scenarios;

   procedure Required_Scenarios_Have_Exactly_One_Pass is
   begin
      for Item in Scenario_Name loop
         if Required (Item).Declared then
            if not Report_Declares_Scenario ("", Item) then
               Fail ("scenario_list does not declare required scenario");
            elsif Seen (Item).Passes /= 1 then
               Fail ("exactly one required scenario record must pass");
            end if;
         end if;
      end loop;
   end Required_Scenarios_Have_Exactly_One_Pass;

   Require_Report      : constant Boolean :=
     Enabled (Env ("SSH_LIB_REQUIRE_LIVE_PROXYCOMMAND_REPORT"));
   Default_Report_Path : constant String :=
     "release_artifacts/live_proxycommand_report.txt";
   Configured_Report_Path : constant String :=
     Env ("SSH_LIB_LIVE_PROXYCOMMAND_REPORT");
   Report_Path : constant String :=
     (if Configured_Report_Path'Length = 0 then Default_Report_Path
      else Configured_Report_Path);
   Required_List : constant String :=
     Env ("SSH_LIB_REQUIRED_LIVE_PROXYCOMMAND_SCENARIOS");
begin
   if not Require_Report then
      Ada.Text_IO.Put_Line
        ("live ProxyCommand report guard skipped: set SSH_LIB_REQUIRE_LIVE_PROXYCOMMAND_REPORT=1 to require an arch"
         & "ived report");
      return;
   end if;

   if not Ada.Directories.Exists (Report_Path) then
      Fail ("missing archived live ProxyCommand report: " & Report_Path);
   else
      Parse_Required_Scenarios (Required_List);
      Require_Exact_Line (Report_Path, "ssh_lib_live_proxycommand_report_version=1");
      Require_Exact_Line (Report_Path, "enabled=true");
      Require_Exact_Line (Report_Path, "result=PASS");
      Reject_Text (Report_Path, "result=FAIL");
      Reject_Text (Report_Path, "result=SKIP");
      Reject_Text (Report_Path, "reason=disabled");
      Reject_Text (Report_Path, "status=INVALID_CONFIG");
      Report_Has_One_Well_Formed_Scenario_List (Report_Path);
      Report_Scenario_Lines_Are_Declared (Report_Path);
      Required_Scenarios_Have_Exactly_One_Pass;
      Report_Declared_Scenarios_Have_Exactly_One_Record;
   end if;

   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("live ProxyCommand report guard passed");
   else
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Live_Proxycommand_Report;
