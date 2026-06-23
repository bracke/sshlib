with Ada.Characters.Handling;
with Ada.Command_Line;
with Ada.Directories;
with Ada.Environment_Variables;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Text_IO;

procedure Check_Live_Git_Matrix_Report is
   use Ada.Strings.Fixed;

   Failure_Count : Natural := 0;

   function Env (Name : String) return String is
   begin
      if Ada.Environment_Variables.Exists (Name) then
         return Ada.Environment_Variables.Value (Name);
      end if;
      return "";
   exception
      when others =>
         return "";
   end Env;

   function Enabled (Text : String) return Boolean is
      Canonical : constant String := Ada.Strings.Fixed.Trim (Text, Ada.Strings.Both);
   begin
      return Canonical = "1"
        or else Canonical = "true"
        or else Canonical = "TRUE"
        or else Canonical = "yes"
        or else Canonical = "YES";
   end Enabled;

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   function File_Contains (Path : String; Needle : String) return Boolean is
      File_Item : Ada.Text_IO.File_Type;
   begin
      if not Ada.Directories.Exists (Path) then
         return False;
      end if;

      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
         begin
            if Index (Line_Text, Needle) /= 0 then
               Ada.Text_IO.Close (File_Item);
               return True;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
      return False;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return False;
   end File_Contains;

   function File_Has_Exact_Line (Path : String; Needle : String) return Boolean is
      File_Item : Ada.Text_IO.File_Type;
   begin
      if not Ada.Directories.Exists (Path) then
         return False;
      end if;

      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
         begin
            if Line_Text = Needle then
               Ada.Text_IO.Close (File_Item);
               return True;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
      return False;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return False;
   end File_Has_Exact_Line;

   function Has_Prefix (Line_Text : String; Prefix : String) return Boolean is
   begin
      return Line_Text'Length >= Prefix'Length
        and then Line_Text (Line_Text'First .. Line_Text'First + Prefix'Length - 1) = Prefix;
   exception
      when others =>
         return False;
   end Has_Prefix;

   procedure Require_Text (Path : String; Needle : String) is
   begin
      if not File_Contains (Path, Needle) then
         Fail ("missing live Git matrix report text in " & Path & ": " & Needle);
      end if;
   end Require_Text;

   procedure Require_Exact_Line (Path : String; Needle : String) is
   begin
      if not File_Has_Exact_Line (Path, Needle) then
         Fail ("missing exact live Git matrix report line in " & Path & ": " & Needle);
      end if;
   end Require_Exact_Line;

   procedure Reject_Text (Path : String; Needle : String) is
   begin
      if File_Contains (Path, Needle) then
         Fail ("forbidden live Git matrix report text in " & Path & ": " & Needle);
      end if;
   end Reject_Text;

   function Canonical_Scenario (Text : String) return String is
      Trimmed_Text : constant String := Ada.Strings.Fixed.Trim (Text, Ada.Strings.Both);
      Result_Text  : String := Trimmed_Text;
   begin
      for Index_Value in Result_Text'Range loop
         Result_Text (Index_Value) :=
           Ada.Characters.Handling.To_Upper (Result_Text (Index_Value));
      end loop;
      return Result_Text;
   end Canonical_Scenario;



   function Is_Known_Scenario (Scenario_Name : String) return Boolean is
      Canonical_Name : constant String := Canonical_Scenario (Scenario_Name);
   begin
      return Canonical_Name = "DIRECT"
        or else Canonical_Name = "AGENT"
        or else Canonical_Name = "IDENTITY"
        or else Canonical_Name = "PASSWORD"
        or else Canonical_Name = "PASSPHRASE"
        or else Canonical_Name = "PROXYJUMP"
        or else Canonical_Name = "RECEIVE";
   end Is_Known_Scenario;

   function Positive_Bytes_Field
     (Line_Text    : String;
      Bytes_Prefix : String)
      return Boolean
   is
      Bytes_First : constant Natural := Line_Text'First + Bytes_Prefix'Length;
      Bytes_Last  : Natural := Bytes_First - 1;
      Value       : Natural := 0;
   begin
      if Line_Text'Length < Bytes_Prefix'Length
        or else Line_Text (Line_Text'First .. Line_Text'First + Bytes_Prefix'Length - 1) /= Bytes_Prefix
      then
         return False;
      end if;

      while Bytes_Last + 1 <= Line_Text'Last
        and then Line_Text (Bytes_Last + 1) in '0' .. '9'
      loop
         Bytes_Last := Bytes_Last + 1;
      end loop;

      if Bytes_Last < Bytes_First then
         return False;
      end if;

      if Bytes_Last = Line_Text'Last
        or else Line_Text (Bytes_Last + 1) /= ' '
      then
         return False;
      end if;

      for Index_Value in Bytes_First .. Bytes_Last loop
         Value := Value * 10 +
           Character'Pos (Line_Text (Index_Value)) - Character'Pos ('0');
      end loop;

      return Value > 0;
   exception
      when others =>
         return False;
   end Positive_Bytes_Field;


   function Scenario_Metadata_Matches
     (Line_Text     : String;
      Scenario_Name : String)
      return Boolean
   is
      Canonical_Name : constant String := Canonical_Scenario (Scenario_Name);
   begin
      if Index (Line_Text, " verify_known_host=true") = 0
        or else Index (Line_Text, " strict_host_key=true") = 0
      then
         return False;
      end if;

      if Canonical_Name = "AGENT" then
         return Index (Line_Text, " use_agent=true") /= 0;
      elsif Canonical_Name = "IDENTITY" then
         return Index (Line_Text, " identity_configured=true") /= 0;
      elsif Canonical_Name = "PASSWORD" then
         return Index (Line_Text, " password_configured=true") /= 0;
      elsif Canonical_Name = "PASSPHRASE" then
         return Index (Line_Text, " identity_configured=true") /= 0
           and then Index (Line_Text, " passphrase_configured=true") /= 0;
      elsif Canonical_Name = "PROXYJUMP" then
         return Index (Line_Text, " proxy_jump_configured=true") /= 0;
      elsif Canonical_Name = "RECEIVE" then
         return Index (Line_Text, " service=receive-pack") /= 0;
      end if;

      return True;
   end Scenario_Metadata_Matches;

   function Scenario_List_Line_Declares
     (Line_Text     : String;
      Scenario_Name : String)
      return Boolean
   is
      Prefix         : constant String := "scenario_list=";
      Canonical_Name : constant String := Canonical_Scenario (Scenario_Name);
   begin
      if Line_Text'Length < Prefix'Length
        or else Line_Text (Line_Text'First .. Line_Text'First + Prefix'Length - 1) /= Prefix
      then
         return False;
      end if;

      if Line_Text'Length = Prefix'Length then
         return Canonical_Name = "DIRECT";
      end if;

      declare
         Declared_List : constant String :=
           Line_Text (Line_Text'First + Prefix'Length .. Line_Text'Last);
      begin
         declare
            Start_Index : Positive := Declared_List'First;
            Stop_Index  : Natural;
         begin
            while Start_Index <= Declared_List'Last loop
               Stop_Index := Start_Index;
               while Stop_Index <= Declared_List'Last
                 and then Declared_List (Stop_Index) /= ','
               loop
                  Stop_Index := Stop_Index + 1;
               end loop;

               if Stop_Index > Start_Index then
                  declare
                     Declared_Name : constant String :=
                       Canonical_Scenario
                         (Declared_List (Start_Index .. Stop_Index - 1));
                  begin
                     if Declared_Name = "ALL"
                       or else Declared_Name = Canonical_Name
                     then
                        return True;
                     end if;
                  end;
               end if;

               Start_Index := Stop_Index + 1;
            end loop;
         end;
      end;

      return False;
   exception
      when others =>
         return False;
   end Scenario_List_Line_Declares;

   function Scenario_List_Line_Is_Well_Formed (Line_Text : String) return Boolean is
      Prefix      : constant String := "scenario_list=";
      Token_Count    : Natural := 0;
      Saw_All        : Boolean := False;
      Saw_Direct     : Boolean := False;
      Saw_Agent      : Boolean := False;
      Saw_Identity   : Boolean := False;
      Saw_Password   : Boolean := False;
      Saw_Passphrase : Boolean := False;
      Saw_Proxyjump  : Boolean := False;
      Saw_Receive    : Boolean := False;
   begin
      if Line_Text'Length < Prefix'Length
        or else Line_Text (Line_Text'First .. Line_Text'First + Prefix'Length - 1) /= Prefix
      then
         return False;
      end if;

      if Line_Text'Length = Prefix'Length then
         return True;
      end if;

      declare
         Declared_List : constant String :=
           Line_Text (Line_Text'First + Prefix'Length .. Line_Text'Last);
         Start_Index   : Positive := Declared_List'First;
         Stop_Index    : Natural;
      begin
         while Start_Index <= Declared_List'Last loop
            Stop_Index := Start_Index;
            while Stop_Index <= Declared_List'Last
              and then Declared_List (Stop_Index) /= ','
            loop
               Stop_Index := Stop_Index + 1;
            end loop;

            if Stop_Index <= Start_Index then
               return False;
            end if;

            declare
               Declared_Name : constant String :=
                 Canonical_Scenario
                   (Declared_List (Start_Index .. Stop_Index - 1));
            begin
               if Declared_Name = "ALL" then
                  Saw_All := True;
               elsif not Is_Known_Scenario (Declared_Name) then
                  return False;
               elsif Declared_Name = "DIRECT" then
                  if Saw_Direct then
                     return False;
                  end if;
                  Saw_Direct := True;
               elsif Declared_Name = "AGENT" then
                  if Saw_Agent then
                     return False;
                  end if;
                  Saw_Agent := True;
               elsif Declared_Name = "IDENTITY" then
                  if Saw_Identity then
                     return False;
                  end if;
                  Saw_Identity := True;
               elsif Declared_Name = "PASSWORD" then
                  if Saw_Password then
                     return False;
                  end if;
                  Saw_Password := True;
               elsif Declared_Name = "PASSPHRASE" then
                  if Saw_Passphrase then
                     return False;
                  end if;
                  Saw_Passphrase := True;
               elsif Declared_Name = "PROXYJUMP" then
                  if Saw_Proxyjump then
                     return False;
                  end if;
                  Saw_Proxyjump := True;
               elsif Declared_Name = "RECEIVE" then
                  if Saw_Receive then
                     return False;
                  end if;
                  Saw_Receive := True;
               end if;
            end;

            Token_Count := Token_Count + 1;
            Start_Index := Stop_Index + 1;
         end loop;
      end;

      return Token_Count > 0 and then (not Saw_All or else Token_Count = 1);
   exception
      when others =>
         return False;
   end Scenario_List_Line_Is_Well_Formed;

   function Report_Has_One_Well_Formed_Scenario_List
     (Path : String)
      return Boolean
   is
      File_Item : Ada.Text_IO.File_Type;
      Prefix    : constant String := "scenario_list=";
      Count     : Natural := 0;
   begin
      if not Ada.Directories.Exists (Path) then
         return False;
      end if;

      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
         begin
            if Line_Text'Length >= Prefix'Length
              and then Line_Text (Line_Text'First .. Line_Text'First + Prefix'Length - 1) = Prefix
            then
               Count := Count + 1;
               if not Scenario_List_Line_Is_Well_Formed (Line_Text) then
                  Ada.Text_IO.Close (File_Item);
                  return False;
               end if;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
      return Count = 1;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return False;
   end Report_Has_One_Well_Formed_Scenario_List;

   function Read_Scenario_List_Line (Path : String) return String is
      File_Item : Ada.Text_IO.File_Type;
      Prefix    : constant String := "scenario_list=";
   begin
      if not Ada.Directories.Exists (Path) then
         return "";
      end if;

      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
         begin
            if Has_Prefix (Line_Text, Prefix) then
               Ada.Text_IO.Close (File_Item);
               return Line_Text;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
      return "";
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return "";
   end Read_Scenario_List_Line;

   function Scenario_Record_Count
     (Path          : String;
      Scenario_Name : String)
      return Natural
   is
      File_Item : Ada.Text_IO.File_Type;
      Prefix    : constant String :=
        "scenario=" & Canonical_Scenario (Scenario_Name) & " ";
      Count     : Natural := 0;
   begin
      if not Ada.Directories.Exists (Path) then
         return 0;
      end if;

      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
         begin
            if Has_Prefix (Line_Text, Prefix) then
               Count := Count + 1;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
      return Count;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return 0;
   end Scenario_Record_Count;

   function Report_Scenario_Lines_Are_Declared (Path : String) return Boolean is
      File_Item      : Ada.Text_IO.File_Type;
      Scenario_Pfx   : constant String := "scenario=";
      Declared_Line  : constant String := Read_Scenario_List_Line (Path);
   begin
      if Declared_Line'Length = 0 or else not Ada.Directories.Exists (Path) then
         return False;
      end if;

      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
         begin
            if Has_Prefix (Line_Text, Scenario_Pfx) then
               declare
                  Name_First : constant Positive := Line_Text'First + Scenario_Pfx'Length;
                  Name_Last  : Natural := Name_First - 1;
               begin
                  while Name_Last + 1 <= Line_Text'Last
                    and then Line_Text (Name_Last + 1) /= ' '
                  loop
                     Name_Last := Name_Last + 1;
                  end loop;

                  if Name_Last < Name_First
                    or else Name_Last = Line_Text'Last
                  then
                     Ada.Text_IO.Close (File_Item);
                     return False;
                  end if;

                  declare
                     Scenario_Name : constant String :=
                       Canonical_Scenario (Line_Text (Name_First .. Name_Last));
                  begin
                     if not Is_Known_Scenario (Scenario_Name)
                       or else not Scenario_List_Line_Declares
                         (Declared_Line, Scenario_Name)
                     then
                        Ada.Text_IO.Close (File_Item);
                        return False;
                     end if;
                  end;
               end;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
      return True;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return False;
   end Report_Scenario_Lines_Are_Declared;

   function Report_Declared_Scenarios_Have_Exactly_One_Record
     (Path : String)
      return Boolean
   is
      Declared_Line : constant String := Read_Scenario_List_Line (Path);

      function Declared_Count_Is_Correct (Scenario_Name : String) return Boolean is
         Declared : constant Boolean :=
           Scenario_List_Line_Declares (Declared_Line, Scenario_Name);
         Count    : constant Natural := Scenario_Record_Count (Path, Scenario_Name);
      begin
         if Declared then
            return Count = 1;
         end if;
         return Count = 0;
      end Declared_Count_Is_Correct;
   begin
      if Declared_Line'Length = 0 then
         return False;
      end if;

      return Declared_Count_Is_Correct ("DIRECT")
        and then Declared_Count_Is_Correct ("AGENT")
        and then Declared_Count_Is_Correct ("IDENTITY")
        and then Declared_Count_Is_Correct ("PASSWORD")
        and then Declared_Count_Is_Correct ("PASSPHRASE")
        and then Declared_Count_Is_Correct ("PROXYJUMP")
        and then Declared_Count_Is_Correct ("RECEIVE");
   exception
      when others =>
         return False;
   end Report_Declared_Scenarios_Have_Exactly_One_Record;

   function Report_Declares_Scenario
     (Path          : String;
      Scenario_Name : String)
      return Boolean
   is
      File_Item : Ada.Text_IO.File_Type;
   begin
      if not Ada.Directories.Exists (Path) then
         return False;
      end if;

      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
         begin
            if Scenario_List_Line_Declares (Line_Text, Scenario_Name) then
               Ada.Text_IO.Close (File_Item);
               return True;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
      return False;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return False;
   end Report_Declares_Scenario;

   function Scenario_Line_Passed
     (Path          : String;
      Scenario_Name : String)
      return Boolean
   is
      File_Item : Ada.Text_IO.File_Type;
      Prefix    : constant String :=
        "scenario=" & Canonical_Scenario (Scenario_Name) &
        " result=PASS stage=complete bytes=";
   begin
      if not Ada.Directories.Exists (Path) then
         return False;
      end if;

      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
         begin
            if Positive_Bytes_Field (Line_Text, Prefix)
              and then Index (Line_Text, " session_opened=true") /= 0
              and then Index (Line_Text, " channel_opened=true") /= 0
              and then Index (Line_Text, " exit_code=0 ") /= 0
              and then Scenario_Metadata_Matches (Line_Text, Scenario_Name)
            then
               Ada.Text_IO.Close (File_Item);
               return True;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
      return False;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return False;
   end Scenario_Line_Passed;

   procedure Require_Scenario (Path : String; Scenario_Name : String) is
      Record_Count : constant Natural := Scenario_Record_Count (Path, Scenario_Name);
   begin
      if not Report_Declares_Scenario (Path, Scenario_Name) then
         Fail
           ("live Git matrix report scenario_list does not declare required scenario in " &
            Path & ": " & Canonical_Scenario (Scenario_Name));
      end if;

      if Record_Count /= 1 then
         Fail
           ("live Git matrix report must contain exactly one required scenario record in " &
            Path & ": " & Canonical_Scenario (Scenario_Name));
      end if;

      if not Scenario_Line_Passed (Path, Scenario_Name) then
         Fail
           ("missing completed passing live Git matrix scenario in " & Path &
            ": " & Canonical_Scenario (Scenario_Name));
      end if;
   end Require_Scenario;

   procedure Require_Scenarios (Path : String; Scenario_List : String) is
      Start_Index : Positive := Scenario_List'First;
      Stop_Index  : Natural;
   begin
      if Scenario_List'Length = 0 then
         Require_Scenario (Path, "DIRECT");
         return;
      end if;

      while Start_Index <= Scenario_List'Last loop
         Stop_Index := Start_Index;
         while Stop_Index <= Scenario_List'Last
           and then Scenario_List (Stop_Index) /= ','
         loop
            Stop_Index := Stop_Index + 1;
         end loop;

         if Stop_Index > Start_Index then
            declare
               Scenario_Name : constant String :=
                 Canonical_Scenario
                   (Scenario_List (Start_Index .. Stop_Index - 1));
            begin
               if Scenario_Name = "ALL" then
                  Require_Scenario (Path, "DIRECT");
                  Require_Scenario (Path, "AGENT");
                  Require_Scenario (Path, "IDENTITY");
                  Require_Scenario (Path, "PASSWORD");
                  Require_Scenario (Path, "PASSPHRASE");
                  Require_Scenario (Path, "PROXYJUMP");
                  Require_Scenario (Path, "RECEIVE");
               elsif Scenario_Name'Length = 0 then
                  Fail ("empty scenario in SSH_LIB_REQUIRED_LIVE_GIT_SCENARIOS");
               elsif Is_Known_Scenario (Scenario_Name) then
                  Require_Scenario (Path, Scenario_Name);
               else
                  Fail
                    ("unknown scenario in SSH_LIB_REQUIRED_LIVE_GIT_SCENARIOS: " &
                     Scenario_Name);
               end if;
            end;
         else
            Fail ("empty scenario in SSH_LIB_REQUIRED_LIVE_GIT_SCENARIOS");
         end if;

         Start_Index := Stop_Index + 1;
      end loop;
   end Require_Scenarios;

   Require_Report      : constant Boolean :=
     Enabled (Env ("SSH_LIB_REQUIRE_LIVE_GIT_REPORT"));
   Default_Report_Path : constant String :=
     "release_artifacts/live_git_matrix_report.txt";
   Configured_Report_Path : constant String := Env ("SSH_LIB_LIVE_GIT_REPORT");
   Report_Path : constant String :=
     (if Configured_Report_Path'Length = 0 then Default_Report_Path
      else Configured_Report_Path);
   Scenario_List : constant String := Env ("SSH_LIB_REQUIRED_LIVE_GIT_SCENARIOS");
begin
   if not Require_Report then
      Ada.Text_IO.Put_Line
        ("live Git matrix report guard skipped: set SSH_LIB_REQUIRE_LIVE_GIT_REPORT=1 to require an archived report");
      return;
   end if;

   if not Ada.Directories.Exists (Report_Path) then
      Fail ("missing live Git matrix report: " & Report_Path);
   else
      Require_Exact_Line (Report_Path, "ssh_lib_live_git_interop_matrix_report_version=1");
      Require_Exact_Line (Report_Path, "enabled=true");
      Require_Text (Report_Path, "scenario_list=");
      if not Report_Has_One_Well_Formed_Scenario_List (Report_Path) then
         Fail
           ("live Git matrix report must contain exactly one well-formed scenario_list line with no duplicate scenario names");
      end if;
      if not Report_Scenario_Lines_Are_Declared (Report_Path) then
         Fail
           ("live Git matrix report scenario records must be known and declared by scenario_list");
      end if;
      if not Report_Declared_Scenarios_Have_Exactly_One_Record (Report_Path) then
         Fail
           ("live Git matrix report must contain exactly one record for every declared scenario and none for undeclared scenarios");
      end if;
      Require_Exact_Line (Report_Path, "result=PASS");
      Reject_Text (Report_Path, "result=FAIL");
      Reject_Text (Report_Path, "result=SKIP");
      Reject_Text (Report_Path, "status=INVALID_CONFIG");
      Reject_Text (Report_Path, "reason=disabled");
      Reject_Text (Report_Path, "reason=unhandled_exception");
      Require_Scenarios (Report_Path, Scenario_List);
   end if;

   if Failure_Count /= 0 then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   else
      Ada.Text_IO.Put_Line ("live Git matrix report guard passed");
   end if;
end Check_Live_Git_Matrix_Report;
