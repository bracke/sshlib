with Ada.Characters.Latin_1;
with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Maps.Constants;
with Ada.Text_IO;

procedure Check_Compile_Preflight is
   use Ada.Strings.Fixed;
   use type Ada.Directories.File_Kind;

   Failure_Count : Natural := 0;

   procedure Fail (Message_Text : String) is
   begin
      Ada.Text_IO.Put_Line ("FAIL: " & Message_Text);
      Failure_Count := Failure_Count + 1;
   end Fail;

   function Lower (Value : String) return String is
   begin
      return Ada.Strings.Fixed.Translate
        (Value, Ada.Strings.Maps.Constants.Lower_Case_Map);
   end Lower;

   function Has_Suffix (Value : String; Suffix : String) return Boolean is
   begin
      return Value'Length >= Suffix'Length
        and then Value (Value'Last - Suffix'Length + 1 .. Value'Last) = Suffix;
   end Has_Suffix;

   function Is_Ada_Source (Name_Text : String) return Boolean is
      Lower_Name : constant String := Lower (Name_Text);
   begin
      return Has_Suffix (Lower_Name, ".ads")
        or else Has_Suffix (Lower_Name, ".adb");
   end Is_Ada_Source;

   function Is_Identifier_Character (Item : Character) return Boolean is
   begin
      return (Item >= 'a' and then Item <= 'z')
        or else (Item >= 'A' and then Item <= 'Z')
        or else (Item >= '0' and then Item <= '9')
        or else Item = '_';
   end Is_Identifier_Character;

   function Is_Ada_Keyword (Lower_Name : String) return Boolean is
   begin
      return Lower_Name = "abort"
        or else Lower_Name = "abs"
        or else Lower_Name = "abstract"
        or else Lower_Name = "accept"
        or else Lower_Name = "access"
        or else Lower_Name = "aliased"
        or else Lower_Name = "all"
        or else Lower_Name = "and"
        or else Lower_Name = "array"
        or else Lower_Name = "at"
        or else Lower_Name = "begin"
        or else Lower_Name = "body"
        or else Lower_Name = "case"
        or else Lower_Name = "constant"
        or else Lower_Name = "declare"
        or else Lower_Name = "delay"
        or else Lower_Name = "delta"
        or else Lower_Name = "digits"
        or else Lower_Name = "do"
        or else Lower_Name = "else"
        or else Lower_Name = "elsif"
        or else Lower_Name = "end"
        or else Lower_Name = "entry"
        or else Lower_Name = "exception"
        or else Lower_Name = "exit"
        or else Lower_Name = "for"
        or else Lower_Name = "function"
        or else Lower_Name = "generic"
        or else Lower_Name = "goto"
        or else Lower_Name = "if"
        or else Lower_Name = "in"
        or else Lower_Name = "interface"
        or else Lower_Name = "is"
        or else Lower_Name = "limited"
        or else Lower_Name = "loop"
        or else Lower_Name = "mod"
        or else Lower_Name = "new"
        or else Lower_Name = "not"
        or else Lower_Name = "null"
        or else Lower_Name = "of"
        or else Lower_Name = "or"
        or else Lower_Name = "others"
        or else Lower_Name = "out"
        or else Lower_Name = "overriding"
        or else Lower_Name = "parallel"
        or else Lower_Name = "package"
        or else Lower_Name = "pragma"
        or else Lower_Name = "private"
        or else Lower_Name = "procedure"
        or else Lower_Name = "protected"
        or else Lower_Name = "raise"
        or else Lower_Name = "range"
        or else Lower_Name = "record"
        or else Lower_Name = "rem"
        or else Lower_Name = "renames"
        or else Lower_Name = "requeue"
        or else Lower_Name = "return"
        or else Lower_Name = "reverse"
        or else Lower_Name = "select"
        or else Lower_Name = "separate"
        or else Lower_Name = "some"
        or else Lower_Name = "subtype"
        or else Lower_Name = "synchronized"
        or else Lower_Name = "tagged"
        or else Lower_Name = "task"
        or else Lower_Name = "terminate"
        or else Lower_Name = "then"
        or else Lower_Name = "type"
        or else Lower_Name = "until"
        or else Lower_Name = "use"
        or else Lower_Name = "when"
        or else Lower_Name = "while"
        or else Lower_Name = "with"
        or else Lower_Name = "xor";
   end Is_Ada_Keyword;

   function Strip_Comments_And_Strings (Line_Text : String) return String is
      Result : String := Line_Text;
      In_String : Boolean := False;
      Index_Value : Integer := Result'First;
   begin
      while Index_Value <= Result'Last loop
         if In_String then
            if Result (Index_Value) = '"' then
               Result (Index_Value) := ' ';
               if Index_Value < Result'Last and then Result (Index_Value + 1) = '"' then
                  Index_Value := Index_Value + 1;
                  Result (Index_Value) := ' ';
               else
                  In_String := False;
               end if;
            else
               Result (Index_Value) := ' ';
            end if;
         elsif Result (Index_Value) = '"' then
            In_String := True;
            Result (Index_Value) := ' ';
         elsif Result (Index_Value) = '-'
           and then Index_Value < Result'Last
           and then Result (Index_Value + 1) = '-'
         then
            for Tail_Index in Index_Value .. Result'Last loop
               Result (Tail_Index) := ' ';
            end loop;
            exit;
         end if;

         Index_Value := Index_Value + 1;
      end loop;

      return Result;
   end Strip_Comments_And_Strings;

   function Subprogram_Name_Uses_Keyword
     (Lower_Line : String; Prefix_Text : String) return Boolean
   is
      Search_From : Positive := Lower_Line'First;
   begin
      if Lower_Line'Length = 0 then
         return False;
      end if;

      loop
         declare
            Prefix_Position : constant Natural := Index
              (Source  => Lower_Line,
               Pattern => Prefix_Text,
               From    => Search_From);
         begin
            if Prefix_Position = 0 then
               return False;
            end if;

            declare
               Name_First : constant Natural := Prefix_Position + Prefix_Text'Length;
               Name_Last  : Natural := Name_First - 1;
            begin
               while Name_Last < Lower_Line'Last
                 and then Is_Identifier_Character (Lower_Line (Name_Last + 1))
               loop
                  Name_Last := Name_Last + 1;
               end loop;

               if Name_Last >= Name_First
                 and then Is_Ada_Keyword (Lower_Line (Name_First .. Name_Last))
               then
                  return True;
               end if;

               Search_From := Prefix_Position + 1;
               exit when Search_From > Lower_Line'Last;
            end;
         end;
      end loop;

      return False;
   end Subprogram_Name_Uses_Keyword;

   procedure Check_Keyword_Identifier_Declarations
     (Path : String; Line_Number : Natural; Line_Text : String)
   is
      Code_Line  : constant String := Strip_Comments_And_Strings (Line_Text);
      Lower_Line : constant String := Lower (Code_Line);
   begin
      if Subprogram_Name_Uses_Keyword (Lower_Line, "function ") then
         Fail ("Ada keyword used as function name at " & Path
               & ":" & Natural'Image (Line_Number));
      end if;

      if Subprogram_Name_Uses_Keyword (Lower_Line, "procedure ") then
         Fail ("Ada keyword used as procedure name at " & Path
               & ":" & Natural'Image (Line_Number));
      end if;

      for Colon_Index in Lower_Line'Range loop
         if Lower_Line (Colon_Index) = ':' then
            declare
               Name_Last : Natural := Colon_Index - 1;
            begin
               while Name_Last >= Lower_Line'First
                 and then Lower_Line (Name_Last) = ' '
               loop
                  exit when Name_Last = Lower_Line'First;
                  Name_Last := Name_Last - 1;
               end loop;

               if Name_Last >= Lower_Line'First
                 and then Is_Identifier_Character (Lower_Line (Name_Last))
               then
                  declare
                     Name_First : Natural := Name_Last;
                  begin
                     while Name_First > Lower_Line'First
                       and then Is_Identifier_Character (Lower_Line (Name_First - 1))
                     loop
                        Name_First := Name_First - 1;
                     end loop;

                     if Is_Ada_Keyword (Lower_Line (Name_First .. Name_Last)) then
                        Fail ("Ada keyword used as variable/parameter name at "
                              & Path & ":" & Natural'Image (Line_Number)
                              & " -> " & Lower_Line (Name_First .. Name_Last));
                     end if;
                  end;
               end if;
            end;
         end if;
      end loop;
   end Check_Keyword_Identifier_Declarations;

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


   function Count_Text (Path : String; Needle : String) return Natural is
      File_Item : Ada.Text_IO.File_Type;
      Count_Value : Natural := 0;
   begin
      if not Ada.Directories.Exists (Path) then
         return 0;
      end if;

      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
         begin
            if Index (Line_Text, Needle) /= 0 then
               Count_Value := Count_Value + 1;
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);
      return Count_Value;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         return 0;
   end Count_Text;

   procedure Require_File (Path : String) is
   begin
      if not Ada.Directories.Exists (Path) then
         Fail ("missing compile-preflight file: " & Path);
      end if;
   end Require_File;

   procedure Require_Text (Path : String; Needle : String) is
   begin
      if not File_Contains (Path, Needle) then
         Fail ("missing compile-preflight text in " & Path & ": " & Needle);
      end if;
   end Require_Text;

   procedure Require_Absent_Text (Path : String; Needle : String) is
   begin
      if File_Contains (Path, Needle) then
         Fail ("forbidden compile-preflight text in " & Path & ": " & Needle);
      end if;
   end Require_Absent_Text;


   procedure Require_Text_Count (Path : String; Needle : String; Expected_Count : Natural) is
      Actual_Count : constant Natural := Count_Text (Path, Needle);
   begin
      if Actual_Count /= Expected_Count then
         Fail ("unexpected text count in " & Path & ": " & Needle
               & " expected" & Natural'Image (Expected_Count)
               & " got" & Natural'Image (Actual_Count));
      end if;
   end Require_Text_Count;

   function Spec_Path_For_Body (Path : String) return String is
   begin
      if Has_Suffix (Path, ".adb") then
         return Path (Path'First .. Path'Last - 3) & "ads";
      else
         return Path & ".ads";
      end if;
   end Spec_Path_For_Body;

   procedure Check_Ada_Source (Path : String) is
      File_Item : Ada.Text_IO.File_Type;
      Has_Package_Body : Boolean := False;
      Has_Tab : Boolean := False;
      Line_Number : Natural := 0;
      Lower_Path : constant String := Lower (Path);
   begin
      Ada.Text_IO.Open (File_Item, Ada.Text_IO.In_File, Path);
      while not Ada.Text_IO.End_Of_File (File_Item) loop
         declare
            Line_Text : constant String := Ada.Text_IO.Get_Line (File_Item);
            Lower_Line : constant String := Lower (Line_Text);
         begin
            Line_Number := Line_Number + 1;

            Check_Keyword_Identifier_Declarations (Path, Line_Number, Line_Text);

            if Index (Trim (Lower_Line, Ada.Strings.Both), "package body ") = 1 then
               Has_Package_Body := True;
            end if;

            for Character_Item of Line_Text loop
               if Character_Item = Character'Val (9) then
                  Has_Tab := True;
               end if;
            end loop;

            if Index (Lower_Line, "with SSH_Lib.tests.fixtures") /= 0
              and then Index (Lower_Path, "/src/") /= 0
              and then Index (Lower_Path, "/tests/") = 0
            then
               Fail ("library source depends on test fixture at " & Path
                     & ":" & Natural'Image (Line_Number));
            end if;
         end;
      end loop;
      Ada.Text_IO.Close (File_Item);

      if Has_Package_Body and then not Ada.Directories.Exists (Spec_Path_For_Body (Path)) then
         Fail ("package body has no same-unit spec: " & Path);
      end if;

      if Has_Tab then
         Fail ("tab character in Ada source: " & Path);
      end if;
   exception
      when others =>
         if Ada.Text_IO.Is_Open (File_Item) then
            Ada.Text_IO.Close (File_Item);
         end if;
         Fail ("unable to preflight Ada source: " & Path);
   end Check_Ada_Source;

   procedure Scan_Ada_Tree (Directory_Path : String) is
      Search_Item : Ada.Directories.Search_Type;
      Directory_Item : Ada.Directories.Directory_Entry_Type;
   begin
      if not Ada.Directories.Exists (Directory_Path) then
         Fail ("missing source directory: " & Directory_Path);
         return;
      end if;

      Ada.Directories.Start_Search
        (Search    => Search_Item,
         Directory => Directory_Path,
         Pattern   => "*",
         Filter    => [Ada.Directories.Ordinary_File => True,
                       Ada.Directories.Directory => True,
                       Ada.Directories.Special_File => False]);

      while Ada.Directories.More_Entries (Search_Item) loop
         Ada.Directories.Get_Next_Entry (Search_Item, Directory_Item);
         declare
            Full_Path : constant String := Ada.Directories.Full_Name (Directory_Item);
            Name_Text : constant String := Ada.Directories.Simple_Name (Directory_Item);
            Kind_Value : constant Ada.Directories.File_Kind :=
              Ada.Directories.Kind (Directory_Item);
         begin
            if Kind_Value = Ada.Directories.Directory then
               if Name_Text /= "." and then Name_Text /= ".."
                 and then Name_Text /= "obj" and then Name_Text /= "bin"
                 and then Name_Text /= ".git"
               then
                  Scan_Ada_Tree (Full_Path);
               end if;
            elsif Is_Ada_Source (Name_Text) then
               Check_Ada_Source (Full_Path);
            end if;
         end;
      end loop;

      Ada.Directories.End_Search (Search_Item);
   exception
      when others =>
         Fail ("unable to scan source directory: " & Directory_Path);
   end Scan_Ada_Tree;

   procedure Check_Gpr_Project (Path : String; Requires_Executable : Boolean := True) is
   begin
      Require_File (Path);
      Require_Text (Path, "for Source_Dirs use");
      Require_Text (Path, "for Object_Dir use");
      if Requires_Executable then
         Require_Text (Path, "for Exec_Dir use");
      end if;
   end Check_Gpr_Project;

begin
   --  Phase 19 compile-preflight guard: catches source-tree/GPR drift before GNAT.
   Check_Gpr_Project ("SSH_Lib.gpr", Requires_Executable => False);
   Check_Gpr_Project ("tests/tests.gpr");
   Check_Gpr_Project ("tests/security/security_tests.gpr");
   Check_Gpr_Project ("tests/version_integration/version_integration.gpr");
   Check_Gpr_Project ("examples/examples.gpr");
   Check_Gpr_Project ("tools/tools.gpr");

   Require_File ("src/SSH_Lib.ads");
   Require_File ("src/ssh_lib-errors.ads");
   Require_File ("src/ssh_lib-sessions.ads");
   Require_File ("src/ssh_lib-channels.ads");
   Require_File ("src/ssh_lib-git.ads");
   Require_File ("src/ssh_lib-known_hosts.ads");
   Require_File ("src/ssh_lib-config.ads");
   Require_File ("src/ssh_lib-remote_names.ads");
   Require_File ("src/ssh_lib-sessions-open_guards.ads");
   Require_File ("src/ssh_lib-sessions-open_guards.adb");

   Require_Text ("tools/tools.gpr", "check_compile_preflight.adb");
   Require_Text ("docs/TESTING.md", "check_compile_preflight");
   Require_Text ("README.md", "Phase 19 completeness pass 25");
   Require_Text ("tools/check_compile_preflight.adb", "Ada keyword used as variable/parameter name");
   Require_Text ("tools/check_compile_preflight.adb", "Ada keyword used as function name");
   Require_Text ("tools/check_compile_preflight.adb", "Ada keyword used as procedure name");

   --  Pass 100 regression guard: the live group14 KEX path once contained
   --  an orphan duplicate continuation line after setting the session
   --  identifier.  Without GNAT in minimal containers this kind of syntax
   --  drift can otherwise survive source-only passes, so keep a small
   --  preflight count over the exact assignment site.
   Require_Text_Count
     ("src/ssh_lib-sessions-live_transport.adb",
      "Session_Identifier, Digest_To_Array (Exchange_Digest)",
      2);


   --  Pass 104 regression guard: pass 103 briefly introduced a duplicate
   --  local declaration while adding negotiated HMAC-SHA-512 support to
   --  protected-packet setup.  Keep this source-only guard because minimal
   --  containers may not have GNAT available to catch the Ada compile error.
   Require_Text_Count
     ("src/ssh_lib-protocol-protected_packets.adb",
      "Outbound_Kind : Mac_Algorithm",
      1);


   --  Pass 105 regression guard: group14 KEX now follows the same
   --  best-effort secret cleanup discipline as the Curve25519 KEX path.
   --  The live transport must keep a local cleanup routine and invoke it
   --  on success, deterministic failure, and exception containment paths.
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "procedure Clear_Group14_Material is");
   Require_Text_Count
     ("src/ssh_lib-sessions-live_transport.adb",
      "Clear_Group14_Material;",
      21);


   --  Pass 106 regression guard: both live KEX paths must clear derived
   --  key buffers after installing them into the protected transcript.
   --  Curve25519 must also clear its KEX packet buffers, matching group14
   --  cleanup discipline for source-only security passes.
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "SSH_Lib.Protocol.Session_Keys.Clear (Derived_Item);");
   Require_Text_Count
     ("src/ssh_lib-sessions-live_transport.adb",
      "SSH_Lib.Protocol.Session_Keys.Clear (Derived_Item);",
      2);
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "procedure Clear_Curve_Material is");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "SSH_Lib.Protocol.Buffers.Clear (Kex_Init_Payload);");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "SSH_Lib.Protocol.Buffers.Clear (Kex_Reply_Payload);");


   --  Pass 102 regression guard: ProxyJump-backed sessions do not have an
   --  inner TCP socket.  Read_Identification must therefore read the inner
   --  SSH identification through the generic driver path in Jump_Channel_Mode,
   --  not through GNAT.Sockets.Receive_Socket.
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "if Item.Mode = Jump_Channel_Mode then");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "The inner SSH identification is carried over an outer");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "Status_Value := Read_Exact (Item, Byte_Buffer)");



   --  Pass 108 regression guard: comma-separated ProxyJump chains are
   --  implemented recursively by opening the final jump host through the
   --  preceding jump prefix.  Commas inside bracketed IPv6 literals remain
   --  rejected by the single-hop parser, while the chain splitter tracks
   --  bracket state before selecting the final hop.
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "function Split_Proxy_Jump_Chain");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Jump_Options.Proxy_Jump := Prefix_Jumps;");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Final_Hop := To_Unbounded_String (Value (Last_Comma + 1 .. Value'Last));");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "if Value (Host_First) = '[' then");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Unbracketed IPv6 literals are ambiguous with :port");


   --  Pass 109 regression guard: successful ProxyJump tunnel setup transfers
   --  ownership of the outer jump transcript to the inner jump-backed
   --  transcript, then detaches the temporary jump session without closing it.
   --  Closing the public target session must close/free the outer transcript
   --  exactly once rather than leaking it or double-freeing it.
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.ads",
      "Owns_Outer_Driver : Boolean := False;");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "procedure Free_Driver is new Ada.Unchecked_Deallocation");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "if Item.Owns_Outer_Driver and then Item.Outer_Driver /= null then");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Own_Outer       => True");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Detach_Without_Close (Jump_Session)");



   --  Pass 110 regression guard: ProxyJump ownership transfer must free
   --  owned outer transcripts through the same canonical live-transcript
   --  access type used for allocation.  The attachment layer may still store
   --  addresses inside Session, but it must not define a second access type
   --  through Address_To_Access_Conversions and then deallocate owned jump
   --  transcripts through a different access type.
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.ads",
      "type Driver_Access is access all Driver;");
   Require_Text
     ("src/ssh_lib-sessions-live_attachment.ads",
      "subtype Transcript_Access is SSH_Lib.Sessions.Live_Transcript.Driver_Access;");
   Require_Text
     ("src/ssh_lib-sessions-live_attachment.adb",
      "function Address_To_Transcript is new Ada.Unchecked_Conversion");
   Require_Text
     ("src/ssh_lib-sessions-live_attachment.adb",
      "Item.Live_Transcript_Address := Address_Of (Pointer);");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "procedure Free_Driver is new Ada.Unchecked_Deallocation");


   --  Pass 111 regression guard: a jump-backed transcript only owns the
   --  outer transcript when Connect_Through_Jump was called with Own_Outer.
   --  Closing a non-owning jump-backed driver must close the direct-tcpip
   --  channel but must not recursively close or free the caller-owned outer
   --  transport.
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "if Item.Owns_Outer_Driver and then Item.Outer_Driver /= null then");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "Close (Owned_Outer.all);");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "Free_Driver (Owned_Outer);");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "Own_Outer        : Boolean := False");


   --  Pass 112 regression guard: owned ProxyJump outer transcripts must be
   --  released even when the inner jump-backed transcript is only partially
   --  connected or the best-effort CHANNEL_CLOSE path raises.  The close path
   --  detaches the owned pointer before recursive close/free so exception
   --  containment cannot double-free it.
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "procedure Close_Owned_Outer_Quietly");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "Ownership is independent of the inner tunnel's Connected flag");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "Owned_Outer := Item.Outer_Driver;");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "Item.Outer_Driver := null;");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "Close_Owned_Outer_Quietly (Item);");


   --  Pass 113 regression guard: ProxyJump transcript ownership must store
   --  the canonical allocated Driver_Access directly.  It must not derive an
   --  access value from an aliased parameter with Unchecked_Access and later
   --  pass that derived value to Unchecked_Deallocation.
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.ads",
      "Outer            : Driver_Access;");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "Outer            : Driver_Access;");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "if Outer = null");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "Item.Outer_Driver := Outer;");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Jump_Transcript,");
   Require_Absent_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "Outer'Unchecked_Access");
   Require_Absent_Text
     ("src/ssh_lib-sessions-live_transcript.ads",
      "aliased in out Driver");
   Require_Absent_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "aliased in out Driver");

   --  Pass 114 regression guard: if a direct-tcpip open is confirmed
   --  but the inner jump-backed transcript cannot be created or attached,
   --  the remote channel must be closed before local channel-table cleanup.
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "procedure Close_Remote_Tunnel_Quietly");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Remote_Channel_Open := True;");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Close_Remote_Tunnel_Quietly;");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Encode_Channel_Close");

   --  Pass 115 regression guard: jump-backed transcript reads must behave
   --  like the other protected wait loops.  Tunnel reads skip bounded
   --  SSH_MSG_IGNORE/DEBUG/UNIMPLEMENTED packets, fail closed on DISCONNECT,
   --  and reject unsupported global requests with REQUEST_FAILURE when the
   --  peer requested a reply rather than treating all non-channel packets as
   --  raw tunnel failure.
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "with SSH_Lib.Protocol.Global_Requests;");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "with SSH_Lib.Protocol.Transport_Messages;");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "SSH_Lib.Protocol.Global_Requests.SSH_MSG_GLOBAL_REQUEST");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "SSH_Lib.Protocol.Global_Requests.Encode_Request_Failure");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "SSH_Lib.Protocol.Transport_Messages.Is_Ignorable_During_Wait");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "SSH_Lib.Protocol.Transport_Messages.Failure_Status");

   --  Pass 116 regression guard: passphrase-protected identity support
   --  must be explicit, non-interactive, and non-retaining.  Session options
   --  expose an opt-in passphrase field, identity parsers provide passphrase
   --  overloads, live identity userauth passes that secret only to Load, and
   --  stored session options clear it alongside Password.
   Require_Text
     ("src/ssh_lib-sessions.ads",
      "Use_Identity_Passphrase : Boolean := False;");
   Require_Text
     ("src/ssh_lib-sessions.ads",
      "Identity_Passphrase");
   Require_Text
     ("src/ssh_lib-identity_files.ads",
      "Passphrase : String;");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Decrypt_OpenSSH_Encrypted_Section");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Decode_OpenSSH_BCrypt_KDF_Options");
   Require_Text
     ("src/ssh_lib-sessions.adb",
      "Result.Identity_Passphrase := Null_Unbounded_String;");
   Require_Text
     ("src/ssh_lib-sessions-close_pipeline.adb",
      "Item.Stored_Options.Identity_Passphrase := Null_Unbounded_String;");
   Require_Text
     ("src/ssh_lib-sessions-live_userauth.adb",
      "Options.Use_Identity_Passphrase");

   --  Pass 143 regression guard: interactive credential callbacks remain
   --  caller-provided, non-storing, and protected-userauth-only.
   Require_Text
     ("src/ssh_lib-sessions.ads",
      "type Password_Callback_Access is access function");
   Require_Text
     ("src/ssh_lib-sessions.ads",
      "type Identity_Passphrase_Callback_Access is access function");
   Require_Text
     ("src/ssh_lib-sessions.ads",
      "type Password_Change_Callback_Access is access function");
   Require_Text
     ("src/ssh_lib-sessions.adb",
      "Result.Password_Callback := null;");
   Require_Text
     ("src/ssh_lib-sessions-close_pipeline.adb",
      "Item.Stored_Options.Password_Change_Callback := null;");
   Require_Text
     ("src/ssh_lib-sessions-live_userauth.adb",
      "Effective_Password (Options)");
   Require_Text
     ("src/ssh_lib-sessions-live_userauth.adb",
      "Effective_Identity_Passphrase (Options)");
   Require_Text
     ("src/ssh_lib-sessions-live_userauth.adb",
      "Effective_New_Password");
   Require_Text
     ("src/ssh_lib-protocol-userauth.ads",
      "Encode_Password_Change_Request");


   --  Pass 144 regression guard: callback results are normalized and cleared
   --  in both live and deterministic identity-passphrase paths.
   Require_Text
     ("src/ssh_lib-sessions-live_userauth.adb",
      "procedure Clear_Callback_Result");
   Require_Text
     ("src/ssh_lib-sessions-live_userauth.adb",
      "Clear_Callback_Result (Callback_Result);");
   Require_Text
     ("src/ssh_lib-sessions-open_runtime.adb",
      "function Valid_Callback_Secret");
   Require_Text
     ("src/ssh_lib-sessions-open_runtime.adb",
      "function Deterministic_Password");
   Require_Text
     ("src/ssh_lib-sessions-userauth_io.ads",
      "function Run_Password_Userauth");
   Require_Text
     ("src/ssh_lib-sessions-userauth_io.adb",
      "Send_Password_Userauth_Payload");
   Require_Text
     ("tests/src/fixtures/ssh_lib-tests-fixtures-open_runtime.adb",
      "password callback secret is not retained in the plain transcript");

   --  Pass 117/146 regression guard: OpenSSH encrypted private keys use
   --  the OpenBSD bcrypt_pbkdf KDF.  The passphrase API remains explicit
   --  and non-retaining, and the encrypted OpenSSH private-section path
   --  must not silently substitute SHA-2 stretching for bcrypt_pbkdf.
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "OpenSSH encrypted private keys use bcrypt_pbkdf");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "implementation so this code cannot accidentally substitute PBKDF2");
   Require_Text
     ("../cryptolib/src/cryptolib-bcrypt_pbkdf.adb",
      "procedure BCrypt_Hash");
   Require_Text
     ("tests/security/README.md",
      "OpenSSH bcrypt-encrypted private keys now route through the Ada bcrypt_pbkdf implementation");

   --  Pass 118/146 regression guard: fixtures must distinguish malformed
   --  encrypted OpenSSH key material from a syntactically valid bcrypt KDF
   --  envelope.  With bcrypt_pbkdf present, the syntactic envelope reaches
   --  derivation and then rejects the fixture's invalid decrypted payload.
   Require_Text
     ("tests/src/fixtures/ssh_lib-tests-fixtures-identity_files.ads",
      "Encrypted_OpenSSH_BCrypt_Envelope_Private_Key");
   Require_Text
     ("tests/src/fixtures/ssh_lib-tests-fixtures-auth_security.adb",
      "valid OpenSSH bcrypt KDF envelope derives and rejects invalid decrypted payload");
   Require_Text
     ("tests/src/main.adb",
      "phase146 valid bcrypt KDF envelope derives and rejects invalid decrypted payload");



   --  Pass 119 regression guard: the KDF option parser must bound salt and
   --  round counts before the expensive bcrypt_pbkdf derivation path is
   --  entered.
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Max_OpenSSH_BCrypt_Salt_Length");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Max_OpenSSH_BCrypt_Rounds");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Rounds > Max_OpenSSH_BCrypt_Rounds");
   Require_Text
     ("docs/RUNTIME_BOUNDARIES.md",
      "bounds OpenSSH bcrypt KDF salt length and round counts before bcrypt_pbkdf derivation");


   --  Pass 120 regression guard: encrypted OpenSSH parsing must route bcrypt
   --  derivation attempts through a dedicated bcrypt_pbkdf crypto boundary.
   --  The identity parser must not perform ad hoc SHA stretching or clear the
   --  decoded salt before handing it to that boundary, and the temporary
   --  derived buffer must be scrubbed before any return.
   Require_File ("../cryptolib/src/cryptolib-bcrypt_pbkdf.ads");
   Require_File ("../cryptolib/src/cryptolib-bcrypt_pbkdf.adb");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "with CryptoLib.BCrypt_PBKDF;");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Status_Value := CryptoLib.BCrypt_PBKDF.Derive");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Salt_Data  => To_Array (Salt_Buffer)");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Derived_Data := (others => 0);");
   Require_Text
     ("../cryptolib/src/cryptolib-bcrypt_pbkdf.adb",
      "procedure BCrypt_Hash");
   Require_Absent_Text
     ("src/ssh_lib-identity_files.adb",
      "return Finish (Internal_Error);\n         return Finish (Internal_Error);");

   --  Pass 121 regression guard: parsed identity private-key material must be
   --  cleared after live identity-file authentication attempts.  Passphrase
   --  support made the private-key path more sensitive, so both live and
   --  deterministic-open paths must scrub Identity_Key records on success,
   --  deterministic failure, and exception containment.
   Require_Text
     ("src/ssh_lib-sessions-live_userauth.adb",
      "function Finish (Result : Status) return Status is");
   Require_Text
     ("src/ssh_lib-sessions-live_userauth.adb",
      "SSH_Lib.Identity_Files.Clear (Key_Item);");
   Require_Text
     ("src/ssh_lib-sessions-live_userauth.adb",
      "Clear (Request_Buffer);");
   Require_Text
     ("src/ssh_lib-sessions-open_runtime.adb",
      "SSH_Lib.Identity_Files.Clear (Key_Item);");
   Require_Text
     ("src/ssh_lib-sessions-open_runtime.adb",
      "when others =>" & Character'Val (10) &
      "               SSH_Lib.Identity_Files.Clear (Key_Item);");

   --  Pass 122 regression guard: the bcrypt_pbkdf boundary must not mark
   --  Passphrase as unreferenced while it still validates Passphrase'Length.
   --  GNAT treats stale Unreferenced pragmas as a source hygiene/compile risk,
   --  and this guard keeps the explicit passphrase path buildable.
   Require_Absent_Text
     ("../cryptolib/src/cryptolib-bcrypt_pbkdf.adb",
      "pragma Unreferenced (Passphrase);");
   Require_Text
     ("../cryptolib/src/cryptolib-bcrypt_pbkdf.adb",
      "or else Passphrase'Length = 0");



   --  Pass 123/146 regression guard: encrypted OpenSSH private-section
   --  handling must perform the AES-CTR unwrap with the derived key and IV.
   --  The parser must not fail closed merely because the KDF boundary
   --  returns Ok.
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "with CryptoLib.Ciphers;");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Key_Data       : Stream_Element_Array");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "IV_Data        : Stream_Element_Array (1 .. 16)");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Status_Value := CryptoLib.Ciphers.Initialize");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Status_Value := CryptoLib.Ciphers.Decrypt");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Status_Value := Set (Plaintext, Decrypted_Data);");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "CryptoLib.Ciphers.Reset (Cipher_State);");


   --  Pass 124 regression guard: the bcrypt_pbkdf boundary must bound the
   --  requested output length before derivation.  OpenSSH encrypted private
   --  keys currently need only cipher-key plus IV material, and unbounded
   --  output requests must fail closed without leaving derived bytes in
   --  caller-visible buffers.
   Require_Text
     ("../cryptolib/src/cryptolib-bcrypt_pbkdf.ads",
      "Max_Output_Length : constant Natural := 64;");
   Require_Text
     ("../cryptolib/src/cryptolib-bcrypt_pbkdf.adb",
      "if Output'Length = 0");
   Require_Text
     ("../cryptolib/src/cryptolib-bcrypt_pbkdf.adb",
      "Output'Length > Max_Output_Length");
   Require_Text
     ("tests/src/main.adb",
      "phase146 bcrypt_pbkdf derives OpenSSH key material");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Max_OpenSSH_BCrypt_Output_Size : constant Natural := CryptoLib.BCrypt_PBKDF.Max_Output_Length;");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "if Derived_Length > Max_OpenSSH_BCrypt_Output_Size then");

   --  Pass 125 regression guard: identity-file loading converts private-key
   --  bytes into a temporary text buffer before parsing.  The passphrase-aware
   --  path must scrub both temporary representations on success, deterministic
   --  failure, and exception containment.
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "function Finish_Text_Parse (Result : Status) return Status is");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Text := (others => Character'Val (0));");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Data := (others => 0);");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "return Finish_Text_Parse (Parse_Status);");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "return Finish_Text_Parse (Internal_Error);");



   --  Pass 126 regression guard: runtime-boundary documentation must not
   --  regress to the obsolete Phase 50 claim that the public network path
   --  still stops before live KEX/NEWKEYS/protected userauth.  The current
   --  source tree is wired much further; remaining release risk is build and
   --  live interoperability verification, not an intentional pre-KEX stub.
   Require_Absent_Text
     ("docs/RUNTIME_BOUNDARIES.md",
      "live key exchange, exchange-hash verification, NEWKEYS, encrypted packet IO, known-host verification, and userauth still have to be wired");
   Require_Text
     ("docs/RUNTIME_BOUNDARIES.md",
      "Phase 19 pass 126 refreshes this runtime-boundary inventory");
   Require_Text
     ("docs/RUNTIME_BOUNDARIES.md",
      "lack of GNAT build verification and lack of live interoperability runs");


   --  Pass 127 regression guard: the live Git proof must include a real
   --  interoperability matrix, not only a single manually configured live
   --  target.  The matrix remains opt-in/no-network by default but must
   --  exercise the Version-facing public channel sequence and strict
   --  known-host verification when enabled.
   Require_Text
     ("tests/security/security_tests.gpr",
      "test_live_git_interop_matrix.adb");
   Require_Text
     ("tests/security/test_live_git_interop_matrix.adb",
      "SSH_LIB_LIVE_GIT_MATRIX");
   Require_Text
     ("tests/security/test_live_git_interop_matrix.adb",
      "SSH_LIB_LIVE_GIT_SCENARIOS");
   Require_Text
     ("tests/security/test_live_git_interop_matrix.adb",
      "Options.Verify_Known_Host := True;");
   Require_Text
     ("tests/security/test_live_git_interop_matrix.adb",
      "Options.Strict_Host_Key := True;");
   Require_Text
     ("tests/security/test_live_git_interop_matrix.adb",
      "Options.Proxy_Jump := To_Unbounded_String (Proxy_Jump_Text);");
   Require_Text
     ("tests/security/test_live_git_interop_matrix.adb",
      "Options.Use_Identity_Passphrase := True;");
   Require_Text
     ("tests/security/test_live_git_interop_matrix.adb",
      "SSH_Lib.Channels.Open_Exec");
   Require_Text
     ("tests/security/test_live_git_interop_matrix.adb",
      "SSH_Lib.Channels.Write");
   Require_Text
     ("tests/security/test_live_git_interop_matrix.adb",
      "SSH_Lib.Channels.Read_Some");

   --  Pass 128 regression guard: the opt-in live interoperability matrix
   --  must parse scenario lists predictably.  Scenario names are normalized
   --  case-insensitively, unknown values fail closed before network access,
   --  ALL expands to the full matrix, and sensitive password/passphrase
   --  option fields are cleared after each scenario.
   Require_Text
     ("tests/security/test_live_git_interop_matrix.adb",
      "function Canonical_Scenario_Name");
   Require_Text
     ("tests/security/test_live_git_interop_matrix.adb",
      "Ada.Characters.Handling.To_Upper");
   Require_Text
     ("tests/security/test_live_git_interop_matrix.adb",
      "function Is_Known_Scenario");
   Require_Text
     ("tests/security/test_live_git_interop_matrix.adb",
      "unknown live Git matrix scenario");
   Require_Text
     ("tests/security/test_live_git_interop_matrix.adb",
      "Scenario_Name = ""ALL""");
   Require_Text
     ("tests/security/test_live_git_interop_matrix.adb",
      "procedure Clear_Sensitive_Options");
   Require_Text
     ("tests/security/test_live_git_interop_matrix.adb",
      "Clear_Sensitive_Options (Options);");



   --  Pass 130 regression guard: live ProxyJump verification must not rely
   --  only on the Git interoperability matrix.  A dedicated opt-in transport
   --  proof must exercise strict known-host ProxyJump session open, exec over
   --  the jump-backed target transport, stdout reads, exit-status observation,
   --  close semantics, single-hop/multi-hop/IPV6 scenario selection, and
   --  sensitive option cleanup without public-network work by default.
   Require_Text
     ("tests/security/security_tests.gpr",
      "test_live_proxyjump_transport.adb");
   Require_Text
     ("tests/security/test_live_proxyjump_transport.adb",
      "SSH_LIB_LIVE_PROXYJUMP");
   Require_Text
     ("tests/security/test_live_proxyjump_transport.adb",
      "SSH_LIB_LIVE_PROXYJUMP_SCENARIOS");
   Require_Text
     ("tests/security/test_live_proxyjump_transport.adb",
      "Options.Verify_Known_Host := True;");
   Require_Text
     ("tests/security/test_live_proxyjump_transport.adb",
      "Options.Strict_Host_Key := True;");
   Require_Text
     ("tests/security/test_live_proxyjump_transport.adb",
      "Options.Proxy_Jump := To_Unbounded_String (Proxy_Jump_Text);");
   Require_Text
     ("tests/security/test_live_proxyjump_transport.adb",
      "Scenario_Name = ""CHAIN""");
   Require_Text
     ("tests/security/test_live_proxyjump_transport.adb",
      "Scenario_Name = ""IPV6""");
   Require_Text
     ("tests/security/test_live_proxyjump_transport.adb",
      "SSH_Lib.Channels.Open_Exec");
   Require_Text
     ("tests/security/test_live_proxyjump_transport.adb",
      "SSH_Lib.Channels.Read_Some");
   Require_Text
     ("tests/security/test_live_proxyjump_transport.adb",
      "SSH_Lib.Channels.Exit_Status");
   Require_Text
     ("tests/security/test_live_proxyjump_transport.adb",
      "Clear_Sensitive_Options (Options);");

   --  Pass 131 regression guard: live ProxyJump scenario selectors must
   --  reject empty comma-separated tokens instead of silently skipping them.
   Require_Text
     ("tests/security/test_live_proxyjump_transport.adb",
      "empty live ProxyJump scenario in list");
   Require_Text
     ("tests/security/test_live_proxyjump_transport.adb",
      "if Stop_Index = Start_Index then");
   Require_Text
     ("tests/security/test_live_proxyjump_transport.adb",
      "if Scenario_Name'Length = 0 then");


   --  Pass 132 regression guard: live rekeying must preserve the original
   --  SSH session identifier while deriving new keys from the new exchange
   --  hash and must carry rekey packets through protected transport after
   --  NEWKEYS has made encryption active.
   Require_Text
     ("src/ssh_lib-sessions.ads",
      "function Rekey");
   Require_Text
     ("src/ssh_lib-sessions.ads",
      "Live_Session_Identifier");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.ads",
      "function Rekey");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Established_Session_Identifier");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Buffer_To_Digest");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Send_Key_Exchange_Packet");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "if Item.Protected_Installed then");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Item.Live_Rekey_Count := Item.Live_Rekey_Count + 1");

   Require_Text
     ("tests/security/security_tests.gpr",
      "test_live_rekey_transport.adb");
   Require_Text
     ("tests/security/test_live_rekey_transport.adb",
      "SSH_LIB_LIVE_REKEY=1");
   Require_Text
     ("tests/security/test_live_rekey_transport.adb",
      "SSH_Lib.Sessions.Rekey (Session_Item)");
   Require_Text
     ("tests/security/test_live_rekey_transport.adb",
      "Sessions.Rekey before exec");
   Require_Text
     ("tests/security/test_live_rekey_transport.adb",
      "Sessions.Rekey after exec");
   Require_Text
     ("tests/security/test_live_rekey_transport.adb",
      "Verify_Known_Host := True");

   --  Pass 133 regression guard: peer-initiated rekey must preserve an
   --  already-read server KEXINIT and dispatch it through the owning session
   --  instead of treating it as channel data.
   Require_Text
     ("src/ssh_lib-sessions-live_transport.ads",
      "Rekey_With_Peer_Kexinit");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "function Rekey_With_Peer_Kexinit");
   Require_Text
     ("src/ssh_lib-channels.ads",
      "Owning_Session_Address");
   Require_Text
     ("src/ssh_lib-channels.adb",
      "Handle_Peer_Initiated_Rekey");
   Require_Text
     ("src/ssh_lib-channels.adb",
      "SSH_Lib.Protocol.Messages.SSH_MSG_KEXINIT");
   Require_Text
     ("src/ssh_lib-channels.adb",
      "Rekey_With_Peer_Kexinit");


   --  Pass 134 regression guard: Curve25519 must remain a fixed-limb
   --  implementation and must not fall back to Ada big-integer arithmetic.
   Require_Absent_Text
     ("../cryptolib/src/cryptolib-curve25519.adb",
      "Ada.Numerics.Big_Numbers.Big_Integers");
   Require_Absent_Text
     ("../cryptolib/src/cryptolib-curve25519.adb",
      "Big_Integer");
   Require_Text
     ("../cryptolib/src/cryptolib-curve25519.adb",
      "type Field_Element is array (Limb_Index) of Long_Long_Integer");
   Require_Text
     ("../cryptolib/src/cryptolib-curve25519.adb",
      "procedure Conditional_Swap");
   Require_Text
     ("../cryptolib/src/cryptolib-curve25519.adb",
      "Swap_Mask");
   Require_Text
     ("../cryptolib/src/cryptolib-curve25519.adb",
      "for Bit_Index in reverse 0 .. 254 loop");
   Require_Text
     ("../cryptolib/src/cryptolib-curve25519.adb",
      "Received_U (32) := Received_U (32) and Stream_Element'(16#7F#);");

   --  Pass 135 regression guard: the fixed-limb X25519 function must not
   --  contain an orphan nested begin after the function body begin.
   Require_Absent_Text
     ("../cryptolib/src/cryptolib-curve25519.adb",
      "begin" & Ada.Characters.Latin_1.LF & "   begin" & Ada.Characters.Latin_1.LF & "      Result_Item := (others => 0);");

   --  Pass 136 regression guard: OpenSSH encrypt-then-MAC algorithms must
   --  remain advertised, negotiated, and implemented with clear packet-length
   --  headers plus MAC verification over ciphertext before decryption.
   Require_Text
     ("src/ssh_lib-algorithms.adb",
      "umac-128-etm@openssh.com,umac-64-etm@openssh.com,umac-128@openssh.com,umac-64@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1-etm@openssh.com,hmac-sha1,hmac-sha1-96-etm@openssh.com,hmac-sha1-96");
   Require_Text
     ("src/ssh_lib-protocol-protected_packets.ads",
      "HMAC_SHA2_512_ETM");
   Require_Text
     ("src/ssh_lib-protocol-protected_packets.ads",
      "function Inbound_Header_Is_Clear");
   Require_Text
     ("src/ssh_lib-protocol-protected_packets.adb",
      "function Is_EtM");
   Require_Text
     ("src/ssh_lib-protocol-protected_packets.adb",
      "Plain_Header := Encrypted_Header;");
   Require_Text
     ("src/ssh_lib-protocol-protected_packets.adb",
      "Wire_Packet");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "hmac-sha2-512-etm@openssh.com");
   Require_Text
     ("tests/src/main.adb",
      "phase19 aes256/hmac512-etm protected packet decode");

   --  Pass 156 regression guard: RFC 8308 extension negotiation must broaden
   --  real-server algorithm interoperability without letting the marker become
   --  a selectable KEX algorithm.
   Require_Text
     ("src/ssh_lib-algorithms.ads",
      "Extension_Only");
   Require_Text
     ("src/ssh_lib-algorithms.adb",
      "diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c");
   Require_Text
     ("src/ssh_lib-algorithms.adb",
      "return Extension_Only;");
   Require_Text
     ("src/ssh_lib-protocol-messages.ads",
      "SSH_MSG_EXT_INFO");
   Require_Text
     ("src/ssh_lib-protocol-transport_messages.ads",
      "Transport_Ext_Info");
   Require_Text
     ("src/ssh_lib-protocol-transport_messages.adb",
      "Transport_Ext_Info");


   --  Pass 159 regression guard: bounded group14 SHA-1 compatibility KEX is
   --  only valid when the live path computes SHA-1 exchange hashes and derives
   --  SHA-1 session keys; it must not be a documentation-only advertisement.
   Require_Text
     ("src/ssh_lib-algorithms.adb",
      "diffie-hellman-group14-sha1");
   Require_Text
     ("src/ssh_lib-protocol-exchange_hash.ads",
      "Compute_Group14_SHA1");
   Require_Text
     ("src/ssh_lib-protocol-session_keys.ads",
      "Derive_SHA1_Keys");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Compute_Group14_SHA1");
   Require_Text
     ("tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.adb",
      "legacy-compatible group14 SHA-1 KEX intersects successfully");
   Require_Text
     ("tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.adb",
      "RFC8308 ext-info-c marker is not selected as a key exchange");


   --  Pass 138 regression guard: live transports must support automatic
   --  client-initiated rekey after configurable packet or byte thresholds.
   Require_Text
     ("src/ssh_lib-sessions.ads",
      "Automatic_Rekey     : Boolean := True");
   Require_Text
     ("src/ssh_lib-sessions.ads",
      "Rekey_After_Packets : Natural := 1_000_000");
   Require_Text
     ("src/ssh_lib-sessions.ads",
      "Rekey_After_Bytes   : Interfaces.Unsigned_64 := 1_073_741_824");
   Require_Text
     ("src/ssh_lib-sessions.ads",
      "Rekey_After_Seconds : Natural := 3_600");
   Require_Text
     ("src/ssh_lib-sessions.ads",
      "Live_Packets_Since_Rekey");
   Require_Text
     ("src/ssh_lib-sessions.ads",
      "Live_Rekey_Started");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.ads",
      "Check_Automatic_Rekey");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.ads",
      "function Automatic_Rekey_Needed");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "function Automatic_Rekey_Needed");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Item.Live_Packets_Since_Rekey >= Packet_Limit");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Item.Live_Bytes_Since_Rekey >= Byte_Limit");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "function Time_Based_Rekey_Needed");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Time_Based_Rekey_Needed (Item)");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Item.Live_Rekey_Started := Ada.Calendar.Clock");
   Require_Text
     ("src/ssh_lib-sessions-channel_io.adb",
      "Check_Automatic_Rekey (Item)");
   Require_Text
     ("src/ssh_lib-channels.adb",
      "Check_Automatic_Rekey");
   Require_Text
     ("src/ssh_lib-sessions.ads",
      "client-initiated automatic");
   Require_Text
     ("src/ssh_lib-sessions.ads",
      "Reads do not start a client rekey");
   Require_Text
     ("README.md",
      "reads do not start a client rekey in the middle of pending peer data");
   Require_Text
     ("README.md",
      "Rekey_After_Seconds");
   Require_Text
     ("src/ssh_lib-sessions-test_support.ads",
      "Automatic_Rekey_Needed_For_Test");
   Require_Text
     ("tests/src/main.adb",
      "time-based automatic rekey becomes due at elapsed threshold");
   Require_Text
     ("tests/src/main.adb",
      "disabled automatic rekey suppresses elapsed trigger");
   Require_Absent_Text
     ("src/ssh_lib-sessions.ads",
      "before sending or reading more channel data");



   --  Pass 140 regression guard: SSH MAC fallback coverage must include
   --  hmac-sha1, hmac-sha1-etm@openssh.com, hmac-sha1-96, and
   --  hmac-sha1-96-etm@openssh.com only as lowest-priority interoperability
   --  fallbacks, with real SHA-1/HMAC-SHA1 packet MAC implementation,
   --  20-byte full SHA-1 MACs, and 12-byte truncated SHA-1-96 MACs.
   Require_Text
     ("../cryptolib/src/cryptolib-hashes.ads",
      "type SHA1_Digest is array");
   Require_Text
     ("../cryptolib/src/cryptolib-hashes.adb",
      "function SHA1");
   Require_Text
     ("../cryptolib/src/cryptolib-macs.ads",
      "function HMAC_SHA1");
   Require_Text
     ("src/ssh_lib-protocol-protected_packets.ads",
      "SHA1_Mac_Length : constant Natural := 20");
   Require_Text
     ("src/ssh_lib-protocol-protected_packets.ads",
      "HMAC_SHA1_ETM");
   Require_Text
     ("src/ssh_lib-protocol-protected_packets.ads",
      "HMAC_SHA1_96_ETM");
   Require_Text
     ("src/ssh_lib-protocol-protected_packets.adb",
      "function SHA1_96_Digest_To_Array");
   Require_Text
     ("src/ssh_lib-protocol-protected_packets.adb",
      "return 12;");
   Require_Text
     ("src/ssh_lib-protocol-protected_packets.adb",
      "CryptoLib.Macs.HMAC_SHA1");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "hmac-sha1-etm@openssh.com");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "hmac-sha1-96-etm@openssh.com");
   Require_Text
     ("src/ssh_lib-algorithms.adb",
      "umac-128-etm@openssh.com,umac-64-etm@openssh.com,umac-128@openssh.com,umac-64@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1-etm@openssh.com,hmac-sha1,hmac-sha1-96-etm@openssh.com,hmac-sha1-96");
   Require_Text
     ("tests/src/main.adb",
      "phase4 hmac sha1 vector");
   Require_Text
     ("tests/src/main.adb",
      "implemented hmac-sha1-96 fallback support status available");


   --  Pass 141 regression guard: known_hosts hashed selector matching must
   --  use the shared SHA-1/HMAC-SHA1 primitives introduced for packet MACs,
   --  rather than carrying a second local SHA-1 implementation that can
   --  diverge from the tested crypto boundary.
   Require_Text
     ("src/ssh_lib-known_hosts.adb",
      "with CryptoLib.Hashes;");
   Require_Text
     ("src/ssh_lib-known_hosts.adb",
      "with CryptoLib.Macs;");
   Require_Text
     ("src/ssh_lib-known_hosts.adb",
      "CryptoLib.Macs.HMAC_SHA1");
   Require_Absent_Text
     ("src/ssh_lib-known_hosts.adb",
      "subtype SHA1_Digest_Index");
   Require_Absent_Text
     ("src/ssh_lib-known_hosts.adb",
      "type SHA1_Digest is array");
   Require_Absent_Text
     ("src/ssh_lib-known_hosts.adb",
      "function HMAC_SHA1");

   --  Pass 137 regression guard: live protected packet streaming reads must
   --  mark the protected state dirty when the decoded packet length is invalid.
   --  This is important for EtM because the clear length is authenticated only
   --  after the remainder of the packet is read; malformed lengths must leave
   --  the connection fail-closed rather than reusable.
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "SSH_Lib.Protocol.Protected_Packets.Mark_Dirty");
   Require_Text
     ("src/ssh_lib-sessions-live_transcript.adb",
      "(Item.Protected_State, Handshake_Failed);");


   --  Pass 150 regression guard: encrypted PKCS#8 PBES2/PBKDF2
   --  support must not regress to only SHA-1/SHA-256 PRFs.  OpenSSL and
   --  other key generators may emit hmacWithSHA512 AlgorithmIdentifier
   --  values, so the bounded AES-CBC encrypted-key path must route SHA-512
   --  through the shared HMAC implementation instead of failing closed.
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "PBKDF2_HMAC_SHA512");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "HMAC_SHA512_OID");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "CryptoLib.Macs.HMAC_SHA512");
   Require_Text
     ("docs/RUNTIME_BOUNDARIES.md",
      "PBKDF2-HMAC-SHA1, HMAC-SHA256, or HMAC-SHA512");
   Require_Absent_Text
     ("README.md",
      "encrypted PKCS#8 and encrypted legacy PEM files remain explicitly unsupported");
   Require_Absent_Text
     ("docs/RUNTIME_BOUNDARIES.md",
      "Encrypted PKCS#8 remains explicitly unsupported");


   --  Pass 151 regression guard: OpenSSH bcrypt-encrypted identity files
   --  must support both CTR and CBC AES private-section ciphers.
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Is_OpenSSH_CBC_Cipher");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Decrypt_CBC_Raw");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Cipher_Name = ""aes256-ctr"" or else Cipher_Name = ""aes256-cbc""");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "Padding_Limit");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "full AES block padding range");
   Require_Text
     ("docs/RUNTIME_BOUNDARIES.md",
      "AES-CTR or AES-CBC private-section unwrap");



   --  Pass 152 regression guard: documentation and malformed-input tests must
   --  distinguish supported encrypted identity-file envelopes from malformed
   --  or unsupported encrypted cases.  The current implementation supports
   --  explicit non-retained passphrases for OpenSSH bcrypt keys, traditional
   --  AES-CBC legacy PEM RSA keys, and PBES2/PBKDF2 AES-CBC PKCS#8 RSA keys;
   --  stale blanket "encrypted keys unsupported" wording would mislead
   --  downstream Version integration work.
   Require_Text
     ("README.md",
      "supported encrypted OpenSSH bcrypt, legacy AES-CBC/MD5, and PKCS#8 AES-CBC/PBKDF2 identity files");
   Require_Text
     ("docs/SECURITY.md",
      "supported encrypted OpenSSH, legacy PEM, and PKCS#8 identities use explicit non-retained passphrase input");
   Require_Text
     ("tests/src/fixtures/ssh_lib-tests-fixtures-auth_security.adb",
      "unsupported non-RSA legacy PEM private key rejected");
   Require_Text
     ("tests/src/fixtures/ssh_lib-tests-fixtures-identity_files.ads",
      "Encrypted_Legacy_RSA_AES256_CBC_Private_Key");
   Require_Text
     ("tests/src/fixtures/ssh_lib-tests-fixtures-identity_files.ads",
      "Encrypted_PKCS8_RSA_AES256_CBC_Private_Key");
   Require_Text
     ("tests/src/fixtures/ssh_lib-tests-fixtures-auth_security.adb",
      "encrypted legacy PEM AES-256-CBC fixture parses");
   Require_Text
     ("tests/src/fixtures/ssh_lib-tests-fixtures-auth_security.adb",
      "encrypted PKCS#8 AES-256-CBC fixture parses");
   Require_Absent_Text
     ("README.md",
      "encrypted identity files, unsupported private-key algorithms");
   Require_Absent_Text
     ("docs/SECURITY.md",
      "Unsupported or encrypted keys remain method failures");
   Require_Absent_Text
     ("tests/security/README.md",
      "encrypted/legacy/unsupported identity formats");


   --  Pass 153 regression guard: the top-level README must not regress to
   --  stale pre-callback/pre-ProxyJump status text.  Password callbacks,
   --  identity passphrase callbacks, password-change callbacks, and
   --  SSH-over-SSH ProxyJump direct-tcpip routing are implemented; only
   --  optional TOFU and non-Version SSH feature families remain out of scope;
   --  ProxyCommand is now an explicit subprocess-backed transport boundary.
   Require_Absent_Text
     ("README.md",
      "passphrase callback authentication");
   Require_Absent_Text
     ("README.md",
      "interactive password callback authentication");
   Require_Absent_Text
     ("README.md",
      "ProxyJump / ProxyCommand");
   Require_Text
     ("README.md",
      "explicit subprocess-backed SSH transport");
   Require_Text
     ("README.md",
      "live interoperability proof and full GNAT build proof in this environment");
   Require_Absent_Text
     ("tests/security/README.md",
      "unsupported encrypted envelopes");
   Require_Absent_Text
     ("docs/THREAT_MODEL.md",
      "unsupported encrypted envelopes");
   Require_Absent_Text
     ("docs/SECURITY_REVIEW.md",
      "unsupported encrypted-envelope");


   --  Pass 155 regression guard: callback-capable security documentation
   --  must not regress to the older wording that listed password or
   --  passphrase callbacks as absent.  The implemented callbacks are
   --  deliberately non-retaining; explicit credential prompting and storage
   --  remain caller-invoked rather than automatic session-open behavior.
   Require_Absent_Text
     ("docs/SECURITY.md",
      "does not implement interactive password callbacks");
   Require_Absent_Text
     ("docs/SECURITY.md",
      "passphrase callbacks, ProxyCommand");
   Require_Absent_Text
     ("docs/SECURITY_REVIEW.md",
      "does not implement passphrase callbacks");
   Require_Absent_Text
     ("docs/SECURITY_REVIEW.md",
      "interactive password callbacks, ProxyCommand");
   Require_Absent_Text
     ("docs/THREAT_MODEL.md",
      "interactive password callbacks, or passphrase callbacks");
   Require_Text
     ("docs/SECURITY.md",
      "supports non-interactive password, identity-passphrase, and password-change callbacks");
   Require_Text
     ("docs/SECURITY_REVIEW.md",
      "Non-interactive password, identity-passphrase, and password-change callbacks are implemented");
   Require_Text
     ("docs/THREAT_MODEL.md",
      "callbacks are implemented without retaining returned secrets");


   --  Pass 157 regression guard: RSA publickey userauth must not be locked
   --  to rsa-sha2-512 only.  Some modern servers and agents accept RSA keys
   --  only with rsa-sha2-256; the identity-file and agent live paths now try
   --  rsa-sha2-512 first and then rsa-sha2-256 before falling back to the
   --  next authentication method.
   Require_Text
     ("src/ssh_lib-sessions-live_userauth.adb",
      "Userauth_Algorithm_For_Attempt");
   Require_Text
     ("src/ssh_lib-sessions-live_userauth.adb",
      "return ""rsa-sha2-256"";");
   Require_Text
     ("src/ssh_lib-protocol-userauth-identity.ads",
      "Public_Key_Algorithm : String");
   Require_Text
     ("tests/src/fixtures/ssh_lib-tests-fixtures-auth_security.adb",
      "RSA identity can build rsa-sha2-256 userauth request");
   Require_Text
     ("docs/SECURITY_REVIEW.md",
      "rsa-sha2-512 first and then rsa-sha2-256");


   --  Pass 158 regression guard: public algorithm status documentation must
   --  match the implemented HMAC-SHA1 interoperability fallback list.  The
   --  SHA-1 MACs remain lowest-priority fallbacks, but they are real packet
   --  MAC implementations and must not disappear from public coverage notes.
   Require_Text
     ("docs/SECURITY_REVIEW.md",
      "hmac-sha2-512,hmac-sha2-256,hmac-sha1-etm@openssh.com,hmac-sha1");
   Require_Text
     ("docs/TESTING.md",
      "hmac-sha2-512,hmac-sha2-256,hmac-sha1-etm@openssh.com,hmac-sha1");
   Require_Text
     ("docs/THREAT_MODEL.md",
      "hmac-sha2-512,hmac-sha2-256,hmac-sha1-etm@openssh.com,hmac-sha1");
   Require_Text
     ("tests/security/README.md",
      "hmac-sha2-512,hmac-sha2-256,hmac-sha1-etm@openssh.com,hmac-sha1");
   Require_Absent_Text
     ("docs/SECURITY_REVIEW.md",
      "hmac-sha2-512,hmac-sha2-256`, and `none` compression");
   Require_Absent_Text
     ("docs/TESTING.md",
      "hmac-sha2-512,hmac-sha2-256`, and `none` compression");
   Require_Absent_Text
     ("docs/THREAT_MODEL.md",
      "hmac-sha2-512,hmac-sha2-256`, and `none` compression");
   Require_Absent_Text
     ("tests/security/README.md",
      "hmac-sha2-512,hmac-sha2-256`, and `none` compression");


   --  Pass 160 regression guard: SSH compression is intentionally wired only
   --  after the Ada zlib dependency is present.  Advertising zlib must remain
   --  tied to real protected-packet payload compression/decompression, not just
   --  a KEXINIT name-list edit.
   Require_Text
     ("alire.toml",
      "zlib = ""*""");
   Require_Text
     ("SSH_Lib.gpr",
      "with ""zlib"";");
   Require_Text
     ("src/ssh_lib-algorithms.adb",
      "return ""zlib@openssh.com,zlib,none"";");
   Require_Text
     ("src/ssh_lib-protocol-protected_packets.adb",
      "Configure_Compression");
   Require_Text
     ("src/ssh_lib-protocol-protected_packets.adb",
      "Compress_Payload");
   Require_Text
     ("src/ssh_lib-protocol-protected_packets.adb",
      "Decompress_Payload");
   Require_Text
     ("src/ssh_lib-protocol-protected_packets.adb",
      "Activate_Delayed_Compression");
   Require_Text
     ("src/ssh_lib-sessions-live_userauth.adb",
      "Activate_Post_Auth_Compression");
   Require_Text
     ("src/ssh_lib-algorithms.adb",
      "zlib@openssh.com");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "Compression_Client_To_Server");
   Require_Absent_Text
     ("docs/SECURITY_REVIEW.md",
      "and `none` compression");
   Require_Absent_Text
     ("docs/TESTING.md",
      "and `none` compression");


   --  Pass 162 regression guard: broadened transport cipher coverage must be
   --  real AES-CBC packet encryption/decryption support, not only a KEXINIT
   --  advertisement change.  CBC remains lower priority than CTR.
   Require_Text
     ("src/ssh_lib-algorithms.adb",
      "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc");
   Require_Text
     ("../cryptolib/src/cryptolib-ciphers.ads",
      "type Cipher_Mode is (CTR_Mode, CBC_Mode)");
   Require_Text
     ("../cryptolib/src/cryptolib-ciphers.adb",
      "Apply_CBC_Encrypt");
   Require_Text
     ("../cryptolib/src/cryptolib-ciphers.adb",
      "Apply_CBC_Decrypt");
   Require_Text
     ("tests/src/fixtures/ssh_lib-tests-fixtures-crypto_primitives.adb",
      "AES-128-CBC known-vector ciphertext matches NIST SP 800-38A F.2.1");
   Require_Text
     ("docs/SECURITY_REVIEW.md",
      "AES-CTR and AES-CBC transport cipher support");


   --  Pass 166 regression guard: ssh-rsa/RSA-SHA1 is a deliberately
   --  lowest-priority interoperability fallback, not a documentation-only
   --  advertisement.  It must be advertised, parsed, verified, and usable for
   --  identity-file/agent request construction only after RSA SHA-2 variants.
   Require_Text
     ("src/ssh_lib-algorithms.adb",
      "ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa");
   Require_Text
     ("src/ssh_lib-rsa.ads",
      "function Verify_SHA1");
   Require_Text
     ("src/ssh_lib-rsa.ads",
      "function Sign_SHA1");
   Require_Text
     ("src/ssh_lib-sessions-live_userauth.adb",
      "return ""ssh-rsa"";");
   Require_Text
     ("src/ssh_lib-agent-protocol.adb",
      "or else Public_Key_Algorithm = ""ssh-rsa""");
   Require_Text
     ("tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.adb",
      "legacy ssh-rsa SHA-1 host-key signatures retained as last-resort interoperability fallback");
   Require_Text
     ("README.md",
      "ssh-rsa`/RSA-SHA1 as a deliberately lowest-priority interoperability fallback");
   Require_Text
     ("README.md",
      "optional algorithm coverage is now broad; remaining gaps are live interoperability/build validation, not intentionally unadvertised core algorithm families");
   Require_Absent_Text
     ("README.md",
      "SSH algorithms outside the Version transport set");


   --  Pass 164 regression guard: public runtime status must not regress to
   --  stale pre-channel-publication or broad algorithm-gap wording.  The
   --  remaining algorithm gaps are now specific optional families; implemented
   --  cipher/MAC/compression/KEX families must be documented as wired, not as
   --  blanket fail-closed gaps.
   Require_Text
     ("README.md",
      "Implemented algorithm families now include Curve25519, group-exchange SHA-256/SHA-1, group18/group16 SHA-512, group14 SHA-256/SHA-1, RSA SHA-2/SHA-1 and Ed25519 host keys, chacha20-poly1305 AEAD and AES-GCM/AES-CTR/AES-CBC transport ciphers, SHA-2/SHA-1 MACs including SHA1-96 fallbacks, and zlib/zlib@openssh.com compression.");
   Require_Text
     ("docs/SECURITY_REVIEW.md",
      "Non-fixture hosts now proceed through live SSH identification, cleartext KEXINIT packet exchange, negotiated key exchange, NEWKEYS, protected-packet installation, host-key signature verification, known-host trust, protected userauth, and retained channel setup.");
   Require_Text
     ("docs/THREAT_MODEL.md",
      "the remaining runtime risk is real-server validation coverage for both the caller-driven and optional background-reader channel paths.");
   Require_Absent_Text
     ("README.md",
      "broader optional algorithm coverage remains intentionally fail-closed");
   Require_Absent_Text
     ("docs/SECURITY_REVIEW.md",
      "fails closed after key exchange and NEWKEYS");
   Require_Absent_Text
     ("docs/THREAT_MODEL.md",
      "channel publication and broader key/signature interoperability");


   --  Pass 169 regression guard: runtime-boundary and public docs must track
   --  the implemented group16 SHA-512 live finite-field KEX path instead of
   --  stale group14-only wording.
   Require_Text
     ("README.md",
      "live Curve25519, group-exchange SHA-256/SHA-1, group18/group16 SHA-512, or group14 key exchange");
   Require_Text
     ("README.md",
      "supported finite-field DH paths: `diffie-hellman-group-exchange-sha256`, `diffie-hellman-group-exchange-sha1`, `diffie-hellman-group18-sha512`, `diffie-hellman-group16-sha512`, `diffie-hellman-group14-sha256`, and `diffie-hellman-group14-sha1`");
   Require_Text
     ("docs/RUNTIME_BOUNDARIES.md",
      "group-exchange-selected group18/group16/group14 and fixed group18/group16/group14 shared-secret computation, SHA-512/SHA-256/SHA-1 exchange-hash computation selected by the negotiated KEX name");
   Require_Text
     ("docs/SECURITY_REVIEW.md",
      "group18/group16 SHA-512 finite-field KEX coverage");
   Require_Text
     ("docs/TESTING.md",
      "group18/group16 KEX selection/runtime guards");
   Require_Absent_Text
     ("README.md",
      "live Curve25519 or group14 key exchange");
   Require_Absent_Text
     ("docs/RUNTIME_BOUNDARIES.md",
      "group14 shared-secret computation, SHA-256 exchange-hash computation");


   --  Pass 165 regression guard: runtime-boundary documentation must track
   --  the implemented AES-CBC transport and encrypted identity-file support,
   --  rather than older CTR-only / encrypted-key-fail-closed wording.
   Require_Text
     ("docs/RUNTIME_BOUNDARIES.md",
      "CBC chaining state is updated per protected packet");
   Require_Text
     ("docs/RUNTIME_BOUNDARIES.md",
      "bcrypt-encrypted OpenSSH private keys, traditional AES/DES/3DES-CBC encrypted RSA PEM, and PBES2/PBKDF2 AES/3DES-CBC encrypted PKCS#8 RSA");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "DES-EDE3-CBC");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "DES-CBC");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "des-EDE3-CBC");
   Require_Text
     ("src/ssh_lib-identity_files.adb",
      "3des-cbc");
   Require_Text
     ("../cryptolib/src/cryptolib-ciphers.adb",
      "Algorithm_Name = ""des-cbc"" or else Algorithm_Name = ""3des-cbc""");
   Require_Text
     ("tests/src/fixtures/ssh_lib-tests-fixtures-crypto_primitives.adb",
      "3DES-CBC raw decrypt restores OpenSSL known-vector plaintext");
   Require_Absent_Text
     ("docs/RUNTIME_BOUNDARIES.md",
      "The cipher package implements `aes256-ctr`, `aes192-ctr`, and `aes128-ctr` for live transport and rejects unsupported or legacy transport cipher names");
   Require_Absent_Text
     ("docs/RUNTIME_BOUNDARIES.md",
      "Unsupported and encrypted key shapes continue to fail closed");




   --  Pass 170 regression guard: group18 SHA-512 KEX must be fully wired,
   --  not merely documented or advertised.
   Require_Text
     ("src/ssh_lib-algorithms.adb",
      "diffie-hellman-group18-sha512");
   Require_Text
     ("../cryptolib/src/cryptolib-diffie_hellman.ads",
      "Generate_Group18_Keypair");
   Require_Text
     ("../cryptolib/src/cryptolib-diffie_hellman.ads",
      "Compute_Group18_Shared_Secret");
   Require_Text
     ("src/ssh_lib-protocol-exchange_hash.ads",
      "Compute_Group18_SHA512");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "CryptoLib.Diffie_Hellman.Generate_Group18_Keypair");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "CryptoLib.Diffie_Hellman.Compute_Group18_Shared_Secret");
   Require_Text
     ("src/ssh_lib-sessions-live_transport.adb",
      "SSH_Lib.Protocol.Exchange_Hash.Compute_Group18_SHA512");
   Require_Text
     ("tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.adb",
      "implemented group18 SHA-512 KEX intersects successfully");
   Require_Absent_Text
     ("README.md",
      "group18/group-exchange KEX");



   Require_Text ("../cryptolib/src/cryptolib-chacha20_poly1305.adb", "procedure Quarter_Round");
   Require_Text ("../cryptolib/src/cryptolib-chacha20_poly1305.adb", "function Poly1305_Tag");
   Require_Text ("src/ssh_lib-protocol-protected_packets.adb", "Item.Outbound_Chacha20_Poly1305");
   Require_Text ("src/ssh_lib-protocol-protected_packets.adb", "if Outbound_Cipher_Name = ""chacha20-poly1305@openssh.com"" then");
   Require_Text ("src/ssh_lib-protocol-protected_packets.adb", "if Inbound_Cipher_Name = ""chacha20-poly1305@openssh.com"" then");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.adb", "mixed outbound chacha20-poly1305 and inbound AES-CTR protected state initializes");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.adb", "mixed outbound AES-CTR and inbound chacha20-poly1305 protected state initializes");
   Require_Absent_Text ("src/ssh_lib-protocol-protected_packets.adb", "Outbound_Cipher_Name /= ""chacha20-poly1305@openssh.com""");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "chacha20-poly1305@openssh.com");


   --  Pass 173 regression guard: AES-GCM must be a real AEAD transport
   --  cipher path, not a name-list-only advertisement.
   Require_Text ("src/ssh_lib-algorithms.adb", "aes256-gcm@openssh.com");
   Require_Text ("../cryptolib/src/cryptolib-ciphers.ads", "function Seal_GCM");
   Require_Text ("../cryptolib/src/cryptolib-ciphers.adb", "function GHASH_Multiply");
   Require_Text ("../cryptolib/src/cryptolib-ciphers.adb", "function Open_GCM");
   Require_Text ("src/ssh_lib-protocol-protected_packets.adb", "Item.Outbound_AES_GCM");
   Require_Text ("src/ssh_lib-protocol-protected_packets.adb", "CryptoLib.Ciphers.Seal_GCM");
   Require_Text ("src/ssh_lib-protocol-protected_packets.adb", "CryptoLib.Ciphers.Open_GCM");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "aes256-gcm@openssh.com");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.adb", "AES-GCM protected state initializes in both directions");
   Require_Absent_Text ("README.md", "AES-GCM, group-exchange KEX, and OpenSSH certificate validation");



   --  Pass 174 regression guard: OpenSSH host certificates must be real
   --  certificate validation, not advertisement-only names.  CA trust flows
   --  through @cert-authority known_hosts records and certificate parsing.
   Require_Text
     ("src/ssh_lib-protocol-certificates.adb",
      "function Validate_Host_Certificate");
   Require_Text
     ("src/ssh_lib-known_hosts.adb",
      "Parsed_Record_Cert_Authority");
   Require_Text
     ("src/ssh_lib-protocol-host_keys.adb",
      "Parse_Host_Certificate");
   Require_Text
     ("src/ssh_lib-algorithms.adb",
      "ssh-ed25519-cert-v01@openssh.com");
   Require_Text
     ("README.md",
      "Pass 174 adds OpenSSH host-certificate validation");
   Require_Absent_Text
     ("README.md",
      "OpenSSH certificate validation` remains not implemented");

   --  Pass 175 regression guard: group-exchange SHA-256/SHA-1 KEX must be
   --  advertised and routed through the real RFC 4419 request/group/init/reply
   --  exchange-hash path, not left as a fail-closed optional gap.
   Require_Text ("src/ssh_lib-algorithms.adb", "diffie-hellman-group-exchange-sha256");
   Require_Text ("src/ssh_lib-protocol-kexdh.ads", "SSH_MSG_KEX_DH_GEX_REQUEST");
   Require_Text ("src/ssh_lib-protocol-kexdh.ads", "Parse_Group_Exchange_Group");
   Require_Text ("src/ssh_lib-protocol-exchange_hash.ads", "Compute_Group_Exchange_SHA256");
   Require_Text ("../cryptolib/src/cryptolib-diffie_hellman.ads", "Select_Group_Exchange_Group");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "Encode_Group_Exchange_Request");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "Parse_Group_Exchange_Reply");
   Require_Absent_Text ("README.md", "optional algorithm family not yet implemented: group-exchange KEX");

   --  Pass 179 regression guard: RFC 4419 group-exchange request bounds
   --  must be public session options, not hard-coded live-transport constants.
   Require_Text ("src/ssh_lib-sessions.ads", "Gex_Minimum_Bits");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "Item.Stored_Options.Gex_Minimum_Bits");
   Require_Text ("README.md", "Session_Options.Gex_Minimum_Bits");

   --  Pass 176 regression guard: legacy RFC 4419 SHA-1 group-exchange
   --  remains a low-priority compatibility fallback, but must be routed
   --  through the same real GEX packet flow and SHA-1 exchange hash path.
   Require_Text ("src/ssh_lib-algorithms.adb", "diffie-hellman-group-exchange-sha1");
   Require_Text ("src/ssh_lib-protocol-exchange_hash.ads", "Compute_Group_Exchange_SHA1");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "Compute_Group_Exchange_SHA1");
   Require_Text ("src/ssh_lib-sessions-live_transport.adb", "Derive_SHA1_Keys");
   Require_Text ("tests/src/fixtures/ssh_lib-tests-fixtures-algorithm_security.adb", "legacy GEX SHA-1 KEX intersects successfully");



   --  Pass 180 regression guard: live runtime documentation must not
   --  regress to stale pass-20-era wording that public-network sessions stop
   --  before known-host trust or production userauth.  The live transcript now
   --  carries KEX, protected packets, host-key/certificate validation,
   --  protected userauth, and retained channel setup; Ok remains gated on all
   --  checks rather than impossible after KEX.
   Require_Text ("docs/SECURITY.md", "strict host-key verification, known-host or certificate-authority trust, protected userauth, and retained channel setup");
   Require_Text ("docs/SECURITY_REVIEW.md", "complete socket-backed open boundary: identification, KEXINIT, negotiated KEX including group-exchange, NEWKEYS, protected packet installation");
   Require_Text ("docs/TESTING.md", "public `Ok` remains impossible unless the complete connected/encrypted/trusted/authenticated gate set is satisfied");
   Require_Text ("docs/THREAT_MODEL.md", "public-network path uses the same live encrypted transcript boundary instead of a fixture-only userauth shortcut");
   Require_Text ("README.md", "public-network path now uses the live socket-backed transcript for protected userauth as well");
   Require_Absent_Text ("docs/SECURITY.md", "Public success is still fail-closed until known-host trust and production userauth are connected");
   Require_Absent_Text ("docs/SECURITY_REVIEW.md", "Public success is still fail-closed until known-host trust and production userauth are connected");
   Require_Absent_Text ("docs/TESTING.md", "Public success is still fail-closed until known-host trust and production userauth are connected");
   Require_Absent_Text ("docs/THREAT_MODEL.md", "ordinary public-network transcript I/O remains fail-closed until connected to live encrypted sockets");
   Require_Absent_Text ("README.md", "arbitrary public-network SSH remains fail-closed until the live transcript driver is connected");

   --  Pass 177 regression guard: explicit known_hosts append support must
   --  exist without reintroducing silent TOFU in Sessions.Open.
   Require_Text ("src/ssh_lib-known_hosts.ads", "function Append_Trusted_Host");
   Require_Text ("src/ssh_lib-known_hosts.adb", "This helper is deliberately explicit");
   Require_Text ("README.md", "Append_Trusted_Host");
   Require_Absent_Text ("README.md", "optional TOFU/add-known-host workflow");
   Require_Absent_Text ("docs/SECURITY.md", "TOFU/add-known-host workflow");

   Scan_Ada_Tree ("src");
   Scan_Ada_Tree ("tests");
   Scan_Ada_Tree ("examples");
   Scan_Ada_Tree ("tools");


   --  Pass 181 regression guard: optional background channel reader must stay
   --  wired as a real channel task path, not just documentation.
   Require_Text
     ("src/ssh_lib-channels.ads",
      "function Start_Background_Reader");
   Require_Text
     ("src/ssh_lib-channels.ads",
      "function Stop_Background_Reader");
   Require_Text
     ("src/ssh_lib-sessions.ads",
      "Enable_Background_Channel_Reader : Boolean := False");
   Require_Text
     ("src/ssh_lib-channels.adb",
      "task body Background_Reader is");
   Require_Text
     ("src/ssh_lib-channels.adb",
      "Background_Drain_One");
   Require_Absent_Text
     ("README.md",
      "no background reader task is introduced");

   if Failure_Count = 0 then
      Ada.Text_IO.Put_Line ("compile preflight guard passed");
   else
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Check_Compile_Preflight;
