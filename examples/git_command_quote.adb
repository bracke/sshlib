with Ada.Text_IO;
with SSH_Lib.Git;

procedure Git_Command_Quote is
begin
   Ada.Text_IO.Put_Line
     (SSH_Lib.Git.Upload_Pack_Command ("group/repo.git"));
   Ada.Text_IO.Put_Line
     (SSH_Lib.Git.Receive_Pack_Command ("repo with space.git"));
   Ada.Text_IO.Put_Line
     (SSH_Lib.Git.Upload_Pack_Command ("repo'with'quotes.git"));
end Git_Command_Quote;
