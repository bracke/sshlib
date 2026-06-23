package body SSH_Lib.Diagnostics.Redaction is
   function Decimal_Image (Value : Natural) return String is
      Raw_Text : constant String := Natural'Image (Value);
   begin
      if Raw_Text'Length > 0 and then Raw_Text (Raw_Text'First) = ' ' then
         return Raw_Text (Raw_Text'First + 1 .. Raw_Text'Last);
      else
         return Raw_Text;
      end if;
   end Decimal_Image;

   function Bytes_Redacted
     (Data : Ada.Streams.Stream_Element_Array)
      return String
   is
   begin
      return "<redacted " & Decimal_Image (Data'Length) & " bytes>";
   end Bytes_Redacted;

   function Secret_Redacted return String is
   begin
      return "<redacted>";
   end Secret_Redacted;

   function Text_Redacted (Label_Text : String) return String is
      pragma Unreferenced (Label_Text);
   begin
      return "<redacted>";
   end Text_Redacted;
end SSH_Lib.Diagnostics.Redaction;
