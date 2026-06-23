package body SSH_Lib.Diagnostics.Safe_Trace is
   function Decimal_Image (Value : Natural) return String is
      Raw : constant String := Natural'Image (Value);
   begin
      if Raw'Length > 0 and then Raw (Raw'First) = ' ' then
         return Raw (Raw'First + 1 .. Raw'Last);
      else
         return Raw;
      end if;
   end Decimal_Image;

   function Status_Label
     (Value : CryptoLib.Errors.Status)
      return String
   is
      Raw : constant String := CryptoLib.Errors.Status'Image (Value);
   begin
      return Raw;
   exception
      when others =>
         return "INTERNAL_ERROR";
   end Status_Label;

   function Redacted_Bytes_Label
     (Data : Ada.Streams.Stream_Element_Array)
      return String
   is
   begin
      return "<redacted " & Decimal_Image (Data'Length) & " bytes>";
   exception
      when others =>
         return "<redacted bytes>";
   end Redacted_Bytes_Label;

   function Secret_Label return String is
   begin
      return "<secret redacted>";
   end Secret_Label;
end SSH_Lib.Diagnostics.Safe_Trace;
