with CryptoLib.Hashes;
with CryptoLib.Macs;
with SSH_Lib.Protocol.Numbers;

package body SSH_Lib.ECDSA is

   use Ada.Streams;
   use CryptoLib.Errors;

   subtype Word_Index is Natural range 0 .. 31;
   type UInt256 is array (Word_Index) of Natural range 0 .. 255;

   Zero_Value  : constant UInt256 := [others => 0];
   One_Value   : constant UInt256 := [0 .. 30 => 0, 31 => 1];
   Three_Value : constant UInt256 := [0 .. 30 => 0, 31 => 3];

   P_Value : constant UInt256 :=
     [16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#00#,
      16#00#,
      16#00#,
      16#01#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#];

   N_Value : constant UInt256 :=
     [16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#00#,
      16#00#,
      16#00#,
      16#00#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#BC#,
      16#E6#,
      16#FA#,
      16#AD#,
      16#A7#,
      16#17#,
      16#9E#,
      16#84#,
      16#F3#,
      16#B9#,
      16#CA#,
      16#C2#,
      16#FC#,
      16#63#,
      16#25#,
      16#51#];

   Half_N_Value : constant UInt256 :=
     [16#7F#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#80#,
      16#00#,
      16#00#,
      16#00#,
      16#7F#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#FF#,
      16#DE#,
      16#73#,
      16#7D#,
      16#56#,
      16#D3#,
      16#8B#,
      16#CF#,
      16#42#,
      16#79#,
      16#DC#,
      16#E5#,
      16#61#,
      16#7E#,
      16#31#,
      16#92#,
      16#A8#];

   B_Value : constant UInt256 :=
     [16#5A#,
      16#C6#,
      16#35#,
      16#D8#,
      16#AA#,
      16#3A#,
      16#93#,
      16#E7#,
      16#B3#,
      16#EB#,
      16#BD#,
      16#55#,
      16#76#,
      16#98#,
      16#86#,
      16#BC#,
      16#65#,
      16#1D#,
      16#06#,
      16#B0#,
      16#CC#,
      16#53#,
      16#B0#,
      16#F6#,
      16#3B#,
      16#CE#,
      16#3C#,
      16#3E#,
      16#27#,
      16#D2#,
      16#60#,
      16#4B#];

   G_X : constant UInt256 :=
     [16#6B#,
      16#17#,
      16#D1#,
      16#F2#,
      16#E1#,
      16#2C#,
      16#42#,
      16#47#,
      16#F8#,
      16#BC#,
      16#E6#,
      16#E5#,
      16#63#,
      16#A4#,
      16#40#,
      16#F2#,
      16#77#,
      16#03#,
      16#7D#,
      16#81#,
      16#2D#,
      16#EB#,
      16#33#,
      16#A0#,
      16#F4#,
      16#A1#,
      16#39#,
      16#45#,
      16#D8#,
      16#98#,
      16#C2#,
      16#96#];

   G_Y : constant UInt256 :=
     [16#4F#,
      16#E3#,
      16#42#,
      16#E2#,
      16#FE#,
      16#1A#,
      16#7F#,
      16#9B#,
      16#8E#,
      16#E7#,
      16#EB#,
      16#4A#,
      16#7C#,
      16#0F#,
      16#9E#,
      16#16#,
      16#2B#,
      16#CE#,
      16#33#,
      16#57#,
      16#6B#,
      16#31#,
      16#5E#,
      16#CE#,
      16#CB#,
      16#B6#,
      16#40#,
      16#68#,
      16#37#,
      16#BF#,
      16#51#,
      16#F5#];

   type Point is record
      Infinity : Boolean := True;
      X_Value  : UInt256 := Zero_Value;
      Y_Value  : UInt256 := Zero_Value;
   end record;

   type Jacobian_Point is record
      Infinity : Boolean := True;
      X_Value  : UInt256 := Zero_Value;
      Y_Value  : UInt256 := Zero_Value;
      Z_Value  : UInt256 := Zero_Value;
   end record;

   function Equal_Text
     (Data : Stream_Element_Array; Text : String) return Boolean
   is
      Text_Index : Natural := Text'First;
   begin
      if Data'Length /= Text'Length then
         return False;
      end if;
      for Data_Index in Data'Range loop
         if Natural (Data (Data_Index)) /= Character'Pos (Text (Text_Index))
         then
            return False;
         end if;
         Text_Index := Text_Index + 1;
      end loop;
      return True;
   end Equal_Text;

   function Compare (Left_Item, Right_Item : UInt256) return Integer is
   begin
      for Index_Value in Word_Index loop
         if Left_Item (Index_Value) < Right_Item (Index_Value) then
            return -1;
         elsif Left_Item (Index_Value) > Right_Item (Index_Value) then
            return 1;
         end if;
      end loop;
      return 0;
   end Compare;

   function Is_Zero (Item : UInt256) return Boolean is
   begin
      return Compare (Item, Zero_Value) = 0;
   end Is_Zero;

   function Is_In_Range_1_To_Modulus_Minus_1
     (Item : UInt256; Modulus_Item : UInt256) return Boolean is
   begin
      return (not Is_Zero (Item)) and then Compare (Item, Modulus_Item) < 0;
   end Is_In_Range_1_To_Modulus_Minus_1;

   function Is_In_Range_0_To_Modulus_Minus_1
     (Item : UInt256; Modulus_Item : UInt256) return Boolean is
   begin
      return Compare (Item, Modulus_Item) < 0;
   end Is_In_Range_0_To_Modulus_Minus_1;

   procedure Subtract_In_Place
     (Left_Item : in out UInt256; Right_Item : UInt256)
   is
      Borrow_Value : Integer := 0;
      Diff_Value   : Integer;
   begin
      for Index_Value in reverse Word_Index loop
         Diff_Value :=
           Left_Item (Index_Value) - Right_Item (Index_Value) - Borrow_Value;
         if Diff_Value < 0 then
            Diff_Value := Diff_Value + 256;
            Borrow_Value := 1;
         else
            Borrow_Value := 0;
         end if;
         Left_Item (Index_Value) := Diff_Value;
      end loop;
   end Subtract_In_Place;

   procedure Add_Wrap
     (Left_Item    : UInt256;
      Right_Item   : UInt256;
      Result_Value : out UInt256;
      Carry_Value  : out Natural)
   is
      Sum_Value : Natural;
   begin
      Carry_Value := 0;
      Result_Value := Zero_Value;
      for Index_Value in reverse Word_Index loop
         Sum_Value :=
           Left_Item (Index_Value) + Right_Item (Index_Value) + Carry_Value;
         Result_Value (Index_Value) := Sum_Value mod 256;
         Carry_Value := Sum_Value / 256;
      end loop;
   end Add_Wrap;

   function Add_Mod
     (Left_Item : UInt256; Right_Item : UInt256; Modulus_Item : UInt256)
      return UInt256
   is
      Result_Value     : UInt256 := Zero_Value;
      Carry_Value      : Natural := 0;
      Correction_Value : UInt256 := Zero_Value;
      Correction_Carry : Natural := 0;
   begin
      Add_Wrap (Left_Item, Right_Item, Result_Value, Carry_Value);
      if Carry_Value /= 0 then
         --  Fold the carry bit back modulo Modulus: 2**256 is congruent to
         --  2**256 - Modulus.  The correction is small for the NIST P-256
         --  field and order, but compute it generically as a wrapped value.
         Correction_Value := Zero_Value;
         Subtract_In_Place (Correction_Value, Modulus_Item);
         declare
            Corrected_Value : UInt256 := Zero_Value;
         begin
            Add_Wrap
              (Result_Value,
               Correction_Value,
               Corrected_Value,
               Correction_Carry);
            Result_Value := Corrected_Value;
         end;
      end if;
      if Correction_Carry /= 0
        or else Compare (Result_Value, Modulus_Item) >= 0
      then
         Subtract_In_Place (Result_Value, Modulus_Item);
      end if;
      return Result_Value;
   end Add_Mod;

   function Sub_Mod
     (Left_Item : UInt256; Right_Item : UInt256; Modulus_Item : UInt256)
      return UInt256
   is
      Result_Value : UInt256 := Left_Item;
      Delta_Value  : UInt256 := Right_Item;
   begin
      if Compare (Left_Item, Right_Item) >= 0 then
         Subtract_In_Place (Result_Value, Right_Item);
         return Result_Value;
      end if;

      --  Compute Left - Right mod Modulus as Modulus - (Right - Left),
      --  avoiding an overflowing Left + Modulus intermediate.
      Subtract_In_Place (Delta_Value, Left_Item);
      Result_Value := Modulus_Item;
      Subtract_In_Place (Result_Value, Delta_Value);
      if Compare (Result_Value, Modulus_Item) >= 0 then
         Subtract_In_Place (Result_Value, Modulus_Item);
      end if;
      return Result_Value;
   end Sub_Mod;

   function Double_Mod (Item : UInt256; Modulus_Item : UInt256) return UInt256
   is
   begin
      return Add_Mod (Item, Item, Modulus_Item);
   end Double_Mod;

   function Get_Bit_Value (Item : UInt256; Bit_Index : Natural) return Natural
   is
      Byte_Index : constant Natural := Bit_Index / 8;
      Bit_Offset : constant Natural := 7 - (Bit_Index mod 8);
   begin
      return (Item (Byte_Index) / (2 ** Bit_Offset)) mod 2;
   end Get_Bit_Value;

   function Select_UInt256
     (False_Item : UInt256; True_Item : UInt256; Choice : Natural)
      return UInt256
   is
      Choice_Value : constant Natural := Choice mod 2;
      Other_Value  : constant Natural := 1 - Choice_Value;
      Result_Value : UInt256 := Zero_Value;
   begin
      for Index_Value in Word_Index loop
         Result_Value (Index_Value) :=
           False_Item (Index_Value) * Other_Value
           + True_Item (Index_Value) * Choice_Value;
      end loop;
      return Result_Value;
   end Select_UInt256;

   function Select_Jacobian_Point
     (False_Item : Jacobian_Point;
      True_Item  : Jacobian_Point;
      Choice     : Natural) return Jacobian_Point
   is
      Choice_Value : constant Natural := Choice mod 2;
   begin
      return
        (Infinity =>
           (if Choice_Value = 0
            then False_Item.Infinity
            else True_Item.Infinity),
         X_Value  =>
           Select_UInt256
             (False_Item.X_Value, True_Item.X_Value, Choice_Value),
         Y_Value  =>
           Select_UInt256
             (False_Item.Y_Value, True_Item.Y_Value, Choice_Value),
         Z_Value  =>
           Select_UInt256
             (False_Item.Z_Value, True_Item.Z_Value, Choice_Value));
   end Select_Jacobian_Point;

   function Reduce_Once_If_At_Least
     (Item : UInt256; Modulus_Item : UInt256) return UInt256
   is
      Candidate_Value : UInt256 := Item;
      Choice_Value    : Natural := 0;
   begin
      --  Bounded reduction for values already known to be below 2*modulus.
      --  This removes the previous data-dependent while loop in ECDSA
      --  verification/signing reductions.
      if Compare (Item, Modulus_Item) >= 0 then
         Subtract_In_Place (Candidate_Value, Modulus_Item);
         Choice_Value := 1;
      end if;
      return Select_UInt256 (Item, Candidate_Value, Choice_Value);
   end Reduce_Once_If_At_Least;

   function Mul_Mod
     (Left_Item : UInt256; Right_Item : UInt256; Modulus_Item : UInt256)
      return UInt256
   is
      Result_Value    : UInt256 := Zero_Value;
      Addend_Value    : UInt256 := Left_Item;
      Candidate_Value : UInt256 := Zero_Value;
      Bit_Value       : Natural;
   begin
      for Bit_Index in reverse 0 .. 255 loop
         Bit_Value := Get_Bit_Value (Right_Item, Bit_Index);
         Candidate_Value := Add_Mod (Result_Value, Addend_Value, Modulus_Item);
         Result_Value :=
           Select_UInt256 (Result_Value, Candidate_Value, Bit_Value);
         Addend_Value := Double_Mod (Addend_Value, Modulus_Item);
      end loop;
      return Result_Value;
   end Mul_Mod;

   function Square_Mod (Item : UInt256; Modulus_Item : UInt256) return UInt256
   is
   begin
      return Mul_Mod (Item, Item, Modulus_Item);
   end Square_Mod;

   function Modulus_Minus_Two (Modulus_Item : UInt256) return UInt256 is
      Result_Value : UInt256 := Modulus_Item;
   begin
      Subtract_In_Place (Result_Value, One_Value);
      Subtract_In_Place (Result_Value, One_Value);
      return Result_Value;
   end Modulus_Minus_Two;

   function Pow_Mod
     (Base_Item : UInt256; Exponent_Item : UInt256; Modulus_Item : UInt256)
      return UInt256
   is
      Result_Value  : UInt256 := One_Value;
      Current_Value : UInt256 := Base_Item;
   begin
      for Bit_Index in reverse 0 .. 255 loop
         declare
            Product_Value : constant UInt256 :=
              Mul_Mod (Result_Value, Current_Value, Modulus_Item);
            Bit_Value     : constant Natural :=
              Get_Bit_Value (Exponent_Item, Bit_Index);
         begin
            Result_Value :=
              Select_UInt256 (Result_Value, Product_Value, Bit_Value);
            Current_Value := Square_Mod (Current_Value, Modulus_Item);
         end;
      end loop;
      return Result_Value;
   end Pow_Mod;

   function Inv_Mod
     (Item : UInt256; Modulus_Item : UInt256; Invertible : out Boolean)
      return UInt256 is
   begin
      Invertible := not Is_Zero (Item);
      if not Invertible then
         return Zero_Value;
      end if;
      return Pow_Mod (Item, Modulus_Minus_Two (Modulus_Item), Modulus_Item);
   end Inv_Mod;

   function Curve_Right (X_Value : UInt256) return UInt256 is
      X2_Value : constant UInt256 := Square_Mod (X_Value, P_Value);
      X3_Value : constant UInt256 := Mul_Mod (X2_Value, X_Value, P_Value);
      Three_X  : constant UInt256 := Mul_Mod (Three_Value, X_Value, P_Value);
   begin
      return Add_Mod (Sub_Mod (X3_Value, Three_X, P_Value), B_Value, P_Value);
   end Curve_Right;

   function On_Curve (Point_Item : Point) return Boolean is
   begin
      if Point_Item.Infinity then
         return False;
      end if;
      return
        Square_Mod (Point_Item.Y_Value, P_Value)
        = Curve_Right (Point_Item.X_Value);
   end On_Curve;

   function Add_Point (Left_Point, Right_Point : Point) return Point is
      Lambda_Value      : UInt256;
      Numerator_Value   : UInt256;
      Denominator_Value : UInt256;
      Inverse_Value     : UInt256;
      Invertible        : Boolean;
      X3_Value          : UInt256;
      Y3_Value          : UInt256;
   begin
      if Left_Point.Infinity then
         return Right_Point;
      elsif Right_Point.Infinity then
         return Left_Point;
      end if;

      if Left_Point.X_Value = Right_Point.X_Value then
         if Add_Mod (Left_Point.Y_Value, Right_Point.Y_Value, P_Value)
           = Zero_Value
         then
            return
              (Infinity => True, X_Value => Zero_Value, Y_Value => Zero_Value);
         end if;

         Numerator_Value :=
           Sub_Mod
             (Mul_Mod
                (Three_Value,
                 Square_Mod (Left_Point.X_Value, P_Value),
                 P_Value),
              Three_Value,
              P_Value);
         Denominator_Value := Double_Mod (Left_Point.Y_Value, P_Value);
      else
         Numerator_Value :=
           Sub_Mod (Right_Point.Y_Value, Left_Point.Y_Value, P_Value);
         Denominator_Value :=
           Sub_Mod (Right_Point.X_Value, Left_Point.X_Value, P_Value);
      end if;

      Inverse_Value := Inv_Mod (Denominator_Value, P_Value, Invertible);
      if not Invertible then
         return
           (Infinity => True, X_Value => Zero_Value, Y_Value => Zero_Value);
      end if;
      Lambda_Value := Mul_Mod (Numerator_Value, Inverse_Value, P_Value);
      X3_Value :=
        Sub_Mod
          (Sub_Mod
             (Square_Mod (Lambda_Value, P_Value), Left_Point.X_Value, P_Value),
           Right_Point.X_Value,
           P_Value);
      Y3_Value :=
        Sub_Mod
          (Mul_Mod
             (Lambda_Value,
              Sub_Mod (Left_Point.X_Value, X3_Value, P_Value),
              P_Value),
           Left_Point.Y_Value,
           P_Value);
      return (Infinity => False, X_Value => X3_Value, Y_Value => Y3_Value);
   end Add_Point;

   function Four_Mod (Item : UInt256; Modulus_Item : UInt256) return UInt256 is
   begin
      return Double_Mod (Double_Mod (Item, Modulus_Item), Modulus_Item);
   end Four_Mod;

   function Eight_Mod (Item : UInt256; Modulus_Item : UInt256) return UInt256
   is
   begin
      return Double_Mod (Four_Mod (Item, Modulus_Item), Modulus_Item);
   end Eight_Mod;

   function Double_Jacobian (Point_Item : Jacobian_Point) return Jacobian_Point
   is
      Delta_Value : UInt256;
      Gamma_Value : UInt256;
      Beta_Value  : UInt256;
      Alpha_Value : UInt256;
      X3_Value    : UInt256;
      Y3_Value    : UInt256;
      Z3_Value    : UInt256;
   begin
      if Point_Item.Infinity or else Is_Zero (Point_Item.Y_Value) then
         return
           (Infinity => True,
            X_Value  => Zero_Value,
            Y_Value  => Zero_Value,
            Z_Value  => Zero_Value);
      end if;

      Delta_Value := Square_Mod (Point_Item.Z_Value, P_Value);
      Gamma_Value := Square_Mod (Point_Item.Y_Value, P_Value);
      Beta_Value := Mul_Mod (Point_Item.X_Value, Gamma_Value, P_Value);
      Alpha_Value :=
        Mul_Mod
          (Three_Value,
           Mul_Mod
             (Sub_Mod (Point_Item.X_Value, Delta_Value, P_Value),
              Add_Mod (Point_Item.X_Value, Delta_Value, P_Value),
              P_Value),
           P_Value);
      X3_Value :=
        Sub_Mod
          (Square_Mod (Alpha_Value, P_Value),
           Eight_Mod (Beta_Value, P_Value),
           P_Value);
      Z3_Value :=
        Sub_Mod
          (Sub_Mod
             (Square_Mod
                (Add_Mod (Point_Item.Y_Value, Point_Item.Z_Value, P_Value),
                 P_Value),
              Gamma_Value,
              P_Value),
           Delta_Value,
           P_Value);
      Y3_Value :=
        Sub_Mod
          (Mul_Mod
             (Alpha_Value,
              Sub_Mod (Four_Mod (Beta_Value, P_Value), X3_Value, P_Value),
              P_Value),
           Eight_Mod (Square_Mod (Gamma_Value, P_Value), P_Value),
           P_Value);
      return
        (Infinity => False,
         X_Value  => X3_Value,
         Y_Value  => Y3_Value,
         Z_Value  => Z3_Value);
   end Double_Jacobian;

   function Add_Jacobian_Affine
     (Left_Point : Jacobian_Point; Right_Point : Point) return Jacobian_Point
   is
      Z1Z1_Value : UInt256;
      U2_Value   : UInt256;
      S2_Value   : UInt256;
      H_Value    : UInt256;
      HH_Value   : UInt256;
      I_Value    : UInt256;
      J_Value    : UInt256;
      R_Value    : UInt256;
      V_Value    : UInt256;
      X3_Value   : UInt256;
      Y3_Value   : UInt256;
      Z3_Value   : UInt256;
   begin
      if Left_Point.Infinity then
         if Right_Point.Infinity then
            return
              (Infinity => True,
               X_Value  => Zero_Value,
               Y_Value  => Zero_Value,
               Z_Value  => Zero_Value);
         end if;
         return
           (Infinity => False,
            X_Value  => Right_Point.X_Value,
            Y_Value  => Right_Point.Y_Value,
            Z_Value  => One_Value);
      elsif Right_Point.Infinity then
         return Left_Point;
      end if;

      Z1Z1_Value := Square_Mod (Left_Point.Z_Value, P_Value);
      U2_Value := Mul_Mod (Right_Point.X_Value, Z1Z1_Value, P_Value);
      S2_Value :=
        Mul_Mod
          (Right_Point.Y_Value,
           Mul_Mod (Left_Point.Z_Value, Z1Z1_Value, P_Value),
           P_Value);
      H_Value := Sub_Mod (U2_Value, Left_Point.X_Value, P_Value);
      R_Value :=
        Double_Mod (Sub_Mod (S2_Value, Left_Point.Y_Value, P_Value), P_Value);

      if Is_Zero (H_Value) then
         if Is_Zero (R_Value) then
            return Double_Jacobian (Left_Point);
         end if;
         return
           (Infinity => True,
            X_Value  => Zero_Value,
            Y_Value  => Zero_Value,
            Z_Value  => Zero_Value);
      end if;

      HH_Value := Square_Mod (H_Value, P_Value);
      I_Value := Four_Mod (HH_Value, P_Value);
      J_Value := Mul_Mod (H_Value, I_Value, P_Value);
      V_Value := Mul_Mod (Left_Point.X_Value, I_Value, P_Value);
      X3_Value :=
        Sub_Mod
          (Sub_Mod (Square_Mod (R_Value, P_Value), J_Value, P_Value),
           Double_Mod (V_Value, P_Value),
           P_Value);
      Y3_Value :=
        Sub_Mod
          (Mul_Mod (R_Value, Sub_Mod (V_Value, X3_Value, P_Value), P_Value),
           Double_Mod
             (Mul_Mod (Left_Point.Y_Value, J_Value, P_Value), P_Value),
           P_Value);
      Z3_Value :=
        Sub_Mod
          (Square_Mod
             (Add_Mod (Left_Point.Z_Value, H_Value, P_Value), P_Value),
           Add_Mod (Z1Z1_Value, HH_Value, P_Value),
           P_Value);
      return
        (Infinity => False,
         X_Value  => X3_Value,
         Y_Value  => Y3_Value,
         Z_Value  => Z3_Value);
   end Add_Jacobian_Affine;

   function To_Affine (Point_Item : Jacobian_Point) return Point is
      Z_Inverse_Value  : UInt256;
      Z2_Inverse_Value : UInt256;
      Z3_Inverse_Value : UInt256;
      Invertible       : Boolean;
   begin
      if Point_Item.Infinity then
         return
           (Infinity => True, X_Value => Zero_Value, Y_Value => Zero_Value);
      end if;

      Z_Inverse_Value := Inv_Mod (Point_Item.Z_Value, P_Value, Invertible);
      if not Invertible then
         return
           (Infinity => True, X_Value => Zero_Value, Y_Value => Zero_Value);
      end if;
      Z2_Inverse_Value := Square_Mod (Z_Inverse_Value, P_Value);
      Z3_Inverse_Value := Mul_Mod (Z2_Inverse_Value, Z_Inverse_Value, P_Value);
      return
        (Infinity => False,
         X_Value  => Mul_Mod (Point_Item.X_Value, Z2_Inverse_Value, P_Value),
         Y_Value  => Mul_Mod (Point_Item.Y_Value, Z3_Inverse_Value, P_Value));
   end To_Affine;

   function Mul_Point (Scalar_Item : UInt256; Base_Point : Point) return Point
   is
      Result_Point : Jacobian_Point :=
        (Infinity => True,
         X_Value  => Zero_Value,
         Y_Value  => Zero_Value,
         Z_Value  => Zero_Value);
   begin
      if Base_Point.Infinity or else Is_Zero (Scalar_Item) then
         return
           (Infinity => True, X_Value => Zero_Value, Y_Value => Zero_Value);
      end if;

      for Bit_Index in 0 .. 255 loop
         declare
            Doubled_Point   : constant Jacobian_Point :=
              Double_Jacobian (Result_Point);
            Candidate_Point : constant Jacobian_Point :=
              Add_Jacobian_Affine (Doubled_Point, Base_Point);
            Bit_Value       : constant Natural :=
              Get_Bit_Value (Scalar_Item, Bit_Index);
         begin
            Result_Point :=
              Select_Jacobian_Point
                (Doubled_Point, Candidate_Point, Bit_Value);
         end;
      end loop;
      return To_Affine (Result_Point);
   end Mul_Point;

   function From_32_Bytes
     (Data : Stream_Element_Array; Item : out UInt256) return Boolean
   is
      Target_Index : Natural := 0;
   begin
      Item := Zero_Value;
      if Data'Length /= 32 then
         return False;
      end if;
      for Source_Index in Data'Range loop
         Item (Target_Index) := Natural (Data (Source_Index));
         Target_Index := Target_Index + 1;
      end loop;
      return True;
   end From_32_Bytes;

   function To_32_Bytes (Item : UInt256) return Stream_Element_Array is
      Result_Value : Stream_Element_Array (1 .. 32);
      Cursor_Value : Stream_Element_Offset := Result_Value'First;
   begin
      for Index_Value in Word_Index loop
         Result_Value (Cursor_Value) := Stream_Element (Item (Index_Value));
         Cursor_Value := Cursor_Value + 1;
      end loop;
      return Result_Value;
   end To_32_Bytes;

   function Digest_To_Array
     (Digest_Value : CryptoLib.Hashes.SHA256_Digest)
      return Stream_Element_Array
   is
      Result_Value : Stream_Element_Array (1 .. Digest_Value'Length);
      Cursor_Value : Stream_Element_Offset := Result_Value'First;
   begin
      for Byte_Value of Digest_Value loop
         Result_Value (Cursor_Value) := Byte_Value;
         Cursor_Value := Cursor_Value + 1;
      end loop;
      return Result_Value;
   end Digest_To_Array;

   function HMAC_SHA256_Array
     (Key_Data : Stream_Element_Array; Message_Data : Stream_Element_Array)
      return Stream_Element_Array is
   begin
      return
        Digest_To_Array (CryptoLib.Macs.HMAC_SHA256 (Key_Data, Message_Data));
   end HMAC_SHA256_Array;

   function SHA256_Bits2Int_Mod_N
     (Message_Bytes : Stream_Element_Array) return UInt256
   is
      Digest_Value : constant CryptoLib.Hashes.SHA256_Digest :=
        CryptoLib.Hashes.SHA256 (Message_Bytes);
      Result_Value : UInt256 := Zero_Value;
   begin
      --  P-256 has qlen = SHA-256 output length, so bits2int is the digest
      --  interpreted as a 256-bit integer.  ECDSA arithmetic then uses that
      --  value modulo the group order n.  Reducing here keeps both signing
      --  and verification inside the scalar field and avoids relying on
      --  modular helpers to accept over-range left operands.
      for Index_Value in Word_Index loop
         Result_Value (Index_Value) :=
           Natural (Digest_Value (Index_Value + 1));
      end loop;
      if Compare (Result_Value, N_Value) >= 0 then
         Subtract_In_Place (Result_Value, N_Value);
      end if;
      return Result_Value;
   end SHA256_Bits2Int_Mod_N;

   function From_Positive_Mpint
     (Data : Stream_Element_Array; Item : out UInt256) return Boolean
   is
      First_Index  : Stream_Element_Offset := Data'First;
      Target_Index : Natural;
   begin
      Item := Zero_Value;
      if Data'Length = 0 then
         return False;
      end if;
      if Data (First_Index) = 0 then
         if Data'Length = 1 then
            return False;
         end if;
         if Data (First_Index + 1) < 16#80# then
            return False;
         end if;
         First_Index := First_Index + 1;
      elsif Data (First_Index) >= 16#80# then
         return False;
      end if;
      if Natural (Data'Last - First_Index + 1) > 32 then
         return False;
      end if;
      Target_Index := 32 - Natural (Data'Last - First_Index + 1);
      for Source_Index in First_Index .. Data'Last loop
         Item (Target_Index) := Natural (Data (Source_Index));
         Target_Index := Target_Index + 1;
      end loop;
      return not Is_Zero (Item);
   end From_Positive_Mpint;

   function Extract_Raw_Point
     (Public_Point_Bytes : Stream_Element_Array; Public_Point : out Point)
      return Status is
   begin
      Public_Point :=
        (Infinity => True, X_Value => Zero_Value, Y_Value => Zero_Value);
      if Public_Point_Bytes'Length /= 65
        or else Public_Point_Bytes (Public_Point_Bytes'First) /= 16#04#
      then
         return Handshake_Failed;
      end if;

      if not From_32_Bytes
               (Public_Point_Bytes
                  (Public_Point_Bytes'First + 1
                   .. Public_Point_Bytes'First + 32),
                Public_Point.X_Value)
        or else
          not From_32_Bytes
                (Public_Point_Bytes
                   (Public_Point_Bytes'First + 33
                    .. Public_Point_Bytes'First + 64),
                 Public_Point.Y_Value)
      then
         return Handshake_Failed;
      end if;

      Public_Point.Infinity := False;
      if not Is_In_Range_0_To_Modulus_Minus_1 (Public_Point.X_Value, P_Value)
        or else
          not Is_In_Range_0_To_Modulus_Minus_1 (Public_Point.Y_Value, P_Value)
        or else not On_Curve (Public_Point)
      then
         Public_Point :=
           (Infinity => True, X_Value => Zero_Value, Y_Value => Zero_Value);
         return Handshake_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Public_Point :=
           (Infinity => True, X_Value => Zero_Value, Y_Value => Zero_Value);
         return Internal_Error;
   end Extract_Raw_Point;

   function Extract_Public_Key
     (Public_Key_Blob : Stream_Element_Array; Public_Point : out Point)
      return Status
   is
      Algorithm_Buffer : CryptoLib.Buffers.Packet_Buffer;
      Curve_Buffer     : CryptoLib.Buffers.Packet_Buffer;
      Key_Buffer       : CryptoLib.Buffers.Packet_Buffer;
      After_Algorithm  : Stream_Element_Offset;
      After_Curve      : Stream_Element_Offset;
      After_Key        : Stream_Element_Offset;
      Status_Value     : Status;
   begin
      Public_Point :=
        (Infinity => True, X_Value => Zero_Value, Y_Value => Zero_Value);
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Public_Key_Blob,
           Public_Key_Blob'First,
           Algorithm_Buffer,
           After_Algorithm);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Public_Key_Blob, After_Algorithm, Curve_Buffer, After_Curve);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Public_Key_Blob, After_Curve, Key_Buffer, After_Key);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if After_Key /= Public_Key_Blob'Last + 1 then
         return Handshake_Failed;
      end if;
      if not Equal_Text
               (CryptoLib.Buffers.To_Array (Algorithm_Buffer),
                "ecdsa-sha2-nistp256")
        or else
          not Equal_Text
                (CryptoLib.Buffers.To_Array (Curve_Buffer), "nistp256")
      then
         return Handshake_Failed;
      end if;
      declare
         Key_Data : constant Stream_Element_Array :=
           CryptoLib.Buffers.To_Array (Key_Buffer);
      begin
         if Key_Data'Length /= 65 or else Key_Data (Key_Data'First) /= 16#04#
         then
            return Handshake_Failed;
         end if;
         if not From_32_Bytes
                  (Key_Data (Key_Data'First + 1 .. Key_Data'First + 32),
                   Public_Point.X_Value)
           or else
             not From_32_Bytes
                   (Key_Data (Key_Data'First + 33 .. Key_Data'First + 64),
                    Public_Point.Y_Value)
         then
            return Handshake_Failed;
         end if;
      end;
      Public_Point.Infinity := False;
      --  SEC1 uncompressed NIST P-256 public points use affine field
      --  coordinates.  Coordinates are valid in the inclusive field range
      --  0 .. p - 1; zero is not forbidden by SEC1/RFC 5656.  Only scalar
      --  values such as private keys and ECDSA r/s remain restricted to
      --  1 .. n - 1.
      if not Is_In_Range_0_To_Modulus_Minus_1 (Public_Point.X_Value, P_Value)
        or else
          not Is_In_Range_0_To_Modulus_Minus_1 (Public_Point.Y_Value, P_Value)
        or else not On_Curve (Public_Point)
      then
         return Handshake_Failed;
      end if;
      return Ok;
   exception
      when others =>
         Public_Point :=
           (Infinity => True, X_Value => Zero_Value, Y_Value => Zero_Value);
         return Internal_Error;
   end Extract_Public_Key;

   function Extract_Signature
     (Signature_Bytes : Stream_Element_Array;
      R_Value         : out UInt256;
      S_Value         : out UInt256) return Status
   is
      R_Buffer     : CryptoLib.Buffers.Packet_Buffer;
      S_Buffer     : CryptoLib.Buffers.Packet_Buffer;
      After_R      : Stream_Element_Offset;
      After_S      : Stream_Element_Offset;
      Status_Value : Status;
   begin
      R_Value := Zero_Value;
      S_Value := Zero_Value;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Signature_Bytes, Signature_Bytes'First, R_Buffer, After_R);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value :=
        SSH_Lib.Protocol.Numbers.Decode_SSH_String
          (Signature_Bytes, After_R, S_Buffer, After_S);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      if After_S /= Signature_Bytes'Last + 1 then
         return Handshake_Failed;
      end if;
      if not From_Positive_Mpint
               (CryptoLib.Buffers.To_Array (R_Buffer), R_Value)
        or else
          not From_Positive_Mpint
                (CryptoLib.Buffers.To_Array (S_Buffer), S_Value)
      then
         return Handshake_Failed;
      end if;
      if not Is_In_Range_1_To_Modulus_Minus_1 (R_Value, N_Value)
        or else not Is_In_Range_1_To_Modulus_Minus_1 (S_Value, N_Value)
      then
         return Handshake_Failed;
      end if;
      return Ok;
   exception
      when others =>
         R_Value := Zero_Value;
         S_Value := Zero_Value;
         return Internal_Error;
   end Extract_Signature;

   function Verify_Nistp256_With_E
     (Public_Key_Blob : Stream_Element_Array;
      Signature_Bytes : Stream_Element_Array;
      E_Value         : UInt256) return Status
   is
      Public_Point : Point;
      R_Value      : UInt256;
      S_Value      : UInt256;
      W_Value      : UInt256;
      U1_Value     : UInt256;
      U2_Value     : UInt256;
      Invertible   : Boolean;
      P1_Point     : Point;
      P2_Point     : Point;
      Result_Point : Point;
      Status_Value : Status;
      Base_Point   : constant Point :=
        (Infinity => False, X_Value => G_X, Y_Value => G_Y);
   begin
      Status_Value := Extract_Public_Key (Public_Key_Blob, Public_Point);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      Status_Value := Extract_Signature (Signature_Bytes, R_Value, S_Value);
      if Status_Value /= Ok then
         return Status_Value;
      end if;
      W_Value := Inv_Mod (S_Value, N_Value, Invertible);
      if not Invertible then
         return Handshake_Failed;
      end if;
      U1_Value := Mul_Mod (E_Value, W_Value, N_Value);
      U2_Value := Mul_Mod (R_Value, W_Value, N_Value);
      P1_Point := Mul_Point (U1_Value, Base_Point);
      P2_Point := Mul_Point (U2_Value, Public_Point);
      Result_Point := Add_Point (P1_Point, P2_Point);
      if Result_Point.Infinity then
         return Handshake_Failed;
      end if;
      Result_Point.X_Value :=
        Reduce_Once_If_At_Least (Result_Point.X_Value, N_Value);
      if Result_Point.X_Value = R_Value then
         return Ok;
      end if;
      return Handshake_Failed;
   exception
      when others =>
         return Internal_Error;
   end Verify_Nistp256_With_E;

   function Verify_Nistp256
     (Public_Key_Blob : Stream_Element_Array;
      Signature_Bytes : Stream_Element_Array;
      Message_Bytes   : Stream_Element_Array) return Status is
   begin
      return
        Verify_Nistp256_With_E
          (Public_Key_Blob,
           Signature_Bytes,
           SHA256_Bits2Int_Mod_N (Message_Bytes));
   exception
      when others =>
         return Internal_Error;
   end Verify_Nistp256;

   function Validate_Public_Nistp256
     (Public_Key_Blob : Stream_Element_Array) return Status
   is
      Public_Point : Point;
   begin
      return Extract_Public_Key (Public_Key_Blob, Public_Point);
   exception
      when others =>
         return Internal_Error;
   end Validate_Public_Nistp256;

   function Validate_Signature_Nistp256
     (Signature_Bytes : Stream_Element_Array) return Status
   is
      R_Value : UInt256;
      S_Value : UInt256;
   begin
      return Extract_Signature (Signature_Bytes, R_Value, S_Value);
   exception
      when others =>
         return Internal_Error;
   end Validate_Signature_Nistp256;

   function Public_Matches_Private_Nistp256
     (Public_Key_Blob      : Stream_Element_Array;
      Private_Scalar_Mpint : Stream_Element_Array) return Status
   is
      Public_Point  : Point;
      Private_Value : UInt256 := Zero_Value;
      Derived_Point : Point;
      Base_Point    : constant Point :=
        (Infinity => False, X_Value => G_X, Y_Value => G_Y);
      Status_Value  : Status;
   begin
      Status_Value := Extract_Public_Key (Public_Key_Blob, Public_Point);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      if not From_Positive_Mpint (Private_Scalar_Mpint, Private_Value)
        or else not Is_In_Range_1_To_Modulus_Minus_1 (Private_Value, N_Value)
      then
         return Authentication_Failed;
      end if;

      Derived_Point := Mul_Point (Private_Value, Base_Point);
      if Derived_Point.Infinity
        or else Derived_Point.X_Value /= Public_Point.X_Value
        or else Derived_Point.Y_Value /= Public_Point.Y_Value
      then
         return Authentication_Failed;
      end if;

      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Public_Matches_Private_Nistp256;

   function To_Minimal_Mpint
     (Item : UInt256) return CryptoLib.Buffers.Packet_Buffer
   is
      First_Index    : Natural := 0;
      Payload_Buffer : CryptoLib.Buffers.Packet_Buffer;
      Status_Value   : Status;
   begin
      while First_Index < 31 and then Item (First_Index) = 0 loop
         First_Index := First_Index + 1;
      end loop;
      if Item (First_Index) >= 16#80# then
         Status_Value :=
           CryptoLib.Buffers.Append_Byte (Payload_Buffer, 0);
         if Status_Value /= Ok then
            return Payload_Buffer;
         end if;
      end if;
      for Index_Value in First_Index .. 31 loop
         Status_Value :=
           CryptoLib.Buffers.Append_Byte
             (Payload_Buffer, Stream_Element (Item (Index_Value)));
         if Status_Value /= Ok then
            return Payload_Buffer;
         end if;
      end loop;
      return
        SSH_Lib.Protocol.Numbers.Encode_SSH_String
          (CryptoLib.Buffers.To_Array (Payload_Buffer));
   end To_Minimal_Mpint;

   function Nonce_For
     (Private_Value : UInt256;
      Message_Bytes : Stream_Element_Array;
      Counter_Value : Natural) return UInt256
   is
      X_Data          : constant Stream_Element_Array :=
        To_32_Bytes (Private_Value);
      H1_Value        : constant UInt256 :=
        SHA256_Bits2Int_Mod_N (Message_Bytes);
      H1_Data         : constant Stream_Element_Array :=
        To_32_Bytes (H1_Value);
      V_Data          : Stream_Element_Array (1 .. 32) := [others => 1];
      K_Data          : Stream_Element_Array (1 .. 32) := [others => 0];
      Seed_0          : Stream_Element_Array (1 .. 32 + 1 + 32 + 32);
      Seed_1          : Stream_Element_Array (1 .. 32 + 1 + 32 + 32);
      Tail_Data       : Stream_Element_Array (1 .. 32 + 1);
      Candidate_Value : UInt256 := Zero_Value;
      Accepted_Count  : Natural := 0;
      Cursor_Value    : Stream_Element_Offset;
   begin
      --  RFC 6979 deterministic ECDSA nonce generation using HMAC-SHA256.
      --  This avoids ad-hoc private-key/message hashing and prevents nonce
      --  reuse across repeated signatures of the same SSH userauth payload.
      Cursor_Value := Seed_0'First;
      for Byte_Value of V_Data loop
         Seed_0 (Cursor_Value) := Byte_Value;
         Cursor_Value := Cursor_Value + 1;
      end loop;
      Seed_0 (Cursor_Value) := 0;
      Cursor_Value := Cursor_Value + 1;
      for Byte_Value of X_Data loop
         Seed_0 (Cursor_Value) := Byte_Value;
         Cursor_Value := Cursor_Value + 1;
      end loop;
      for Byte_Value of H1_Data loop
         Seed_0 (Cursor_Value) := Byte_Value;
         Cursor_Value := Cursor_Value + 1;
      end loop;
      K_Data := HMAC_SHA256_Array (K_Data, Seed_0);
      V_Data := HMAC_SHA256_Array (K_Data, V_Data);

      Cursor_Value := Seed_1'First;
      for Byte_Value of V_Data loop
         Seed_1 (Cursor_Value) := Byte_Value;
         Cursor_Value := Cursor_Value + 1;
      end loop;
      Seed_1 (Cursor_Value) := 1;
      Cursor_Value := Cursor_Value + 1;
      for Byte_Value of X_Data loop
         Seed_1 (Cursor_Value) := Byte_Value;
         Cursor_Value := Cursor_Value + 1;
      end loop;
      for Byte_Value of H1_Data loop
         Seed_1 (Cursor_Value) := Byte_Value;
         Cursor_Value := Cursor_Value + 1;
      end loop;
      K_Data := HMAC_SHA256_Array (K_Data, Seed_1);
      V_Data := HMAC_SHA256_Array (K_Data, V_Data);

      loop
         V_Data := HMAC_SHA256_Array (K_Data, V_Data);
         if From_32_Bytes (V_Data, Candidate_Value)
           and then Is_In_Range_1_To_Modulus_Minus_1 (Candidate_Value, N_Value)
         then
            if Accepted_Count = Counter_Value then
               return Candidate_Value;
            end if;
            Accepted_Count := Accepted_Count + 1;
         end if;

         Cursor_Value := Tail_Data'First;
         for Byte_Value of V_Data loop
            Tail_Data (Cursor_Value) := Byte_Value;
            Cursor_Value := Cursor_Value + 1;
         end loop;
         Tail_Data (Cursor_Value) := 0;
         K_Data := HMAC_SHA256_Array (K_Data, Tail_Data);
         V_Data := HMAC_SHA256_Array (K_Data, V_Data);
      end loop;
   exception
      when others =>
         return Zero_Value;
   end Nonce_For;

   function Validate_Raw_Point_Nistp256
     (Public_Point_Bytes : Stream_Element_Array) return Status
   is
      Public_Point : Point;
   begin
      return Extract_Raw_Point (Public_Point_Bytes, Public_Point);
   exception
      when others =>
         return Internal_Error;
   end Validate_Raw_Point_Nistp256;

   function Generate_ECDH_Nistp256_Keypair
     (Source_Item          : in out CryptoLib.Random.Random_Source;
      Private_Scalar_Bytes : out Stream_Element_Array;
      Public_Point_Bytes   : out Stream_Element_Array) return Status
   is
      Private_Value : UInt256 := Zero_Value;
      Public_Point  : Point;
      Status_Value  : Status;
      Random_Data   : Stream_Element_Array (1 .. 32);
      Base_Point    : constant Point :=
        (Infinity => False, X_Value => G_X, Y_Value => G_Y);
      Cursor_Value  : Stream_Element_Offset;
      X_Data        : Stream_Element_Array (1 .. 32);
      Y_Data        : Stream_Element_Array (1 .. 32);
   begin
      Private_Scalar_Bytes := [others => 0];
      Public_Point_Bytes := [others => 0];

      if Private_Scalar_Bytes'Length /= 32
        or else Public_Point_Bytes'Length /= 65
      then
         return Handshake_Failed;
      end if;

      for Attempt_Value in 1 .. 64 loop
         Status_Value := CryptoLib.Random.Fill (Source_Item, Random_Data);
         if Status_Value /= Ok then
            return Status_Value;
         end if;

         if From_32_Bytes (Random_Data, Private_Value)
           and then Is_In_Range_1_To_Modulus_Minus_1 (Private_Value, N_Value)
         then
            Public_Point := Mul_Point (Private_Value, Base_Point);
            if not Public_Point.Infinity then
               Private_Scalar_Bytes := Random_Data;
               X_Data := To_32_Bytes (Public_Point.X_Value);
               Y_Data := To_32_Bytes (Public_Point.Y_Value);

               Cursor_Value := Public_Point_Bytes'First;
               Public_Point_Bytes (Cursor_Value) := 16#04#;
               Cursor_Value := Cursor_Value + 1;
               for Byte_Value of X_Data loop
                  Public_Point_Bytes (Cursor_Value) := Byte_Value;
                  Cursor_Value := Cursor_Value + 1;
               end loop;
               for Byte_Value of Y_Data loop
                  Public_Point_Bytes (Cursor_Value) := Byte_Value;
                  Cursor_Value := Cursor_Value + 1;
               end loop;

               return Ok;
            end if;
         end if;
      end loop;

      Private_Scalar_Bytes := [others => 0];
      Public_Point_Bytes := [others => 0];
      return Internal_Error;
   exception
      when others =>
         Private_Scalar_Bytes := [others => 0];
         Public_Point_Bytes := [others => 0];
         return Internal_Error;
   end Generate_ECDH_Nistp256_Keypair;

   function Validate_ECDH_Nistp256_Shared_Secret
     (Shared_Secret_Bytes : Stream_Element_Array) return Status
   is
      Nonzero_Secret : Boolean := False;
   begin
      if Shared_Secret_Bytes'Length /= 32 then
         return Handshake_Failed;
      end if;

      for Byte_Value of Shared_Secret_Bytes loop
         if Byte_Value /= 0 then
            Nonzero_Secret := True;
            exit;
         end if;
      end loop;

      if not Nonzero_Secret then
         return Handshake_Failed;
      end if;

      return Ok;
   exception
      when others =>
         return Internal_Error;
   end Validate_ECDH_Nistp256_Shared_Secret;

   function Compute_ECDH_Nistp256_Shared_Secret
     (Private_Scalar_Bytes : Stream_Element_Array;
      Server_Point_Bytes   : Stream_Element_Array;
      Shared_Secret_Bytes  : out Stream_Element_Array) return Status
   is
      Private_Value : UInt256 := Zero_Value;
      Server_Point  : Point;
      Shared_Point  : Point;
      Status_Value  : Status;
   begin
      Shared_Secret_Bytes := [others => 0];
      if Private_Scalar_Bytes'Length /= 32
        or else Shared_Secret_Bytes'Length /= 32
      then
         return Handshake_Failed;
      end if;
      if not From_32_Bytes (Private_Scalar_Bytes, Private_Value)
        or else not Is_In_Range_1_To_Modulus_Minus_1 (Private_Value, N_Value)
      then
         return Handshake_Failed;
      end if;
      Status_Value := Extract_Raw_Point (Server_Point_Bytes, Server_Point);
      if Status_Value /= Ok then
         return Status_Value;
      end if;

      Shared_Point := Mul_Point (Private_Value, Server_Point);
      if Shared_Point.Infinity then
         return Handshake_Failed;
      end if;

      Shared_Secret_Bytes := To_32_Bytes (Shared_Point.X_Value);
      return Validate_ECDH_Nistp256_Shared_Secret (Shared_Secret_Bytes);
   exception
      when others =>
         Shared_Secret_Bytes := [others => 0];
         return Internal_Error;
   end Compute_ECDH_Nistp256_Shared_Secret;

   function Sign_Nistp256
     (Private_Scalar_Mpint : Stream_Element_Array;
      Message_Bytes        : Stream_Element_Array;
      Signature_Bytes      : out CryptoLib.Buffers.Packet_Buffer)
      return Status
   is
      Private_Value : UInt256 := Zero_Value;
      E_Value       : UInt256 := Zero_Value;
      K_Value       : UInt256 := Zero_Value;
      R_Value       : UInt256 := Zero_Value;
      S_Value       : UInt256 := Zero_Value;
      K_Inv_Value   : UInt256 := Zero_Value;
      R_Point       : Point;
      Invertible    : Boolean;
      Base_Point    : constant Point :=
        (Infinity => False, X_Value => G_X, Y_Value => G_Y);
      Inner_Buffer  : CryptoLib.Buffers.Packet_Buffer;
      Status_Value  : Status;
   begin
      CryptoLib.Buffers.Clear (Signature_Bytes);
      if not From_Positive_Mpint (Private_Scalar_Mpint, Private_Value)
        or else not Is_In_Range_1_To_Modulus_Minus_1 (Private_Value, N_Value)
      then
         return Authentication_Failed;
      end if;
      E_Value := SHA256_Bits2Int_Mod_N (Message_Bytes);

      for Counter_Value in 0 .. 255 loop
         K_Value := Nonce_For (Private_Value, Message_Bytes, Counter_Value);
         if Is_In_Range_1_To_Modulus_Minus_1 (K_Value, N_Value) then
            R_Point := Mul_Point (K_Value, Base_Point);
            if not R_Point.Infinity then
               R_Value := R_Point.X_Value;
               R_Value := Reduce_Once_If_At_Least (R_Value, N_Value);
               if not Is_Zero (R_Value) then
                  K_Inv_Value := Inv_Mod (K_Value, N_Value, Invertible);
                  if Invertible then
                     S_Value :=
                       Mul_Mod
                         (K_Inv_Value,
                          Add_Mod
                            (E_Value,
                             Mul_Mod (R_Value, Private_Value, N_Value),
                             N_Value),
                          N_Value);
                     if not Is_Zero (S_Value) then
                        --  Emit a deterministic low-S ECDSA signature.  SSH
                        --  verifiers generally accept either S or n-S, but
                        --  canonicalizing local identity-file signatures avoids
                        --  malleable high-S output while keeping verification
                        --  permissive for peer/agent signatures.
                        if Compare (S_Value, Half_N_Value) > 0 then
                           S_Value := Sub_Mod (N_Value, S_Value, N_Value);
                        end if;
                        Status_Value :=
                          CryptoLib.Buffers.Append
                            (Inner_Buffer,
                             CryptoLib.Buffers.To_Array
                               (To_Minimal_Mpint (R_Value)));
                        if Status_Value = Ok then
                           Status_Value :=
                             CryptoLib.Buffers.Append
                               (Inner_Buffer,
                                CryptoLib.Buffers.To_Array
                                  (To_Minimal_Mpint (S_Value)));
                        end if;
                        if Status_Value /= Ok then
                           CryptoLib.Buffers.Clear (Inner_Buffer);
                           return Status_Value;
                        end if;
                        Status_Value :=
                          CryptoLib.Buffers.Set
                            (Signature_Bytes,
                             CryptoLib.Buffers.To_Array (Inner_Buffer));
                        CryptoLib.Buffers.Clear (Inner_Buffer);
                        return Status_Value;
                     end if;
                  end if;
               end if;
            end if;
         end if;
      end loop;
      return Authentication_Failed;
   exception
      when others =>
         CryptoLib.Buffers.Clear (Signature_Bytes);
         return Internal_Error;
   end Sign_Nistp256;
end SSH_Lib.ECDSA;
