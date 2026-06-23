with Ada.Text_IO;
with SSH_Lib.Tests.Fixtures.Crypto_Primitives;

procedure Test_Crypto_Primitives is
begin
   SSH_Lib.Tests.Fixtures.Crypto_Primitives.Assert_Crypto_Primitives;
   Ada.Text_IO.Put_Line ("test_crypto_primitives passed");
end Test_Crypto_Primitives;
