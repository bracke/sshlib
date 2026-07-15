package SSH_Lib.Tests.Fixtures.Temp_Paths is
   function Path (Name : String) return String;

   --  Restrict a fixture file to its owner (chmod 0600). A key file written for
   --  Identity_Files.Load must be owner-only, or Load refuses it the way OpenSSH refuses a
   --  group- or world-readable private key. A no-op where the host has no POSIX modes.
   procedure Make_Owner_Only (Name : String);

   --  Deliberately expose a fixture file (chmod 0644), to prove a private key that others can
   --  read is refused. A no-op where the host has no POSIX modes.
   procedure Make_World_Readable (Name : String);
end SSH_Lib.Tests.Fixtures.Temp_Paths;
