# SSH Config Support

SSH_Lib.Config implements a narrow OpenSSH-style config subset for Git-over-SSH transport use.

Supported directives:

- `Host`
- `HostName`
- `User`
- `Port`
- `IdentityFile`
- `IdentitiesOnly`

Config resolution preserves secure session defaults unless a supported directive explicitly overrides the relevant field. `ProxyJump` is resolved as data in `Session_Options.Proxy_Jump`; `Sessions.Open` implements it as SSH-over-SSH `direct-tcpip` forwarding. `ProxyCommand` is resolved as data in `Session_Options.Proxy_Command`; `Sessions.Open` executes it only as an explicit subprocess-backed transport after applying OpenSSH-style `%h`, `%p`, `%r`, and `%%` token expansion. `ControlMaster`, `ControlPath`, and `ControlPersist` are resolved as data in `Session_Options.Control_Master`, `Control_Path`, and `Control_Persist`. `LocalForward`, `RemoteForward`, and `DynamicForward` are resolved as line-separated session data in `Session_Options.Local_Forwards`, `Remote_Forwards`, and `Dynamic_Forwards`; `SSH_Lib.Config_Apply` can start local/dynamic managed services and request remote forwards from those resolved values. `SendEnv` and `SetEnv` are resolved as line-separated data in `Session_Options.Send_Env` and `Set_Env`; `SSH_Lib.Config_Apply.Apply_Configured_Environment` sends the resulting RFC 4254 `env` requests on a caller-supplied channel. `ProxyCommand none` is normalized to an empty proxy command and uses the normal direct transport path. General config resolution does not shell out. ProxyCommand expansion supports the OpenSSH ProxyCommand token set `%h`, `%n`, `%p`, `%r`, and `%%`; unknown percent pairs are preserved literally.

`Load_Default` should read the default config location through Ada path/environment helpers. Default tests must not depend on the user’s real SSH config.
