# Persistent witness identity without secret command arguments

Run `witnessd -seed-file /protected/path/witness.seed`. The file must contain exactly 64 hexadecimal digits encoding a 32-byte Ed25519 seed, optionally followed by LF or CRLF. Provision it through a protected editor or secret-management tool; never paste its contents into a shell command. Keep its directory protected as well.

On Linux and macOS the file must be regular, owned by the effective user, and have no group or other permission bits (`chmod 600`). A read-only owner file (`400`) also works. Final-component symlinks and non-regular files are refused. Validation and bounded reading use the same opened descriptor. Files with malformed or oversized contents fail startup instead of generating a replacement identity. Diagnostics omit both seed contents and paths.

Linux POSIX ACL grants are bounded by the group-class mode mask, which must be zero. On macOS, mode bits alone do not cover extended ACL grants: the daemon queries the native descriptor ACL and rejects any extended ACL. Remove unwanted grants with `chmod -N /protected/path/witness.seed` and recheck permissions. macOS protected loading requires a cgo-enabled build; a build without cgo fails closed. Other operating systems also refuse `-seed-file` until their access-control checks are implemented. No permission changes are made by the daemon.

Loading the same file retains the same public witness identity across restarts. The public key can still appear in startup logs; seed bytes do not.

`-seed` remains available for compatibility but prints a deprecation warning; migrate persistent deployments to `-seed-file`. There is no scheduled removal in this change. Passing both nonempty options is rejected. An explicitly empty `-seed-file` is also rejected. With neither option, the daemon retains its explicitly logged **EPHEMERAL** demo behavior.

Persistent key identity does **not** persist rollback memory or filing records, repair witness amnesia, create federation, or establish a key registry. The existing trust-on-first-checkpoint and single-witness limitations remain.
