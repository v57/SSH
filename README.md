# SSH

`SSHKit`: SSH for the v57 apps, in-process on libssh2 + mbedTLS (macOS 14, iOS 17, Windows).

- `SSHServer`, `SSHKey` (Ed25519, ECDSA, RSA, or a key held elsewhere such as the Secure Enclave, signing through a
  closure; `SSHKey(importing:passphrase:)` opens OpenSSH and PEM keys behind a passphrase with AES; private bytes are
  overwritten when the last copy of the key goes away) and `SSHLogin`: one session from the TCP connection to a
  logged-in user, with the host key decided before anything is sent (`SSHServer.trust`, required: a pinned key, asking
  someone, or refusing; `SSHKnownHosts` ships GitHub's, GitLab's and Bitbucket's keys), and key, password or
  keyboard-interactive login (the password answers only prompts that ask for it).
- `SSHAlgorithms`: what every session offers: libssh2's algorithms less SHA-1 key exchange and signatures, CBC and
  older ciphers, and MD5, RIPEMD-160 and SHA-1 MACs. Strict key exchange (Terrapin) stays on.
- `SSHCommand`: one command on a pseudo-terminal, its output streamed, its exit status, Stop hanging it up.
- `SSHConnection`: one login running many commands side by side, each on its own channel without a terminal:
  output and errors apart and byte for byte, input written then closed, the exit status (Git's iOS app runs git
  on a Mac over it). `open` starts a command that talks back and forth over a channel (Git's iOS app pushes with
  `git-receive-pack` on one).
- `SFTPClient`: list, stat, ranged reads, atomic writes, folders, rename, remove.
- `SSHJump`: logins through a jump host (`ssh -J`), over a socket pair in this process.
- `Sockets` and `PollWaker`: the socket layer (BSD sockets or Winsock) for apps that drive their own libssh2
  sessions; the `Libssh2` product is libssh2 itself (module `CLibssh2`).

Database's `SSHTunnel` (database connections over `direct-tcpip` channels) is built on it.

libssh2 is prebuilt for Apple platforms (Database's `Scripts/build-libssh2.sh`, published on Shell's GitHub
Releases; a local `Binary/Libssh2.xcframework` wins) and built from source on Windows (`Sources/CLibssh2`, WinCNG).
It has no Ed25519 host keys: servers need an ECDSA or RSA host key.

```bash
swift build
swift test    # key tests; the login tests need an sshd (see Tests/SSHKitTests/TestServer.swift)
```
