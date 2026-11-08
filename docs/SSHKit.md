# SSHKit

SSH for Swift apps, in the app's own process, on libssh2. Part of [SSH](../README.md); the C library underneath is
the [Libssh2](Libssh2.md) product.

## Purpose

`SSHKit` logs in to an SSH server and does work there: runs commands, moves files over SFTP, and reaches servers
through a jump host. Every login goes through one path (`SSHLogin`), so host keys are checked and users authenticated
the same way whatever the app does next. The server's host key is decided after the handshake and before any password
or signature leaves the device, and an app can't make a login without saying how that decision is made.

It is not a terminal emulator, an SSH server, or a port forwarder: Database's `SSHTunnel` (database connections over
`direct-tcpip` channels) is built on it, and an app that drives its own libssh2 sessions (a terminal) uses the
`Libssh2` product with `SSHKit`'s socket layer. It has no ssh-agent support and doesn't read `~/.ssh/config` or
`~/.ssh/known_hosts`: the app keeps keys and known host keys itself and passes them in.

## Getting started

```swift
// Package.swift
dependencies: [
  .package(url: "https://github.com/v57/SSH.git", branch: "main"),
],
targets: [
  .target(name: "MyApp", dependencies: [.product(name: "SSHKit", package: "SSH")]),
]
```

Log in with a key, trust the host key the user accepted before (or ask), and run one command:

```swift
import SSHKit

func uptime(savedFingerprint: String?, keyText: String) async throws -> String {
  let key = try SSHKey(importing: keyText)
  let server = SSHServer(
    host: "example.com", user: "user", key: key,
    trust: .known(savedFingerprint, otherwise: .ask { hostKey in
      // Show hostKey.fingerprint ("SHA256:…") and hostKey.type to the user; true goes on.
      await confirmHostKey(hostKey)
    }))
  let connection = try await SSHConnection.connect(server: server)
  defer { connection.close() }
  // connection.hostKeyFingerprint is the key that was accepted: save it and pin it next time.
  let output = try await connection.run("uptime")
  return String(decoding: output.stdout, as: UTF8.self)
}
```

`confirmHostKey` stands for the app's own prompt.

## Main API

### Servers and host-key trust

- `SSHServer(host:fallbackHosts:port:user:password:key:trust:)`: where and how to log in. `port` defaults to 22.
  `fallbackHosts` are other addresses of the same machine, tried in order when `host` doesn't answer.
  `unattended` (default `false`) says nobody started this login just now, so a key that would ask the user fails
  instead.
- `SSHHostTrust`: required on every `SSHServer`.
  - `.pinned("SHA256:…")`: only this key. Any other fails with `SSHTunnelError.hostKeyChanged`.
  - `.ask { (SSHHostKey) async -> Bool in … }`: nothing is known and someone can answer. The closure gets the key
    after the handshake. It waits two minutes at most; no answer is a no (`hostKeyRejected`). Only the server's own
    address is asked about: if a fallback address answered, the login fails with `hostKeyFromFallback`, since anyone
    on the network can answer for a `.local` name. Fallbacks work once the key is pinned.
  - `.refuseUnknown`: nothing is known and nobody can answer (a background job, a command-line tool). An unknown key
    fails with `hostKeyUnverified`.
  - `SSHHostTrust.known(_:otherwise:)`: `.pinned` when the fingerprint is non-empty, else the fallback.
- `SSHHostKey`: what the server showed: `host`, `port`, `address` (the address that answered), `fingerprint`
  (`SHA256:…`, as `ssh-keygen -l` prints it) and `type` ("ECDSA P-256", "RSA", …).
- `SSHKnownHosts.fingerprints(host:port:)`: the host keys shipped with the library for GitHub, GitLab and Bitbucket
  (`github.com:22`, `ssh.github.com:443`, `gitlab.com:22`, `altssh.gitlab.com:443`, `bitbucket.org:22`,
  `ssh.bitbucket.org:22`). These win over the app's `trust`: another key there is refused with
  `hostKeyNotPublished`, and nobody is asked. A key change at one of these sites needs a new build of SSHKit.
- `SSHServer.verify(_:)`: the decision itself, for apps that run their own handshake.

Keep the accepted fingerprint (`hostKeyFingerprint` on `SSHConnection`, `SFTPClient`, `SSHCommand`, `SSHLogin`)
and pass it back as `.pinned` next time. The library doesn't store it.

### Keys and authentication

- `SSHKey(importing:passphrase:)`: reads an OpenSSH private key (`BEGIN OPENSSH PRIVATE KEY`) or a PEM key
  (PKCS#1 RSA, SEC1 ECDSA, PKCS#8 ECDSA, RSA or Ed25519). Keys behind a passphrase open with AES (OpenSSH's format with
  bcrypt_pbkdf, PEM with AES-CBC). Without a passphrase it throws `SSHKey.ImportError.needsPassphrase`, with the wrong
  one `wrongPassphrase`; other encryption (chacha20-poly1305, 3DES, encrypted PKCS#8) throws `unsupportedEncryption`
  with the `ssh-keygen` command that rewrites the key.
- `SSHKey.generateEd25519(comment:)`: a new key.
- `SSHKey(kind:privateBytes:comment:)`: a key from raw material (the 32-byte seed for Ed25519, the scalar for ECDSA,
  PKCS#1 DER for RSA).
- `SSHKey(kind:publicKeyBlob:comment:prepare:sign:)`: a key held elsewhere (a Secure Enclave key, a key on another
  device). `sign` returns the signature body libssh2 expects. `prepare`, when given, runs just before the login uses
  the key, after the host key is settled and once the server takes keys; it gets `true` when the server is
  `unattended`, and throwing ends the login with that error. Time spent in `prepare` doesn't count against the login's
  timeout.
- `SSHKey.Kind`: `.ed25519`, `.ecdsaP256`, `.ecdsaP384`, `.ecdsaP521`, `.rsa` (signs with `rsa-sha2-256`).
- On a key: `authorizedKeyLine` (for `~/.ssh/authorized_keys`), `fingerprint`, `publicKeyBlob()`, `sign(_:)`,
  `openSSHPrivateKey` (unencrypted OpenSSH text, for saving a generated key), `comment`.

A key's private bytes live in memory of their own and are overwritten with zeros when the last copy of the key goes
away. `privateBytes` returns a new copy that the caller must look after.

How a login authenticates (`SSHServer.key` and `SSHServer.password`):

1. If the server needs no authentication, nothing is sent.
2. With a key and a server that takes `publickey`, the key signs.
3. With a password, `password` authentication, then `keyboard-interactive`. In a keyboard-interactive round the
   password answers only a hidden prompt that asks for the password (in several languages), never a prompt that shows
   what's typed, asks for a one-time code, or asks for a new password. Other prompts get an empty answer.
4. Otherwise `SSHTunnelError.authenticationFailed(methods:)` lists what the server allows.

### Commands

- `SSHConnection.connect(server:through:timeout:)`: one login that runs many commands side by side, each on its own
  channel without a terminal. `through` is an optional jump host; `timeout` (20 s) covers the login.
  - `run(_:input:onError:)`: runs the command through the login shell, writes `input` and closes it, and returns
    `SSHConnection.Output` (`stdout`, `stderr`, `status`; `status` is nil when the server sent none). `onError` gets
    standard error as it arrives. Cancelling the task closes the channel.
  - `open(_:)`: starts a command that talks back and forth and returns a `SSHConnection.Channel`: `write(_:)`,
    `finishWriting()`, `read()` (the next piece of standard output, nil at the end), `finished()` (standard error and
    the exit status) and `close()`. A reader that falls behind holds the command back.
  - `isAlive`, `onClosed(_:)`, `close()`, `hostKeyFingerprint`, `connectedHost`.
- `SSHCommand(server:command:)`: one command on a pseudo-terminal, as `ssh host command` runs it. Programs flush line
  by line and show progress; standard error arrives mixed into the output. `run(timeout:onOutput:)` returns the exit
  status, and `stop()` hangs the command up.

Use `SSHConnection` for programs whose output you parse, and `SSHCommand` for output a person reads.

### Files

- `SFTPClient.connect(server:through:timeout:operationTimeout:)`: logs in and starts SFTP. `operationTimeout` (60 s)
  is how long one call may wait without progress.
- `realPath(_:)`, `list(_:followLinks:)` (sorted by name, without `.` and `..`), `stat(_:followLinks:)` (nil when
  nothing is there), `read(_:offset:length:)`, `write(_:to:atomic:createParents:permissions:)`,
  `createDirectory(_:intermediate:permissions:)`, `rename(_:to:replacing:)`, `removeFile(_:)`,
  `removeDirectory(_:)`.
- `write` is atomic by default: it writes a temporary file next to the target and renames it over, keeping a replaced
  file's permissions. It falls back to writing in place when the folder can't take a new file.
- `read` without a `length` takes at most `SFTPClient.wholeFileLimit` (256 MB) and refuses a larger file, whatever
  size the server reports. Read larger files in ranges.
- `SFTPFileInfo`: `path`, `name`, `kind`, `isDirectory`, `isSymbolicLink`, `size`, `modified`, `permissions`.
- `SFTPError`: `noSuchFile`, `permissionDenied`, `alreadyExists`, `directoryNotEmpty`, `notADirectory`,
  `isADirectory`, `unsupported`, `failed(path:status:message:)`, `connectionLost` and `closed`.

### Jump hosts

Pass the jump host's `SSHServer` as `through:` to `SSHConnection.connect` or `SFTPClient.connect`. The jump host and
the server each have their own `trust`. The bytes cross a socket pair inside the process; nothing listens on a port.
`SFTPClient.jumpHostKeyFingerprint` is the jump host's key.

For your own sessions: `SSHJump.open(to:through:timeout:)`, then `SSHLogin(server:jump:)`.

### Lower level

- `SSHLogin(server:jump:)`: one libssh2 session from the TCP connection to a logged-in user. `connect(timeout:)`,
  `session` (the libssh2 session pointer), `socket`, `waitSocket(milliseconds:)`, `lastError()`, `isTransportDead`,
  `teardown(reason:)`. libssh2 isn't thread-safe per session: use a session from one thread.
- `SSHAlgorithms.restrict(_:)`: call on a libssh2 session before the handshake. It offers libssh2's algorithms less
  SHA-1 key exchange and signatures, CBC and older ciphers, and MD5, RIPEMD-160 and SHA-1 MACs. Strict key exchange
  (the Terrapin fix) stays on. Every SSHKit session does this; a server with nothing else fails the handshake.
- `Sockets`: non-blocking TCP sockets on BSD sockets or Winsock: `connect(host:port:timeout:keepAlive:)`,
  `listen(host:port:)`, `accept(_:)`, `receive(_:into:)` and `send(_:_:)` (returning `Sockets.Transfer`),
  `poll(_:milliseconds:)`, `wait(_:for:milliseconds:)`, `close(_:)`, `shutdownWrite(_:)`, `peerAddress(_:)`.
  `SocketHandle` is libssh2's socket type on each platform. `SocketError` says why a connect or listen failed.
- `PollWaker`: wakes a thread sleeping in `poll` (`fd`, `wake()`, `drain()`, `close()`).

### Errors

`SSHTunnelError` covers logins: `connectFailed`, `handshakeFailed`, `hostKeyChanged`, `hostKeyUnverified`,
`hostKeyRejected`, `hostKeyFromFallback`, `hostKeyNotPublished`, `authenticationFailed`, `forwardFailed` and
`closed`. Each has an `errorDescription` meant for the user.

## Server requirements

- The server needs an ECDSA or RSA host key. The prebuilt libssh2 on Apple platforms (Mbed TLS) has no Ed25519 host
  keys.
- The server must offer at least one key exchange, cipher and MAC that `SSHAlgorithms` keeps. Current OpenSSH does.

## Platform notes

- **macOS** (14+) and **iOS / iPadOS** (17+): supported. libssh2 is the prebuilt `Libssh2.xcframework` (arm64 slices
  only: Apple silicon Macs, iOS devices, the arm64 simulator). Keys sign with CryptoKit and Security.
- **Linux**: builds and passes the test suite on Ubuntu 24.04 against a user-level sshd. libssh2 builds from
  `Sources/CLibssh2` with the system's OpenSSL (`apt install libssl-dev`); CryptoKit comes from v57/SwiftUI's
  stand-in and RSA from swift-crypto.
- **Windows**: builds; the login, command, SFTP and host-trust suites pass against an OpenSSH sshd on a Windows VM.
  libssh2 builds from source with WinCNG (ECDSA key exchange included, which OpenSSH 10 servers need). Jump hosts are
  not supported yet: `SSHJump.open` throws `connectFailed`.
- **Android**: not yet. `Package.swift` has no Android section.

On Linux and Windows the package depends on [v57/SwiftUI](https://github.com/v57/SwiftUI) and swift-crypto. Set
`V57_LOCAL=1` to build against a `../SwiftUI` checkout next to this one instead of GitHub's `main`.

## Testing

```bash
swift build
swift test
```

Without an SSH server only the tests that need none run (keys, passphrases, algorithm lists, keyboard-interactive
prompts, error texts, and on Apple platforms a fake hostile server). The login, command, SFTP and jump-host suites
skip themselves when nothing listens on the test port.

To run them, start an sshd that takes a test key (`Tests/SSHKitTests/TestServer.swift` has the details):

```bash
mkdir -p .testing/ssh .testing/sshd
ssh-keygen -t ed25519 -N "" -f .testing/ssh/id_ed25519            # the client key the tests log in with
ssh-keygen -t ecdsa -N "" -f .testing/sshd/ssh_host_ecdsa_key     # an ECDSA host key (no Ed25519, see above)
cp .testing/ssh/id_ed25519.pub .testing/sshd/authorized_keys
cat > .testing/sshd/sshd_config <<EOF
Port 2222
ListenAddress 127.0.0.1
HostKey $PWD/.testing/sshd/ssh_host_ecdsa_key
AuthorizedKeysFile $PWD/.testing/sshd/authorized_keys
StrictModes no
UsePAM no
Subsystem sftp /usr/libexec/sftp-server
EOF
/usr/sbin/sshd -D -e -f "$PWD/.testing/sshd/sshd_config"
```

`.testing/` is gitignored. On Linux the SFTP server is `/usr/lib/openssh/sftp-server`. Then, in another terminal:

```bash
SSH_TEST_PORT=2222 SSH_TEST_USER=$USER SSH_TEST_SERVICES=local swift test
swift test --filter SFTPClientTests     # one suite
```

- `SSH_TEST_PORT`: the sshd's port on 127.0.0.1 (default 2222).
- `SSH_TEST_USER`: the user to log in as (default `tunnel`, the user of Database's docker-compose bastion).
- `SSH_TEST_KEY`: the private key, if not `.testing/ssh/id_ed25519`.
- `SSH_TEST_SERVICES=local`: the sshd runs on this machine at `SSH_TEST_PORT`, so the jump-host tests reach it there
  (without it they expect port 22, as inside Database's docker-compose bastion).

On Linux, add `V57_LOCAL=1` to test against the checkouts next to this one. The library has no fakes for apps; tests
of app code that logs in need a real sshd as above.
