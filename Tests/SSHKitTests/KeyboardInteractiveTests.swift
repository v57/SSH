import CLibssh2
import Foundation
import Testing

@testable import SSHKit

/// A server can ask anything over keyboard-interactive. The saved password used to answer every prompt, so a server
/// asking for "Verification code" with the code shown, or a question of its own, got the password in plain text.
struct KeyboardInteractiveTests {
  /// Runs libssh2's callback on these prompts and returns what it answered each with.
  private func answers(_ prompts: [(text: String, echo: Bool)], password: String = "hunter2") -> [String?] {
    var texts = prompts.map { Array($0.text.utf8) }
    let box = Unmanaged.passRetained(PasswordBox(password))
    defer { box.release() }
    var abstract: UnsafeMutableRawPointer? = box.toOpaque()
    return texts.withUnsafeMutableBufferPointer { buffers in
      var cPrompts: [LIBSSH2_USERAUTH_KBDINT_PROMPT] = []
      for i in buffers.indices {
        let pointer = buffers[i].withUnsafeMutableBufferPointer { $0.baseAddress }
        cPrompts.append(
          LIBSSH2_USERAUTH_KBDINT_PROMPT(text: pointer, length: buffers[i].count, echo: prompts[i].echo ? 1 : 0))
      }
      var responses = [LIBSSH2_USERAUTH_KBDINT_RESPONSE](
        repeating: LIBSSH2_USERAUTH_KBDINT_RESPONSE(text: nil, length: 99), count: prompts.count)
      keyboardInteractiveCallback(nil, 0, nil, 0, Int32(prompts.count), cPrompts, &responses, &abstract)
      return responses.map { response in
        guard let text = response.text else {
          #expect(response.length == 0)
          return nil
        }
        defer { free(text) }
        return String(
          decoding: UnsafeBufferPointer(start: UnsafeRawPointer(text).assumingMemoryBound(to: UInt8.self), count: Int(response.length)),
          as: UTF8.self)
      }
    }
  }

  @Test(arguments: ["Password:", "alice@example.com's password: ", "(alice@host) Password: ", "Passwort: ", "Пароль: "])
  func aPasswordPromptGetsThePassword(prompt: String) {
    #expect(answers([(prompt, false)]) == ["hunter2"])
  }

  @Test(arguments: [
    "Verification code: ", "One-time password: ", "OTP: ", "Authenticator token: ", "Your mother's maiden name: ",
    "New password: ", "Retype new password: ", "PIN: ", "Duo passcode: ",
  ])
  func anyOtherPromptGetsNothing(prompt: String) {
    #expect(answers([(prompt, false)]) == [nil])
  }

  @Test func aPromptThatShowsWhatsTypedGetsNothing() {
    #expect(answers([("Password: ", true)]) == [nil])
  }

  @Test func onlyThePasswordPromptInARoundIsAnswered() {
    #expect(answers([("Password: ", false), ("Verification code: ", false)]) == ["hunter2", nil])
  }
}
