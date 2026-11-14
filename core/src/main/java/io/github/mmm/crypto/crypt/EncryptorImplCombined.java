package io.github.mmm.crypto.crypt;

/// Implementation of [Encryptor] that combines multiple [Encryptor]s.
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class EncryptorImplCombined extends CryptorImplCombined implements AbstractEncryptor {

  /// The constructor.
  ///
  /// @param encryptors the [Encryptor]s to combine.
  public EncryptorImplCombined(Encryptor[] encryptors) {
    super(encryptors);
  }

}
