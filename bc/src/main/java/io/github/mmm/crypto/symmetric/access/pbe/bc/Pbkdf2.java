package io.github.mmm.crypto.symmetric.access.pbe.bc;

import io.github.mmm.crypto.provider.bc.BouncyCastle;
import io.github.mmm.crypto.symmetric.access.pbe.PbeAccess;
import io.github.mmm.crypto.symmetric.crypt.SymmetricCryptorConfig;
import io.github.mmm.crypto.symmetric.crypt.aes.SymmetricCryptorConfigAes;
import io.github.mmm.crypto.symmetric.key.pbe.SymmetricKeyConfigPbe;

/// [PbeAccess] for <a href="https://en.wikipedia.org/wiki/PBKDF2">PBKDF2</a> (Password-Based Key Derivation
/// Function 2) from _PKCS #5 v2.0_.
///
/// @since 1.0.0
public class Pbkdf2 extends PbeAccess {

  static final SymmetricCryptorConfigAes CRYPTOR_CONFIG_AES = new SymmetricCryptorConfigAes(
      BouncyCastle.getSecurityProvider());

  /// The constructor.
  ///
  /// @param keyConfig the [SymmetricKeyConfigPbe].
  Pbkdf2(SymmetricKeyConfigPbe keyConfig) {

    super(keyConfig, CRYPTOR_CONFIG_AES);
  }

  /// The constructor.
  ///
  /// @param keyConfig the [SymmetricKeyConfigPbe].
  /// @param cryptorConfig the [SymmetricCryptorConfig].
  Pbkdf2(SymmetricKeyConfigPbe keyConfig, SymmetricCryptorConfig cryptorConfig) {

    super(keyConfig, cryptorConfig);
  }

  /// The constructor.
  ///
  /// @param keyAlgorithm the [key algorithm][SymmetricKeyConfigPbe#getAlgorithm()].
  /// @param keyLength the [key-length][#getKeyLength()].
  Pbkdf2(String keyAlgorithm, int keyLength) {

    this(keyAlgorithm, keyLength, CRYPTOR_CONFIG_AES);
  }

  /// The constructor.
  ///
  /// @param keyAlgorithm the [key algorithm][SymmetricKeyConfigPbe#getAlgorithm()].
  /// @param keyLength the [key-length][#getKeyLength()].
  /// @param cryptorConfig the [SymmetricCryptorConfig].
  Pbkdf2(String keyAlgorithm, int keyLength, SymmetricCryptorConfig cryptorConfig) {

    super(new SymmetricKeyConfigPbe(keyAlgorithm, BouncyCastle.getSecurityProvider(), keyLength), cryptorConfig);
  }

}
