package io.github.mmm.crypto.symmetric.access.pbe.bc;

import io.github.mmm.crypto.symmetric.crypt.SymmetricCryptorConfig;

/// [Pbkdf2] with [io.github.mmm.crypto.hash.sha2.Sha224] as HMac.
///
/// @since 1.0.0
public class Pbkdf2WithHmacSha224 extends Pbkdf2 {

  /// The [algorithm][io.github.mmm.crypto.algorithm.CryptoAlgorithm#getAlgorithm()] name {@value}.
  public static final String ALGORITHM_PBKDF2_WITH_HMAC_SHA224 = "PBKDF2WithHmacSHA224";

  /// The constructor.
  ///
  /// @param keyLength the [key length][#getKeyLength()].
  /// @param cryptorConfig the [SymmetricCryptorConfig].
  public Pbkdf2WithHmacSha224(int keyLength, SymmetricCryptorConfig cryptorConfig) {

    super(ALGORITHM_PBKDF2_WITH_HMAC_SHA224, keyLength, cryptorConfig);
  }

  /// The constructor.
  ///
  /// @param keyLength the [key length][#getKeyLength()].
  public Pbkdf2WithHmacSha224(int keyLength) {

    super(ALGORITHM_PBKDF2_WITH_HMAC_SHA224, keyLength);
  }

  /// @return instance of [Pbkdf2WithHmacSha224] with a [key length][#getKeyLength()] of `256` bit.
  public static Pbkdf2WithHmacSha224 of256() {

    return of(256);
  }

  /// @param keyLength the [key length][#getKeyLength()].
  /// @return the [Pbkdf2WithHmacSha224] with the given key length.
  public static Pbkdf2WithHmacSha224 of(int keyLength) {

    return new Pbkdf2WithHmacSha224(keyLength);
  }

}
