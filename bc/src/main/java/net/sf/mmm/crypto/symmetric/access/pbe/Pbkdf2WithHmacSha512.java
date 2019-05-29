package net.sf.mmm.crypto.symmetric.access.pbe;

import net.sf.mmm.crypto.symmetric.crypt.SymmetricCryptorConfig;

/**
 * {@link Pbkdf2} with {@link net.sf.mmm.crypto.hash.sha2.Sha512} as HMac.
 *
 * @since 1.0.0
 */
public class Pbkdf2WithHmacSha512 extends Pbkdf2 {

  /** The {@link net.sf.mmm.crypto.algorithm.CryptoAlgorithm#getAlgorithm() algorithm} name {@value}. */
  public static final String ALGORITHM_PBKDF2_WITH_HMAC_SHA512 = "PBKDF2WithHmacSHA512";

  /**
   * The constructor.
   *
   * @param keyLength the {@link #getKeyLength() key length}.
   * @param cryptorConfig the {@link SymmetricCryptorConfig}.
   */
  public Pbkdf2WithHmacSha512(int keyLength, SymmetricCryptorConfig cryptorConfig) {

    super(ALGORITHM_PBKDF2_WITH_HMAC_SHA512, keyLength, cryptorConfig);
  }

  /**
   * The constructor.
   *
   * @param keyLength the {@link #getKeyLength() key length}.
   */
  public Pbkdf2WithHmacSha512(int keyLength) {

    super(ALGORITHM_PBKDF2_WITH_HMAC_SHA512, keyLength);
  }

  /**
   * @return instance of {@link Pbkdf2WithHmacSha512} with a {@link #getKeyLength() key length} of {@code 256} bit.
   */
  public static Pbkdf2WithHmacSha512 of256() {

    return of(256);
  }

  /**
   * @param keyLength the {@link #getKeyLength() key length}.
   * @return the {@link Pbkdf2WithHmacSha512} with the given key length.
   */
  public static Pbkdf2WithHmacSha512 of(int keyLength) {

    return new Pbkdf2WithHmacSha512(keyLength);
  }

}
