package net.sf.mmm.security.api.symmetric.access.pbe;

import net.sf.mmm.security.api.symmetric.crypt.SecuritySymmetricCryptorConfig;

/**
 * {@link Pbkdf2} with {@link net.sf.mmm.security.api.hash.sha2.Sha384} as HMac.
 *
 * @since 1.0.0
 */
public class Pbkdf2WithHmacSha384 extends Pbkdf2 {

  /** The {@link net.sf.mmm.security.api.algorithm.SecurityAlgorithm#getAlgorithm() algorithm} name {@value}. */
  public static final String ALGORITHM_PBKDF2_WITH_HMAC_SHA384 = "PBKDF2WithHmacSHA384";

  /**
   * The constructor.
   *
   * @param keyLength the {@link #getKeyLength() key length}.
   * @param cryptorConfig the {@link SecuritySymmetricCryptorConfig}.
   */
  public Pbkdf2WithHmacSha384(int keyLength, SecuritySymmetricCryptorConfig cryptorConfig) {

    super(ALGORITHM_PBKDF2_WITH_HMAC_SHA384, keyLength, cryptorConfig);
  }

  /**
   * The constructor.
   *
   * @param keyLength the {@link #getKeyLength() key length}.
   */
  public Pbkdf2WithHmacSha384(int keyLength) {

    super(ALGORITHM_PBKDF2_WITH_HMAC_SHA384, keyLength);
  }

  /**
   * @return instance of {@link Pbkdf2WithHmacSha384} with a {@link #getKeyLength() key length} of {@code 256} bit.
   */
  public static Pbkdf2WithHmacSha384 of256() {

    return of(256);
  }

  /**
   * @param keyLength the {@link #getKeyLength() key length}.
   * @return the {@link Pbkdf2WithHmacSha384} with the given key length.
   */
  public static Pbkdf2WithHmacSha384 of(int keyLength) {

    return new Pbkdf2WithHmacSha384(keyLength);
  }

}
