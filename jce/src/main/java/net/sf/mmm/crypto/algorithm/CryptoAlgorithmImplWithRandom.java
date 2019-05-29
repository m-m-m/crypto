package net.sf.mmm.crypto.algorithm;

import java.security.Provider;
import java.security.SecureRandom;

import net.sf.mmm.crypto.provider.SecurityProvider;
import net.sf.mmm.crypto.random.RandomFactory;
import net.sf.mmm.crypto.random.RandomFactoryImpl;

/**
 * Extends {@link CryptoAlgorithmImpl} with ability to create
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class CryptoAlgorithmImplWithRandom extends CryptoAlgorithmImpl {

  private final RandomFactory randomFactory;

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param provider the security {@link Provider}.
   * @param randomFactory the {@link RandomFactory} to use.
   */
  public CryptoAlgorithmImplWithRandom(String algorithm, SecurityProvider provider, RandomFactory randomFactory) {

    super(algorithm, provider);
    if (randomFactory == null) {
      this.randomFactory = RandomFactoryImpl.ofStrong();
    } else {
      this.randomFactory = randomFactory;
    }
  }

  /**
   * @return the {@link RandomFactory}.
   */
  protected RandomFactory getRandomFactory() {

    return this.randomFactory;
  }

  /**
   * @return a new {@link SecureRandom}.
   * @see RandomFactory#newSecureRandom()
   */
  protected SecureRandom createSecureRandom() {

    return this.randomFactory.newSecureRandom();
  }
}
