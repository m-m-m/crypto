package io.github.mmm.crypto.random;

import java.security.Provider;
import java.security.SecureRandom;

import io.github.mmm.crypto.algorithm.AbstractCryptoAlgorithmWithProvider;
import io.github.mmm.crypto.provider.SecurityProvider;

/**
 * Implementation of {@link RandomFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class RandomFactoryImpl extends AbstractCryptoAlgorithmWithProvider implements RandomFactory {

  private static RandomFactoryImpl STRONG_INSTANCE;

  private final RandomConfig config;

  /**
   * The constructor.
   *
   * @param config the {@link RandomConfig}.
   */
  public RandomFactoryImpl(RandomConfig config) {

    super(config.getProvider());
    this.config = config;
  }

  @Override
  public String getAlgorithm() {

    return this.config.getAlgorithm();
  }

  @Override
  public RandomCreator newRandomCreator() {

    return new RandomCreatorImpl(newSecureRandom(), this.config.getReseedCount());
  }

  @Override
  public SecureRandom newSecureRandom() {

    return this.provider.createSecureRandom(getAlgorithm());
  }

  /**
   * @return {@link RandomFactoryImpl} for {@link SecureRandom#getInstanceStrong()}.
   */
  public static RandomFactoryImpl ofStrong() {

    if (STRONG_INSTANCE == null) {
      synchronized (RandomFactoryImpl.class) {
        if (STRONG_INSTANCE == null) {
          try {
            SecureRandom sample = SecureRandom.getInstanceStrong();
            Provider provider = sample.getProvider();
            RandomConfig configuration = new RandomConfig(sample.getAlgorithm(), SecurityProvider.of(provider));
            STRONG_INSTANCE = new RandomFactoryImpl(configuration);
          } catch (Exception e) {
            throw new IllegalStateException("No implementation of strong SecureRandom available!", e);
          }
        }
      }
    }
    return STRONG_INSTANCE;
  }

}
