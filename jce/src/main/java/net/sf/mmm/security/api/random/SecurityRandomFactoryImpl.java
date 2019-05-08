package net.sf.mmm.security.api.random;

import java.security.Provider;
import java.security.SecureRandom;

import net.sf.mmm.security.api.AbstractSecurityAlgorithmWithProvider;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * Implementation of {@link SecurityRandomFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityRandomFactoryImpl extends AbstractSecurityAlgorithmWithProvider implements SecurityRandomFactory {

  private static SecurityRandomFactoryImpl STRONG_INSTANCE;

  private final SecurityRandomConfig config;

  /**
   * The constructor.
   *
   * @param config the {@link SecurityRandomConfig}.
   */
  public SecurityRandomFactoryImpl(SecurityRandomConfig config) {

    super(config.getProvider());
    this.config = config;
  }

  @Override
  public String getAlgorithm() {

    return this.config.getAlgorithm();
  }

  @Override
  public SecurityRandomCreator newRandomCreator() {

    return new SecurityRandomCreatorImpl(newSecureRandom(), this.config.getReseedCount());
  }

  @Override
  public SecureRandom newSecureRandom() {

    return this.provider.createSecureRandom(getAlgorithm());
  }

  /**
   * @return {@link SecurityRandomFactoryImpl} for {@link SecureRandom#getInstanceStrong()}.
   */
  public static SecurityRandomFactoryImpl ofStrong() {

    if (STRONG_INSTANCE == null) {
      synchronized (SecurityRandomFactoryImpl.class) {
        if (STRONG_INSTANCE == null) {
          try {
            SecureRandom sample = SecureRandom.getInstanceStrong();
            Provider provider = sample.getProvider();
            SecurityRandomConfig configuration = new SecurityRandomConfig(sample.getAlgorithm(), SecurityProvider.of(provider));
            STRONG_INSTANCE = new SecurityRandomFactoryImpl(configuration);
          } catch (Exception e) {
            throw new IllegalStateException("No implementation of strong SecureRandom available!", e);
          }
        }
      }
    }
    return STRONG_INSTANCE;
  }

}
