package net.sf.mmm.security.impl.random;

import java.security.Provider;
import java.security.SecureRandom;

import net.sf.mmm.security.api.random.SecurityRandomConfig;
import net.sf.mmm.security.api.random.SecurityRandomCreator;
import net.sf.mmm.security.api.random.SecurityRandomFactory;
import net.sf.mmm.security.impl.AbstractSecurityAlgorithmWithProvider;

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
   * @param provider the {@link Provider} to use.
   */
  public SecurityRandomFactoryImpl(SecurityRandomConfig config, Provider provider) {
    super(provider);
    this.config = config;
  }

  @Override
  public String getAlgorithm() {

    return this.config.getAlgorithm();
  }

  @Override
  public SecurityRandomCreator newRandomCreator() {

    return new SecurityRandomGeneratorImpl(newSecureRandom(), this.config.getReseedCount());
  }

  @Override
  public SecureRandom newSecureRandom() {

    try {
      Provider provider = getProvider();
      if (provider == null) {
        return SecureRandom.getInstance(getAlgorithm());
      } else {
        return SecureRandom.getInstance(getAlgorithm(), provider);
      }
    } catch (Exception e) {
      throw creationFailedException(e, SecureRandom.class);
    }
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
            SecurityRandomConfig configuration = new SecurityRandomConfig(sample.getAlgorithm());
            STRONG_INSTANCE = new SecurityRandomFactoryImpl(configuration, provider);
          } catch (Exception e) {
            throw new IllegalStateException("No implementation of strong SecureRandom available!", e);
          }
        }
      }
    }
    return STRONG_INSTANCE;
  }

}
