package net.sf.mmm.security.impl.hash;

import java.security.Provider;

import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.hash.SecurityHashCreator;
import net.sf.mmm.security.api.hash.SecurityHashFactory;
import net.sf.mmm.security.impl.AbstractSecurityAlgorithmWithProvider;

/**
 * The implementation of {@link SecurityHashFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityHashFactoryImpl extends AbstractSecurityAlgorithmWithProvider implements SecurityHashFactory {

  private final SecurityHashConfig config;

  /**
   * The constructor.
   *
   * @param config the {@link SecurityHashConfig}.
   * @param provider the security {@link Provider} to use.
   */
  public SecurityHashFactoryImpl(SecurityHashConfig config, Provider provider) {
    super(provider);
    this.config = config;
  }

  @Override
  public String getAlgorithm() {

    return this.config.getAlgorithm();
  }

  @Override
  public SecurityHashCreator newHashCreator() {

    int iterationCount = this.config.getIterationCount();
    if (iterationCount <= 1) {
      return new SecurityHashCreatorImplDigest(getAlgorithm(), getProvider());
    } else {
      return new SecurityHashCreatorImplMultipleRounds(getAlgorithm(), getProvider(), iterationCount);
    }
  }

  @Override
  public String toString() {

    int iterationCount = this.config.getIterationCount();
    if (iterationCount <= 1) {
      return getAlgorithm();
    } else {
      return getAlgorithm() + " (" + iterationCount + "x)";
    }
  }

}
