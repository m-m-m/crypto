package net.sf.mmm.security.api.hash.access;

import net.sf.mmm.security.api.SecurityAccess;
import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.hash.SecurityHashCreator;
import net.sf.mmm.security.api.hash.SecurityHashCreatorImplDigest;
import net.sf.mmm.security.api.hash.SecurityHashCreatorImplMultipleRounds;
import net.sf.mmm.security.api.hash.SecurityHashFactory;

/**
 * {@link SecurityAccess} for {@link SecurityHashFactory}.
 *
 * @since 1.0.0
 */
public class SecurityAccessHash extends SecurityAccess implements SecurityHashFactory {

  private final SecurityHashConfig config;

  /**
   * The constructor.
   *
   * @param config the {@link SecurityHashConfig}.
   */
  public SecurityAccessHash(SecurityHashConfig config) {

    super();
    if (config.getIterationCount() <= 0) {
      throw new IllegalArgumentException("config.iterationCount=" + config.getIterationCount());
    }
    this.config = config;
  }

  @Override
  public SecurityHashCreator newHashCreator() {

    int iterationCount = this.config.getIterationCount();
    if (iterationCount <= 1) {
      return new SecurityHashCreatorImplDigest(this.config.getAlgorithm(), this.config.getProvider());
    } else {
      return new SecurityHashCreatorImplMultipleRounds(this.config.getAlgorithm(), this.config.getProvider(), iterationCount);
    }
  }

  @Override
  public String toString() {

    return this.config.getAlgorithm();
  }

  /**
   * @param config the {@link SecurityHashConfig}.
   * @return the {@link SecurityAccessHash}.
   */
  public static SecurityAccessHash of(SecurityHashConfig config) {

    return new SecurityAccessHash(config);
  }

}
