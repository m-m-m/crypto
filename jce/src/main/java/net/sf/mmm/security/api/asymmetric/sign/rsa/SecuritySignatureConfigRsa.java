package net.sf.mmm.security.api.asymmetric.sign.rsa;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmRsa;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureAlgorithm;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureConfig;
import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecuritySignatureConfig} for {@link SecurityAlgorithmRsa RSA}.
 *
 * @since 1.0.0
 */
public class SecuritySignatureConfigRsa extends SecuritySignatureConfig<SecuritySignatureRsa> {

  /**
   * The constructor.
   *
   * @param hashConfig the {@link SecurityHashConfig} to be used as {@link #getHashConfig() hashing config}.
   * @param provider the {@link #getProvider() provider}.
   */
  public SecuritySignatureConfigRsa(SecurityHashConfig hashConfig, SecurityProvider provider) {

    super(SecuritySignatureFactoryRsa.get(), hashConfig, SecurityAlgorithmRsa.ALGORITHM_RSA, provider);
  }

  /**
   * The constructor.
   *
   * @param hashConfig the {@link SecurityHashConfig} to be used as {@link #getHashConfig() hashing config}.
   * @param hashAlgorithm the {@link SecuritySignatureAlgorithm#getHashAlgorithm() hash algorithm}.
   * @param provider the {@link #getProvider() provider}.
   */
  public SecuritySignatureConfigRsa(SecurityHashConfig hashConfig, String hashAlgorithm, SecurityProvider provider) {

    super(SecuritySignatureFactoryRsa.get(), hashConfig, SecurityAlgorithmRsa.ALGORITHM_RSA, hashAlgorithm, provider);
  }

  @Override
  public SecuritySignatureConfigRsa withoutHashConfig() {

    if (getHashConfig() == null) {
      return this;
    }
    return new SecuritySignatureConfigRsa(null, getSignatureAlgorithm().getHashAlgorithm(), getProvider());
  }

}
