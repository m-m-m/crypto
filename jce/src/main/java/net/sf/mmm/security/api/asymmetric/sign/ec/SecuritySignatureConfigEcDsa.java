package net.sf.mmm.security.api.asymmetric.sign.ec;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmRsa;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignature;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureAlgorithm;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureConfig;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureFactory;
import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecuritySignatureConfig} for {@link SecurityAlgorithmRsa RSA}.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @since 1.0.0
 */
public class SecuritySignatureConfigEcDsa<S extends SecuritySignature> extends SecuritySignatureConfig<S> {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  public static final String ALGORITHM_ECDSA = "ECDSA";

  /**
   * The constructor.
   *
   * @param signatureFactory the {@link #getSignatureFactory() signature factory}.
   * @param hashConfig the {@link SecurityHashConfig} to be used as {@link #getHashConfig() hashing config}.
   * @param provider the {@link #getProvider() provider}.
   */
  public SecuritySignatureConfigEcDsa(SecuritySignatureFactory<S> signatureFactory, SecurityHashConfig hashConfig,
      SecurityProvider provider) {

    super(signatureFactory, hashConfig, ALGORITHM_ECDSA, provider);
  }

  /**
   * The constructor.
   *
   * @param signatureFactory the {@link #getSignatureFactory() signature factory}.
   * @param hashConfig the {@link SecurityHashConfig} to be used as {@link #getHashConfig() hashing config}.
   * @param hashAlgorithm the {@link SecuritySignatureAlgorithm#getHashAlgorithm() hash algorithm}.
   * @param provider the {@link #getProvider() provider}.
   */
  public SecuritySignatureConfigEcDsa(SecuritySignatureFactory<S> signatureFactory, SecurityHashConfig hashConfig, String hashAlgorithm,
      SecurityProvider provider) {

    super(signatureFactory, hashConfig, ALGORITHM_ECDSA, hashAlgorithm, provider);
  }

  @Override
  public SecuritySignatureConfigEcDsa<S> withoutHashConfig() {

    if (getHashConfig() == null) {
      return this;
    }
    return new SecuritySignatureConfigEcDsa<>(getSignatureFactory(), null, getSignatureAlgorithm().getHashAlgorithm(), getProvider());
  }

}
