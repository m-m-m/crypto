package net.sf.mmm.security.api.asymmetric.sign;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmConfig;
import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecurityAlgorithmConfig} for {@link SecuritySignatureSigner#sign(byte[], boolean) signing}.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureConfig<S extends SecuritySignature> extends SecurityAlgorithmConfig {

  private final SecurityHashConfig hashConfig;

  private final SecuritySignatureFactory<S> signatureFactory;

  private final SecuritySignatureAlgorithm signatureAlgorithm;

  /**
   * The constructor.
   *
   * @param signatureFactory the {@link #getSignatureFactory() signature factory}.
   * @param hashConfig the {@link SecurityHashConfig} used to calculate the hash that is the signed.
   * @param signingAlgorithm the {@link SecuritySignatureAlgorithm#getSigningAlgorithm() signing algorithm}.
   * @param hashAlgorithm the {@link SecuritySignatureAlgorithm#getHashAlgorithm() hash algorithm} used by the signing
   *        algorithm (e.g. for HMac).
   * @param provider the {@link #getProvider() provider}.
   */
  public SecuritySignatureConfig(SecuritySignatureFactory<S> signatureFactory, SecurityHashConfig hashConfig, String signingAlgorithm,
      String hashAlgorithm, SecurityProvider provider) {

    this(signatureFactory, SecuritySignatureAlgorithm.of(hashAlgorithm, signingAlgorithm), hashConfig, provider);
  }

  /**
   * The constructor.
   *
   * @param signatureFactory the {@link #getSignatureFactory() signature factory}.
   * @param hashConfig the {@link SecurityHashConfig} used to calculate the hash that is the signed.
   * @param signingAlgorithm the {@link SecuritySignatureAlgorithm#getSigningAlgorithm() signing algorithm}.
   * @param provider the {@link #getProvider() provider}.
   */
  public SecuritySignatureConfig(SecuritySignatureFactory<S> signatureFactory, SecurityHashConfig hashConfig, String signingAlgorithm,
      SecurityProvider provider) {

    this(signatureFactory, SecuritySignatureAlgorithm.of(hashConfig.getAlgorithm(), signingAlgorithm), hashConfig, provider);
  }

  private SecuritySignatureConfig(SecuritySignatureFactory<S> signatureFactory, SecuritySignatureAlgorithm signatureAlgorithm,
      SecurityHashConfig hashConfig, SecurityProvider provider) {

    super(signatureAlgorithm.getAlgorithm(), provider);
    this.signatureFactory = signatureFactory;
    this.hashConfig = hashConfig;
    this.signatureAlgorithm = signatureAlgorithm;
  }

  /**
   * @return the structured {@link SecuritySignatureAlgorithm}.
   */
  public SecuritySignatureAlgorithm getSignatureAlgorithm() {

    return this.signatureAlgorithm;
  }

  /**
   * @return the optional {@link SecurityHashConfig} used for hashing. If not {@code null} the data to sign will be
   *         first hashed using this configuration and the resulting hash will then be signed using
   *         {@link #getSignatureAlgorithm() signature algorithm}.
   */
  public SecurityHashConfig getHashConfig() {

    return this.hashConfig;
  }

  /**
   * @return the {@link SecuritySignatureFactory}.
   */
  public SecuritySignatureFactory<S> getSignatureFactory() {

    return this.signatureFactory;
  }

  /**
   * @return a copy of this {@link SecuritySignatureConfig} without {@link #getHashConfig() hash config} (set to
   *         {@code null}).
   */
  public SecuritySignatureConfig<S> withoutHashConfig() {

    if (this.hashConfig == null) {
      return this;
    }
    return new SecuritySignatureConfig<>(this.signatureFactory, this.signatureAlgorithm, null, this.provider);
  }

}
