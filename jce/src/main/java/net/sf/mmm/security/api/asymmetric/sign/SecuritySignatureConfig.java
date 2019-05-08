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
   * @param hashConfig the {@link SecurityHashConfig} to be used as {@link #getHashConfig() pre-hashing config}.
   * @param signingAlgorithm the {@link SecuritySignatureAlgorithm#getSigningAlgorithm() signing algorithm}.
   * @param hashAlgorithm the {@link SecuritySignatureAlgorithm#getHashAlgorithm() hash algorithm}.
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
   * @param hashConfig the {@link SecurityHashConfig}. The {@link #getHashConfig() pre-hashing config} will be set to
   *        {@link SecurityHashConfig#decrementIterationCount()}.
   * @param signingAlgorithm the {@link SecuritySignatureAlgorithm#getSigningAlgorithm() signing algorithm}.
   * @param provider the {@link #getProvider() provider}.
   */
  public SecuritySignatureConfig(SecuritySignatureFactory<S> signatureFactory, SecurityHashConfig hashConfig, String signingAlgorithm,
      SecurityProvider provider) {

    this(signatureFactory, SecuritySignatureAlgorithm.of(hashConfig.getAlgorithm(), signingAlgorithm), hashConfig.decrementIterationCount(),
        provider);
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
   * @return the optional {@link SecurityHashConfig} used for pre-hashing. If not {@code null} the data to sign will be
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

}
