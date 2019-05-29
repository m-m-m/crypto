package net.sf.mmm.crypto.asymmetric.sign;

import net.sf.mmm.crypto.algorithm.CryptoAlgorithmConfig;
import net.sf.mmm.crypto.hash.HashConfig;
import net.sf.mmm.crypto.provider.SecurityProvider;

/**
 * {@link CryptoAlgorithmConfig} for {@link SignatureSigner#sign(byte[], boolean) signing}.
 *
 * @param <S> type of {@link SignatureBinary}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SignatureConfig<S extends SignatureBinary> extends CryptoAlgorithmConfig {

  private final HashConfig hashConfig;

  private final SignatureFactory<S> signatureFactory;

  private final SignatureAlgorithm signatureAlgorithm;

  /**
   * The constructor.
   *
   * @param signatureFactory the {@link #getSignatureFactory() signature factory}.
   * @param hashConfig the {@link HashConfig} used to calculate the hash that is the signed.
   * @param signingAlgorithm the {@link SignatureAlgorithm#getSigningAlgorithm() signing algorithm}.
   * @param hashAlgorithm the {@link SignatureAlgorithm#getHashAlgorithm() hash algorithm} used by the signing
   *        algorithm (e.g. for HMac).
   * @param provider the {@link #getProvider() provider}.
   */
  public SignatureConfig(SignatureFactory<S> signatureFactory, HashConfig hashConfig, String signingAlgorithm,
      String hashAlgorithm, SecurityProvider provider) {

    this(signatureFactory, SignatureAlgorithm.of(hashAlgorithm, signingAlgorithm), hashConfig, provider);
  }

  /**
   * The constructor.
   *
   * @param signatureFactory the {@link #getSignatureFactory() signature factory}.
   * @param hashConfig the {@link HashConfig} used to calculate the hash that is the signed.
   * @param signingAlgorithm the {@link SignatureAlgorithm#getSigningAlgorithm() signing algorithm}.
   * @param provider the {@link #getProvider() provider}.
   */
  public SignatureConfig(SignatureFactory<S> signatureFactory, HashConfig hashConfig, String signingAlgorithm,
      SecurityProvider provider) {

    this(signatureFactory, SignatureAlgorithm.of(hashConfig.getAlgorithm(), signingAlgorithm), hashConfig, provider);
  }

  private SignatureConfig(SignatureFactory<S> signatureFactory, SignatureAlgorithm signatureAlgorithm,
      HashConfig hashConfig, SecurityProvider provider) {

    super(signatureAlgorithm.getAlgorithm(), provider);
    this.signatureFactory = signatureFactory;
    this.hashConfig = hashConfig;
    this.signatureAlgorithm = signatureAlgorithm;
  }

  /**
   * @return the structured {@link SignatureAlgorithm}.
   */
  public SignatureAlgorithm getSignatureAlgorithm() {

    return this.signatureAlgorithm;
  }

  /**
   * @return the optional {@link HashConfig} used for hashing. If not {@code null} the data to sign will be
   *         first hashed using this configuration and the resulting hash will then be signed using
   *         {@link #getSignatureAlgorithm() signature algorithm}.
   */
  public HashConfig getHashConfig() {

    return this.hashConfig;
  }

  /**
   * @return the {@link SignatureFactory}.
   */
  public SignatureFactory<S> getSignatureFactory() {

    return this.signatureFactory;
  }

  /**
   * @return a copy of this {@link SignatureConfig} without {@link #getHashConfig() hash config} (set to
   *         {@code null}).
   */
  public SignatureConfig<S> withoutHashConfig() {

    if (this.hashConfig == null) {
      return this;
    }
    return new SignatureConfig<>(this.signatureFactory, this.signatureAlgorithm, null, this.provider);
  }

}
