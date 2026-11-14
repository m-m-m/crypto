package io.github.mmm.crypto.asymmetric.sign;

import io.github.mmm.crypto.algorithm.CryptoAlgorithmConfig;
import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/// [CryptoAlgorithmConfig] for [signing][SignatureSigner#sign(byte[], boolean)].
///
/// @param <S> type of [SignatureBinary].
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class SignatureConfig<S extends SignatureBinary> extends CryptoAlgorithmConfig {

  private final HashConfig hashConfig;

  private final SignatureFactory<S> signatureFactory;

  private final SignatureAlgorithm signatureAlgorithm;

  /// The constructor.
  ///
  /// @param signatureFactory the [signature factory][#getSignatureFactory()].
  /// @param hashConfig the [HashConfig] used to calculate the hash that is the signed.
  /// @param signingAlgorithm the [signing algorithm][SignatureAlgorithm#getSigningAlgorithm()].
  /// @param hashAlgorithm the [hash algorithm][SignatureAlgorithm#getHashAlgorithm()] used by the signing
  ///        algorithm (e.g. for HMac).
  /// @param provider the [provider][#getProvider()].
  public SignatureConfig(SignatureFactory<S> signatureFactory, HashConfig hashConfig, String signingAlgorithm,
      String hashAlgorithm, SecurityProvider provider) {

    this(signatureFactory, SignatureAlgorithm.of(hashAlgorithm, signingAlgorithm), hashConfig, provider);
  }

  /// The constructor.
  ///
  /// @param signatureFactory the [signature factory][#getSignatureFactory()].
  /// @param hashConfig the [HashConfig] used to calculate the hash that is the signed.
  /// @param signingAlgorithm the [signing algorithm][SignatureAlgorithm#getSigningAlgorithm()].
  /// @param provider the [provider][#getProvider()].
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

  /// @return the structured [SignatureAlgorithm].
  public SignatureAlgorithm getSignatureAlgorithm() {

    return this.signatureAlgorithm;
  }

  /// @return the optional [HashConfig] used for hashing. If not `null` the data to sign will be
  ///         first hashed using this configuration and the resulting hash will then be signed using
  ///         [signature algorithm][#getSignatureAlgorithm()].
  public HashConfig getHashConfig() {

    return this.hashConfig;
  }

  /// @return the [SignatureFactory].
  public SignatureFactory<S> getSignatureFactory() {

    return this.signatureFactory;
  }

  /// @return a copy of this [SignatureConfig] without [hash config][#getHashConfig()] (set to
  ///         `null`).
  public SignatureConfig<S> withoutHashConfig() {

    if (this.hashConfig == null) {
      return this;
    }
    return new SignatureConfig<>(this.signatureFactory, this.signatureAlgorithm, null, this.provider);
  }

}
