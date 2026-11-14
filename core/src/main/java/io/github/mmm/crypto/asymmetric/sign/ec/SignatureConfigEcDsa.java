package io.github.mmm.crypto.asymmetric.sign.ec;

import io.github.mmm.crypto.asymmetric.sign.SignatureAlgorithm;
import io.github.mmm.crypto.asymmetric.sign.SignatureBinary;
import io.github.mmm.crypto.asymmetric.sign.SignatureConfig;
import io.github.mmm.crypto.asymmetric.sign.SignatureFactory;
import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/// [SignatureConfig] for [io.github.mmm.crypto.asymmetric.access.rsa.Rsa].
///
/// @param <S> type of [SignatureBinary].
/// @since 1.0.0
public class SignatureConfigEcDsa<S extends SignatureBinary> extends SignatureConfig<S> {

  /// The [algorithm][#getAlgorithm()] name {@value}.
  public static final String ALGORITHM_ECDSA = "ECDSA";

  /// The constructor.
  ///
  /// @param signatureFactory the [signature factory][#getSignatureFactory()].
  /// @param hashConfig the [HashConfig] to be used as [hashing config][#getHashConfig()].
  /// @param provider the [provider][#getProvider()].
  public SignatureConfigEcDsa(SignatureFactory<S> signatureFactory, HashConfig hashConfig, SecurityProvider provider) {

    super(signatureFactory, hashConfig, ALGORITHM_ECDSA, provider);
  }

  /// The constructor.
  ///
  /// @param signatureFactory the [signature factory][#getSignatureFactory()].
  /// @param hashConfig the [HashConfig] to be used as [hashing config][#getHashConfig()].
  /// @param hashAlgorithm the [hash algorithm][SignatureAlgorithm#getHashAlgorithm()].
  /// @param provider the [provider][#getProvider()].
  public SignatureConfigEcDsa(SignatureFactory<S> signatureFactory, HashConfig hashConfig, String hashAlgorithm,
      SecurityProvider provider) {

    super(signatureFactory, hashConfig, ALGORITHM_ECDSA, hashAlgorithm, provider);
  }

  @Override
  public SignatureConfigEcDsa<S> withoutHashConfig() {

    if (getHashConfig() == null) {
      return this;
    }
    return new SignatureConfigEcDsa<>(getSignatureFactory(), null, getSignatureAlgorithm().getHashAlgorithm(), getProvider());
  }

}
