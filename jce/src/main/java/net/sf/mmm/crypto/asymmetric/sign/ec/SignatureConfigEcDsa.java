package net.sf.mmm.crypto.asymmetric.sign.ec;

import net.sf.mmm.crypto.asymmetric.sign.SignatureAlgorithm;
import net.sf.mmm.crypto.asymmetric.sign.SignatureBinary;
import net.sf.mmm.crypto.asymmetric.sign.SignatureConfig;
import net.sf.mmm.crypto.asymmetric.sign.SignatureFactory;
import net.sf.mmm.crypto.hash.HashConfig;
import net.sf.mmm.crypto.provider.SecurityProvider;

/**
 * {@link SignatureConfig} for {@link net.sf.mmm.crypto.asymmetric.access.rsa.Rsa}.
 *
 * @param <S> type of {@link SignatureBinary}.
 * @since 1.0.0
 */
public class SignatureConfigEcDsa<S extends SignatureBinary> extends SignatureConfig<S> {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  public static final String ALGORITHM_ECDSA = "ECDSA";

  /**
   * The constructor.
   *
   * @param signatureFactory the {@link #getSignatureFactory() signature factory}.
   * @param hashConfig the {@link HashConfig} to be used as {@link #getHashConfig() hashing config}.
   * @param provider the {@link #getProvider() provider}.
   */
  public SignatureConfigEcDsa(SignatureFactory<S> signatureFactory, HashConfig hashConfig, SecurityProvider provider) {

    super(signatureFactory, hashConfig, ALGORITHM_ECDSA, provider);
  }

  /**
   * The constructor.
   *
   * @param signatureFactory the {@link #getSignatureFactory() signature factory}.
   * @param hashConfig the {@link HashConfig} to be used as {@link #getHashConfig() hashing config}.
   * @param hashAlgorithm the {@link SignatureAlgorithm#getHashAlgorithm() hash algorithm}.
   * @param provider the {@link #getProvider() provider}.
   */
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
