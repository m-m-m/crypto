package net.sf.mmm.crypto.asymmetric.sign.rsa;

import net.sf.mmm.crypto.asymmetric.key.rsa.AsymmetricKeyPairRsa;
import net.sf.mmm.crypto.asymmetric.sign.SignatureAlgorithm;
import net.sf.mmm.crypto.asymmetric.sign.SignatureConfig;
import net.sf.mmm.crypto.hash.HashConfig;
import net.sf.mmm.crypto.provider.SecurityProvider;

/**
 * {@link SignatureConfig} for {@link net.sf.mmm.crypto.asymmetric.access.rsa.Rsa}.
 *
 * @since 1.0.0
 */
public class SignatureConfigRsa extends SignatureConfig<SignatureRsa> {

  /**
   * The constructor.
   *
   * @param hashConfig the {@link HashConfig} to be used as {@link #getHashConfig() hashing config}.
   * @param provider the {@link #getProvider() provider}.
   */
  public SignatureConfigRsa(HashConfig hashConfig, SecurityProvider provider) {

    super(SignatureFactoryRsa.get(), hashConfig, AsymmetricKeyPairRsa.ALGORITHM_RSA, provider);
  }

  /**
   * The constructor.
   *
   * @param hashConfig the {@link HashConfig} to be used as {@link #getHashConfig() hashing config}.
   * @param hashAlgorithm the {@link SignatureAlgorithm#getHashAlgorithm() hash algorithm}.
   * @param provider the {@link #getProvider() provider}.
   */
  public SignatureConfigRsa(HashConfig hashConfig, String hashAlgorithm, SecurityProvider provider) {

    super(SignatureFactoryRsa.get(), hashConfig, AsymmetricKeyPairRsa.ALGORITHM_RSA, hashAlgorithm, provider);
  }

  @Override
  public SignatureConfigRsa withoutHashConfig() {

    if (getHashConfig() == null) {
      return this;
    }
    return new SignatureConfigRsa(null, getSignatureAlgorithm().getHashAlgorithm(), getProvider());
  }

}
