package net.sf.mmm.security.api.asymmetric.access.rsa;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmRsa;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmSha2;
import net.sf.mmm.security.api.asymmetric.access.SecurityAccessAsymmetric;
import net.sf.mmm.security.api.asymmetric.crypt.SecurityAsymmetricCryptorConfig;
import net.sf.mmm.security.api.asymmetric.crypt.rsa.SecurityAsymmetricCryptorConfigRsa;
import net.sf.mmm.security.api.asymmetric.key.rsa.SecurityAsymmetricKeyCreatorRsa;
import net.sf.mmm.security.api.asymmetric.key.rsa.SecurityAsymmetricKeyPairRsa;
import net.sf.mmm.security.api.asymmetric.sign.rsa.SecuritySignatureConfigRsa;
import net.sf.mmm.security.api.asymmetric.sign.rsa.SecuritySignatureRsa;
import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;
import net.sf.mmm.security.api.random.SecurityRandomFactory;

/**
 * Direct builder for {@link SecurityAlgorithmRsa RSA}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public final class SecurityAccessRsa extends
    SecurityAccessAsymmetric<SecuritySignatureRsa, RSAPrivateKey, RSAPublicKey, SecurityAsymmetricKeyPairRsa, SecurityAsymmetricKeyCreatorRsa>
    implements SecurityAlgorithmRsa {

  private final SecurityProvider provider;

  private final int keyLength;

  /**
   * The constructor.
   *
   * @param signatureConfig the {@link SecuritySignatureConfigRsa}.
   * @param cryptorConfig the {@link SecurityAsymmetricCryptorConfig}.
   * @param randomFactory the optional {@link SecurityRandomFactory}.
   * @param keyLength the {@link net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#getKeyLength() key
   *        length}.
   * @param provider the optional {@link SecurityProvider}.
   */
  private SecurityAccessRsa(SecuritySignatureConfigRsa signatureConfig,
      SecurityAsymmetricCryptorConfig<RSAPrivateKey, RSAPublicKey> cryptorConfig, SecurityRandomFactory randomFactory, int keyLength,
      SecurityProvider provider) {

    super(signatureConfig, cryptorConfig, randomFactory);
    this.keyLength = keyLength;
    this.provider = provider;
  }

  @Override
  public SecurityAsymmetricKeyCreatorRsa newKeyCreator() {

    return new SecurityAsymmetricKeyCreatorRsa(this.keyLength, this.provider, this.randomFactory);
  }

  /**
   * @param hashConfig the {@link SecurityHashConfig} for hashing data for {@link SecuritySignatureRsa signatures}.
   * @return a {@link SecurityAccessRsa} instance with a
   *         {@link net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#getKeyLength() key length} of
   *         4096 bits.
   */
  public static SecurityAccessRsa of4096(SecurityHashConfig hashConfig) {

    return of(4096, hashConfig);
  }

  /**
   * @param keyLength the {@link net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#getKeyLength() key
   *        length} in bits.
   * @return a {@link SecurityAccessRsa} instance with {@link SecurityAlgorithmSha2#ALGORITHM_SHA_256} as hash config.
   */
  public static SecurityAccessRsa ofSha256(int keyLength) {

    return of(keyLength, new SecurityHashConfig(SecurityAlgorithmSha2.ALGORITHM_SHA_256));
  }

  /**
   * @param keyLength the {@link net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#getKeyLength() key
   *        length} in bits.
   * @param hashConfig the {@link SecurityHashConfig} for hashing data for {@link SecuritySignatureRsa signatures}.
   * @return the according {@link SecurityAccessRsa} instance.
   */
  public static SecurityAccessRsa of(int keyLength, SecurityHashConfig hashConfig) {

    return of(keyLength, hashConfig, null, null);
  }

  /**
   * @param keyLength the {@link net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#getKeyLength() key
   *        length} in bits.
   * @param hashConfig the {@link SecurityHashConfig} for hashing data for {@link SecuritySignatureRsa signatures}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   * @return the according {@link SecurityAccessRsa} instance.
   */
  public static SecurityAccessRsa of(int keyLength, SecurityHashConfig hashConfig, SecurityRandomFactory randomFactory) {

    return of(keyLength, hashConfig, randomFactory, null);
  }

  /**
   * @param keyLength the {@link net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#getKeyLength() key
   *        length} in bits.
   * @param hashConfig the {@link SecurityHashConfig} for hashing data for {@link SecuritySignatureRsa signatures}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   * @param provider the {@link SecurityProvider} to use.
   * @return the according {@link SecurityAccessRsa} instance.
   */
  public static SecurityAccessRsa of(int keyLength, SecurityHashConfig hashConfig, SecurityRandomFactory randomFactory,
      SecurityProvider provider) {

    SecuritySignatureConfigRsa signatureConfig = new SecuritySignatureConfigRsa(hashConfig, provider);
    SecurityAsymmetricCryptorConfigRsa cryptorConfig = new SecurityAsymmetricCryptorConfigRsa(provider);
    return new SecurityAccessRsa(signatureConfig, cryptorConfig, randomFactory, keyLength, provider);
  }

}
