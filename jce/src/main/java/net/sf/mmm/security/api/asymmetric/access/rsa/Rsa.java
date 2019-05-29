package net.sf.mmm.security.api.asymmetric.access.rsa;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmRsa;
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
public final class Rsa extends
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
  private Rsa(SecuritySignatureConfigRsa signatureConfig,
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
   * @param hashAlgorithm the {@link SecurityHashConfig#getAlgorithm() algorithm} for the hash used for signatures.
   * @return a {@link Rsa} instance with a
   *         {@link net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#getKeyLength() key length} of
   *         4096 bits.
   */
  public static Rsa of4096(String hashAlgorithm) {

    return of4096(new SecurityHashConfig(hashAlgorithm));
  }

  /**
   * @param hashConfig the {@link SecurityHashConfig} for hashing data for {@link SecuritySignatureRsa signatures}.
   * @return a {@link Rsa} instance with a
   *         {@link net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#getKeyLength() key length} of
   *         4096 bits.
   */
  public static Rsa of4096(SecurityHashConfig hashConfig) {

    return of(4096, hashConfig);
  }

  /**
   * @param keyLength the {@link net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#getKeyLength() key
   *        length} in bits.
   * @param hashAlgorithm the {@link SecurityHashConfig#getAlgorithm() algorithm} for the hash used for signatures.
   * @return the according {@link Rsa} instance.
   */
  public static Rsa of(int keyLength, String hashAlgorithm) {

    return of(keyLength, new SecurityHashConfig(hashAlgorithm));
  }

  /**
   * @param keyLength the {@link net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#getKeyLength() key
   *        length} in bits.
   * @param hashConfig the {@link SecurityHashConfig} for hashing data for {@link SecuritySignatureRsa signatures}.
   * @return the according {@link Rsa} instance.
   */
  public static Rsa of(int keyLength, SecurityHashConfig hashConfig) {

    return of(keyLength, hashConfig, hashConfig.getAlgorithm(), null, null);
  }

  /**
   * @param keyLength the {@link net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#getKeyLength() key
   *        length} in bits.
   * @param hashConfig the {@link SecurityHashConfig} for hashing data for {@link SecuritySignatureRsa signatures}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   * @return the according {@link Rsa} instance.
   */
  public static Rsa of(int keyLength, SecurityHashConfig hashConfig, SecurityRandomFactory randomFactory) {

    return of(keyLength, hashConfig, hashConfig.getAlgorithm(), randomFactory, null);
  }

  /**
   * @param keyLength the {@link net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#getKeyLength() key
   *        length} in bits.
   * @param hashConfig the {@link SecurityHashConfig} for hashing data for {@link SecuritySignatureRsa signatures}.
   * @param hashAlgorithm the {@link SecurityHashConfig#getAlgorithm() hash algorithm} for the signature (e.g. for
   *        HMac).
   * @param randomFactory the {@link SecurityRandomFactory}.
   * @param provider the {@link SecurityProvider} to use.
   * @return the according {@link Rsa} instance.
   */
  public static Rsa of(int keyLength, SecurityHashConfig hashConfig, String hashAlgorithm,
      SecurityRandomFactory randomFactory, SecurityProvider provider) {

    SecuritySignatureConfigRsa signatureConfig = new SecuritySignatureConfigRsa(hashConfig, hashAlgorithm, provider);
    SecurityAsymmetricCryptorConfigRsa cryptorConfig = new SecurityAsymmetricCryptorConfigRsa(provider);
    return new Rsa(signatureConfig, cryptorConfig, randomFactory, keyLength, provider);
  }

}
