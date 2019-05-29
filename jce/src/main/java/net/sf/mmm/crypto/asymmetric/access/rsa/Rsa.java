package net.sf.mmm.crypto.asymmetric.access.rsa;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import net.sf.mmm.crypto.asymmetric.access.AsymmetricAccess;
import net.sf.mmm.crypto.asymmetric.crypt.AsymmetricCryptorConfig;
import net.sf.mmm.crypto.asymmetric.crypt.rsa.AsymmetricCryptorConfigRsa;
import net.sf.mmm.crypto.asymmetric.key.rsa.AsymmetricKeyCreatorRsa;
import net.sf.mmm.crypto.asymmetric.key.rsa.AsymmetricKeyPairRsa;
import net.sf.mmm.crypto.asymmetric.sign.rsa.SignatureConfigRsa;
import net.sf.mmm.crypto.asymmetric.sign.rsa.SignatureRsa;
import net.sf.mmm.crypto.hash.HashConfig;
import net.sf.mmm.crypto.provider.SecurityProvider;
import net.sf.mmm.crypto.random.RandomFactory;

/**
 * Direct builder for RSA (Ron Rivest, Adi Shamir and Leonard Adleman) used by PGP/GPG and many others. For details see
 * <a href="https://en.wikipedia.org/wiki/PKCS_1">PKCS #1</a>.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public final class Rsa extends AsymmetricAccess<SignatureRsa, RSAPrivateKey, RSAPublicKey, AsymmetricKeyPairRsa, AsymmetricKeyCreatorRsa> {

  private final SecurityProvider provider;

  private final int keyLength;

  /**
   * The constructor.
   *
   * @param signatureConfig the {@link SignatureConfigRsa}.
   * @param cryptorConfig the {@link AsymmetricCryptorConfig}.
   * @param randomFactory the optional {@link RandomFactory}.
   * @param keyLength the {@link net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#getKeyLength() key length}.
   * @param provider the optional {@link SecurityProvider}.
   */
  private Rsa(SignatureConfigRsa signatureConfig, AsymmetricCryptorConfig<RSAPrivateKey, RSAPublicKey> cryptorConfig,
      RandomFactory randomFactory, int keyLength, SecurityProvider provider) {

    super(signatureConfig, cryptorConfig, randomFactory);
    this.keyLength = keyLength;
    this.provider = provider;
  }

  @Override
  public AsymmetricKeyCreatorRsa newKeyCreator() {

    return new AsymmetricKeyCreatorRsa(this.keyLength, this.provider, this.randomFactory);
  }

  /**
   * @param hashAlgorithm the {@link HashConfig#getAlgorithm() algorithm} for the hash used for signatures.
   * @return a {@link Rsa} instance with a {@link net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#getKeyLength()
   *         key length} of 4096 bits.
   */
  public static Rsa of4096(String hashAlgorithm) {

    return of4096(new HashConfig(hashAlgorithm));
  }

  /**
   * @param hashConfig the {@link HashConfig} for hashing data for {@link SignatureRsa signatures}.
   * @return a {@link Rsa} instance with a {@link net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#getKeyLength()
   *         key length} of 4096 bits.
   */
  public static Rsa of4096(HashConfig hashConfig) {

    return of(4096, hashConfig);
  }

  /**
   * @param keyLength the {@link net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#getKeyLength() key length} in
   *        bits.
   * @param hashAlgorithm the {@link HashConfig#getAlgorithm() algorithm} for the hash used for signatures.
   * @return the according {@link Rsa} instance.
   */
  public static Rsa of(int keyLength, String hashAlgorithm) {

    return of(keyLength, new HashConfig(hashAlgorithm));
  }

  /**
   * @param keyLength the {@link net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#getKeyLength() key length} in
   *        bits.
   * @param hashConfig the {@link HashConfig} for hashing data for {@link SignatureRsa signatures}.
   * @return the according {@link Rsa} instance.
   */
  public static Rsa of(int keyLength, HashConfig hashConfig) {

    return of(keyLength, hashConfig, hashConfig.getAlgorithm(), null, null);
  }

  /**
   * @param keyLength the {@link net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#getKeyLength() key length} in
   *        bits.
   * @param hashConfig the {@link HashConfig} for hashing data for {@link SignatureRsa signatures}.
   * @param randomFactory the {@link RandomFactory}.
   * @return the according {@link Rsa} instance.
   */
  public static Rsa of(int keyLength, HashConfig hashConfig, RandomFactory randomFactory) {

    return of(keyLength, hashConfig, hashConfig.getAlgorithm(), randomFactory, null);
  }

  /**
   * @param keyLength the {@link net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#getKeyLength() key length} in
   *        bits.
   * @param hashConfig the {@link HashConfig} for hashing data for {@link SignatureRsa signatures}.
   * @param hashAlgorithm the {@link HashConfig#getAlgorithm() hash algorithm} for the signature (e.g. for
   *        HMac).
   * @param randomFactory the {@link RandomFactory}.
   * @param provider the {@link SecurityProvider} to use.
   * @return the according {@link Rsa} instance.
   */
  public static Rsa of(int keyLength, HashConfig hashConfig, String hashAlgorithm, RandomFactory randomFactory,
      SecurityProvider provider) {

    SignatureConfigRsa signatureConfig = new SignatureConfigRsa(hashConfig, hashAlgorithm, provider);
    AsymmetricCryptorConfigRsa cryptorConfig = new AsymmetricCryptorConfigRsa(provider);
    return new Rsa(signatureConfig, cryptorConfig, randomFactory, keyLength, provider);
  }

}
