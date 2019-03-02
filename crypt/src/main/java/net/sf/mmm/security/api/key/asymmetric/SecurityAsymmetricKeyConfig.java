package net.sf.mmm.security.api.key.asymmetric;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

import net.sf.mmm.security.api.key.SecurityKeyConfig;
import net.sf.mmm.security.api.key.asymmetric.ec.jce.SecurityAsymmetricKeyConfigEcJce;
import net.sf.mmm.security.api.key.asymmetric.generic.SecurityAsymmetricKeySpecFactoryPkcs8;
import net.sf.mmm.security.api.key.asymmetric.generic.SecurityAsymmetricKeySpecFactoryX509;
import net.sf.mmm.security.api.key.asymmetric.rsa.SecurityAsymmetricKeyConfigRsa;

/**
 * {@link SecurityKeyConfig Key algorithm configuration} for {@link SecurityAsymmetricKeyPair asymmetric keys}.
 *
 * @see SecurityAsymmetricKeyConfigRsa
 * @see SecurityAsymmetricKeyConfigEcJce
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecurityAsymmetricKeyConfig extends SecurityKeyConfig {

  private final SecurityPrivateKeySpecFactory encodedPrivateKeySpecFactory;

  private final SecurityPublicKeySpecFactory encodedPublicKeySpecFactory;

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   */
  public SecurityAsymmetricKeyConfig(String algorithm, int keyLength) {

    this(algorithm, keyLength, SecurityAsymmetricKeySpecFactoryPkcs8.INSTANCE, SecurityAsymmetricKeySpecFactoryX509.INSTANCE);
  }

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   * @param encodedPrivateKeySpecFactory the {@link #getEncodedPrivateKeySpecFactory() private key factory}.
   * @param encodedPublicKeySpecFactory the {@link #getEncodedPublicKeySpecFactory() public key factory}.
   */
  public SecurityAsymmetricKeyConfig(String algorithm, int keyLength, SecurityPrivateKeySpecFactory encodedPrivateKeySpecFactory,
      SecurityPublicKeySpecFactory encodedPublicKeySpecFactory) {

    super(algorithm, keyLength);
    this.encodedPrivateKeySpecFactory = encodedPrivateKeySpecFactory;
    this.encodedPublicKeySpecFactory = encodedPublicKeySpecFactory;
  }

  /**
   * @return the {@link SecurityAsymmetricKeySpecFactory factory} representing the {@link java.security.Key#getFormat()
   *         format} of the {@link java.security.PrivateKey} and used to
   *         {@link SecurityAsymmetricKeySpecFactory#createKeySpec(byte[]) create} an according
   *         {@link java.security.spec.KeySpec}.
   */
  public SecurityPrivateKeySpecFactory getEncodedPrivateKeySpecFactory() {

    return this.encodedPrivateKeySpecFactory;
  }

  /**
   * @return the {@link SecurityAsymmetricKeySpecFactory factory} representing the {@link java.security.Key#getFormat()
   *         format} of the {@link java.security.PublicKey} and used to
   *         {@link SecurityAsymmetricKeySpecFactory#createKeySpec(byte[]) create} an according
   *         {@link java.security.spec.KeySpec}.
   */
  public SecurityPublicKeySpecFactory getEncodedPublicKeySpecFactory() {

    return this.encodedPublicKeySpecFactory;
  }

  /**
   * @return the {@link SecurityAsymmetricKeyPairFactory}.
   */
  public abstract SecurityAsymmetricKeyPairFactory<?, ?, ?, ?, ?> getKeyPairFactory();

  /**
   * @param privateKeyData the serialized key data.
   * @param keyFactory the required {@link KeyFactory}.
   * @return the deserialized {@link SecurityPrivateKey}.
   * @throws Exception if anything goes wrong.
   */
  @SuppressWarnings({ "rawtypes", "unchecked" })
  public SecurityPrivateKey deserializePrivateKey(byte[] privateKeyData, KeyFactory keyFactory) throws Exception {

    KeySpec privateKeySpec = this.encodedPrivateKeySpecFactory.createKeySpec(privateKeyData);
    PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
    return ((SecurityAsymmetricKeyPairFactory) getKeyPairFactory()).createPrivateKey(privateKey);
  }

  /**
   * @param publicKeyData the serialized key data.
   * @param keyFactory the required {@link KeyFactory}.
   * @return the deserialized {@link SecurityPublicKey}.
   * @throws Exception if anything goes wrong.
   */
  @SuppressWarnings({ "rawtypes", "unchecked" })
  public SecurityPublicKey deserializePublicKey(byte[] publicKeyData, KeyFactory keyFactory) throws Exception {

    KeySpec publicKeySpec = this.encodedPublicKeySpecFactory.createKeySpec(publicKeyData);
    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
    return ((SecurityAsymmetricKeyPairFactory) getKeyPairFactory()).createPublicKey(publicKey);
  }

  /**
   * @param keyPairGenerator the {@link KeyPairGenerator} to
   *        {@link KeyPairGenerator#initialize(java.security.spec.AlgorithmParameterSpec, SecureRandom) initialize}.
   * @param random the {@link SecureRandom} instance to use.
   */
  public void init(KeyPairGenerator keyPairGenerator, SecureRandom random) {

    keyPairGenerator.initialize(getKeyLength(), random);
  }

  /**
   * @param keyPairBytes the {@link SecurityAsymmetricKeyPair#asBinary() binary bytes} to deserialize.
   * @param keyFactory the required {@link KeyFactory}.
   * @return the deserialized {@link SecurityAsymmetricKeyPair}.
   * @throws Exception if anything goes wrong.
   */
  public abstract SecurityAsymmetricKeyPair deserializeKeyPair(byte[] keyPairBytes, KeyFactory keyFactory) throws Exception;

}
