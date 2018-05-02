package net.sf.mmm.security.api.key.asymmetric;

import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

import net.sf.mmm.security.api.key.SecurityKeyConfig;

/**
 * {@link SecurityKeyConfig Key algorithm configuration} for {@link SecurityAsymmetricKeyPair asymmetric keys}.
 *
 * @see SecurityAsymmetricKeyConfigRsa
 * @see SecurityAsymmetricKeyConfigEc
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyConfig extends SecurityKeyConfig {

  private final SecurityAsymmetricKeySpecFactory privateKeyFactory;

  private final SecurityAsymmetricKeySpecFactory publicKeyFactory;

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   * @param privateKeyFactory the {@link #getPrivateKeyFactory() private key factory}.
   * @param publicKeyFactory the {@link #getPublicKeyFactory() public key factory}.
   */
  public SecurityAsymmetricKeyConfig(String algorithm, int keyLength, SecurityAsymmetricKeySpecFactory privateKeyFactory,
      SecurityAsymmetricKeySpecFactory publicKeyFactory) {

    super(algorithm, keyLength);
    this.privateKeyFactory = privateKeyFactory;
    this.publicKeyFactory = publicKeyFactory;
  }

  /**
   * @return the {@link SecurityAsymmetricKeySpecFactory factory} representing the {@link java.security.Key#getFormat()
   *         format} of the {@link java.security.PrivateKey} and used to
   *         {@link SecurityAsymmetricKeySpecFactory#createKeySpec(byte[]) create} an according
   *         {@link java.security.spec.KeySpec}.
   */
  public SecurityAsymmetricKeySpecFactory getPrivateKeyFactory() {

    return this.privateKeyFactory;
  }

  /**
   * @param privateKey the {@link PrivateKey} as raw {@code byte} array.
   * @param lazy - {@code true} to return {@code null} if {@code privateKey} is given in normal form, {@code false}
   *        otherwise (for eager deserialization).
   * @return the deserialized {@link KeySpec} or {@code null} if normal form and {@code lazy} is {@code true}.
   */
  public KeySpec deserializePrivateKey(byte[] privateKey, boolean lazy) {

    if (lazy) {
      return null;
    }
    return this.privateKeyFactory.createKeySpec(privateKey);
  }

  /**
   * @param privateKey the {@link PrivateKey} to serialize.
   * @return the serialized data as raw {@code byte} array.
   */
  public byte[] serializePrivateKey(PrivateKey privateKey) {

    return privateKey.getEncoded();
  }

  /**
   * @return the {@link SecurityAsymmetricKeySpecFactory factory} representing the {@link java.security.Key#getFormat()
   *         format} of the {@link java.security.PublicKey} and used to
   *         {@link SecurityAsymmetricKeySpecFactory#createKeySpec(byte[]) create} an according
   *         {@link java.security.spec.KeySpec}.
   */
  public SecurityAsymmetricKeySpecFactory getPublicKeyFactory() {

    return this.publicKeyFactory;
  }

  /**
   * @param publicKey the {@link PublicKey} as raw {@code byte} array.
   * @param lazy - {@code true} to return {@code null} if {@code publicKey} is given in normal form, {@code false}
   *        otherwise (for eager deserialization).
   * @return the deserialized {@link KeySpec} or {@code null} if normal form and {@code lazy} is {@code true}.
   */
  public KeySpec deserializePublicKey(byte[] publicKey, boolean lazy) {

    if (lazy) {
      return null;
    }
    return this.publicKeyFactory.createKeySpec(publicKey);
  }

  /**
   * @param publicKey the {@link PublicKey} to serialize.
   * @return the serialized data as raw {@code byte} array.
   */
  public byte[] serializePublicKey(PublicKey publicKey) {

    return publicKey.getEncoded();
  }

  /**
   * @param keyPairGenerator the {@link KeyPairGenerator} to
   *        {@link KeyPairGenerator#initialize(java.security.spec.AlgorithmParameterSpec, SecureRandom) initialize}.
   * @param random the {@link SecureRandom} instance to use.
   */
  public void init(KeyPairGenerator keyPairGenerator, SecureRandom random) {

    keyPairGenerator.initialize(getKeyLength(), random);
  }

}
