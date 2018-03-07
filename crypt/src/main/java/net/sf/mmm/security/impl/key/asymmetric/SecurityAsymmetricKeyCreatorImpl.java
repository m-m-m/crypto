package net.sf.mmm.security.impl.key.asymmetric;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.KeySpec;

import net.sf.mmm.security.api.key.SecurityKeyCreator;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfig;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPairGeneric;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKeyGeneric;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKeyGeneric;
import net.sf.mmm.security.api.random.SecurityRandomFactory;
import net.sf.mmm.security.impl.SecurityAlgorithmImplWithRandom;

/**
 * Implementation of {@link SecurityKeyCreator}.
 */
public class SecurityAsymmetricKeyCreatorImpl extends SecurityAlgorithmImplWithRandom implements SecurityAsymmetricKeyCreator {

  private final SecurityAsymmetricKeyConfig config;

  private KeyFactory keyFactory;

  /**
   * The constructor.
   *
   * @param config the {@link SecurityAsymmetricKeyConfig}.
   * @param provider the security {@link Provider}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecurityAsymmetricKeyCreatorImpl(SecurityAsymmetricKeyConfig config, Provider provider, SecurityRandomFactory randomFactory) {

    super(config.getAlgorithm(), provider, randomFactory);
    this.config = config;
  }

  @Override
  public SecurityAsymmetricKeyPair generateKeyPair() {

    try {
      KeyPairGenerator keyGen;
      Provider provider = getProvider();
      if (provider == null) {
        keyGen = KeyPairGenerator.getInstance(getAlgorithm());
      } else {
        keyGen = KeyPairGenerator.getInstance(getAlgorithm(), provider);
      }
      this.config.init(keyGen, createSecureRandom());
      KeyPair key = keyGen.generateKeyPair();
      PrivateKey privateKeyPlain = key.getPrivate();
      SecurityPrivateKey privateKey = new SecurityPrivateKeyGeneric(serializePrivateKey(privateKeyPlain), privateKeyPlain);
      PublicKey publicKeyPlain = key.getPublic();
      SecurityPublicKey publicKey = new SecurityPublicKeyGeneric(serializePublicKey(publicKeyPlain), publicKeyPlain);
      return new SecurityAsymmetricKeyPairGeneric(privateKey, publicKey);
    } catch (Exception e) {
      throw creationFailedException(e, KeyPair.class);
    }
  }

  @Override
  public SecurityPrivateKey deserializePrivateKey(byte[] privateKey) {

    return new SecurityPrivateKeyGeneric(privateKey, () -> deserializePrivateKeyRaw(privateKey));
  }

  @Override
  public SecurityPublicKey deserializePublicKey(byte[] publicKey) {

    return new SecurityPublicKeyGeneric(publicKey, () -> deserializePublicKeyRaw(publicKey));
  }

  /**
   * @param privateKey the {@link PrivateKey} as raw {@code byte} array.
   * @return the parsed {@link PrivateKey}.
   */
  protected PrivateKey deserializePrivateKeyRaw(byte[] privateKey) {

    try {
      KeySpec keySpec = this.config.getPrivateKeyFactory().createKeySpec(privateKey);
      return getKeyFactory().generatePrivate(keySpec);
    } catch (Exception e) {
      throw creationFailedException(e, PrivateKey.class);
    }
  }

  /**
   * @param publicKey the {@link PublicKey} as raw {@code byte} array.
   * @return the deserialized {@link PublicKey}.
   */
  protected PublicKey deserializePublicKeyRaw(byte[] publicKey) {

    try {
      KeySpec keySpec = this.config.getPublicKeyFactory().createKeySpec(publicKey);
      return getKeyFactory().generatePublic(keySpec);
    } catch (Exception e) {
      throw creationFailedException(e, PublicKey.class);
    }
  }

  /**
   * @param privateKey the {@link PrivateKey} to serialize.
   * @return the serialized data as raw {@code byte} array.
   */
  protected byte[] serializePrivateKey(PrivateKey privateKey) {

    return privateKey.getEncoded();
  }

  /**
   * @param publicKey the {@link PublicKey} to serialize.
   * @return the serialized data as raw {@code byte} array.
   */
  protected byte[] serializePublicKey(PublicKey publicKey) {

    return publicKey.getEncoded();
  }

  private KeyFactory getKeyFactory() {

    if (this.keyFactory == null) {
      try {
        Provider provider = getProvider();
        if (provider == null) {
          this.keyFactory = KeyFactory.getInstance(getAlgorithm());
        } else {
          this.keyFactory = KeyFactory.getInstance(getAlgorithm(), provider);
        }
      } catch (Exception e) {
        throw creationFailedException(e, KeyFactory.class);
      }
    }
    return this.keyFactory;
  }

}
