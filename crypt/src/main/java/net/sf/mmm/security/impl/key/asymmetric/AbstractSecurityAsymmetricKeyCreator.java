package net.sf.mmm.security.impl.key.asymmetric;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

import net.sf.mmm.security.api.key.SecurityKeyCreator;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfig;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPairFactory;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;
import net.sf.mmm.security.api.random.SecurityRandomFactory;
import net.sf.mmm.security.impl.SecurityAlgorithmImplWithRandom;

/**
 * Implementation of {@link SecurityKeyCreator} based on {@link org.bouncycastle.jce.provider.BouncyCastleProvider
 * bouncy castle}.
 */
public abstract class AbstractSecurityAsymmetricKeyCreator extends SecurityAlgorithmImplWithRandom implements SecurityAsymmetricKeyCreator {

  /** @see #getConfig() */
  protected final SecurityAsymmetricKeyConfig config;

  /**
   * The constructor.
   *
   * @param config the {@link SecurityAsymmetricKeyConfig}.
   * @param provider the security {@link Provider}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public AbstractSecurityAsymmetricKeyCreator(SecurityAsymmetricKeyConfig config, Provider provider, SecurityRandomFactory randomFactory) {

    super(config.getAlgorithm(), provider, randomFactory);
    this.config = config;
  }

  /**
   * @return the {@link SecurityAsymmetricKeyConfig}.
   */
  public SecurityAsymmetricKeyConfig getConfig() {

    return this.config;
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
      SecurityPrivateKey privateKey = createPrivateKey(key.getPrivate());
      SecurityPublicKey publicKey = createPublicKey(key.getPublic());
      return createKeyPair(privateKey, publicKey);
    } catch (Exception e) {
      throw creationFailedException(e, KeyPair.class);
    }
  }

  /**
   * @return the {@link SecurityAsymmetricKeyPairFactory}.
   * @see SecurityAsymmetricKeyConfig#getKeyPairFactory()
   */
  @SuppressWarnings("rawtypes")
  protected SecurityAsymmetricKeyPairFactory getKeyPairFactory() {

    return this.config.getKeyPairFactory();
  }

  @SuppressWarnings("unchecked")
  @Override
  public SecurityAsymmetricKeyPair createKeyPair(SecurityPrivateKey privateKey, SecurityPublicKey publicKey) {

    return getKeyPairFactory().createKeyPair(privateKey, publicKey);
  }

  @SuppressWarnings("unchecked")
  @Override
  public SecurityPrivateKey createPrivateKey(PrivateKey privateKey) {

    return getKeyPairFactory().createPrivateKey(privateKey);
  }

  @SuppressWarnings("unchecked")
  @Override
  public SecurityPublicKey createPublicKey(PublicKey publicKey) {

    return getKeyPairFactory().createPublicKey(publicKey);
  }

  // @Override
  // public SecurityPrivateKey deserializePrivateKey(byte[] privateKey) {
  //
  // KeySpec keySpec = this.config.deserializePrivateKey(privateKey, true);
  // if (keySpec == null) {
  // return new SecurityPrivateKeyGeneric(privateKey, () -> deserializePrivateKeyRaw(privateKey));
  // } else {
  // try {
  // PrivateKey key = getKeyFactory().generatePrivate(keySpec);
  // byte[] privateKeyCompact = this.config.serializePrivateKey(key);
  // return new SecurityPrivateKeyGeneric(privateKeyCompact, key);
  // } catch (Exception e) {
  // throw creationFailedException(e, PrivateKey.class);
  // }
  // }
  // }
  //
  // @Override
  // public SecurityPublicKey deserializePublicKey(byte[] publicKey) {
  //
  // KeySpec keySpec = this.config.deserializePublicKey(publicKey, true);
  // if (keySpec == null) {
  // return new SecurityPublicKeyGeneric(publicKey, () -> deserializePublicKeyRaw(publicKey));
  // } else {
  // return createPublicKey(keySpec);
  // }
  // }
  //
  // /**
  // * @param keySpec the {@link KeySpec}.
  // * @return the {@link SecurityPublicKey}.
  // */
  // public SecurityPublicKey createPublicKey(KeySpec keySpec) {
  //
  // try {
  // PublicKey key = getKeyFactory().generatePublic(keySpec);
  // return new SecurityPublicKeyGeneric(this.config.serializePublicKey(key), key);
  // } catch (Exception e) {
  // throw creationFailedException(e, PublicKey.class);
  // }
  // }
  //
  // /**
  // * @param privateKey the {@link PrivateKey} as raw {@code byte} array.
  // * @return the parsed {@link PrivateKey}.
  // */
  // protected PrivateKey deserializePrivateKeyRaw(byte[] privateKey) {
  //
  // try {
  // KeySpec keySpec = this.config.deserializePrivateKey(privateKey, false);
  // return getKeyFactory().generatePrivate(keySpec);
  // } catch (Exception e) {
  // throw creationFailedException(e, PrivateKey.class);
  // }
  // }
  //
  // /**
  // * @param publicKey the {@link PublicKey} as raw {@code byte} array.
  // * @return the deserialized {@link PublicKey}.
  // */
  // protected PublicKey deserializePublicKeyRaw(byte[] publicKey) {
  //
  // try {
  // KeySpec keySpec = this.config.deserializePublicKey(publicKey, false);
  // return getKeyFactory().generatePublic(keySpec);
  // } catch (Exception e) {
  // throw creationFailedException(e, PublicKey.class);
  // }
  // }

}
