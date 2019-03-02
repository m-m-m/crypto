package net.sf.mmm.security.api.key.asymmetric.ec.bc;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfig;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Implementation of {@link SecurityAsymmetricKeyConfig} based on
 * {@link net.sf.mmm.security.api.algorithm.SecurityAlgorithmEc EC} and {@code BouncyCastle}.
 *
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyConfigEcBc extends SecurityAsymmetricKeyConfig {

  private final SecurityAsymmetricConfigEcBc ellipticCurve;

  private final SecurityPrivateKeySpecFactoryEcBc compactPrivateKeySpecFactory;

  private final SecurityPublicKeySpecFactoryEcBc compactPublicKeySpecFactory;

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param ellipticCurve the {@link #getEllipticCurve() elliptic curve}.
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   */
  public SecurityAsymmetricKeyConfigEcBc(String algorithm, SecurityAsymmetricConfigEcBc ellipticCurve, int keyLength) {

    super(algorithm, keyLength);
    this.ellipticCurve = ellipticCurve;
    ECParameterSpec ecParameters = this.ellipticCurve.getEcParameters();
    this.compactPrivateKeySpecFactory = new SecurityPrivateKeySpecFactoryEcBc(ecParameters);
    this.compactPublicKeySpecFactory = new SecurityPublicKeySpecFactoryEcBc(ecParameters);
  }

  @Override
  public SecurityAsymmetricKeyPairFactoryEcBc getKeyPairFactory() {

    return SecurityAsymmetricKeyPairFactoryEcBc.get();
  }

  /**
   * @return the {@link SecurityAsymmetricConfigEcBc}.
   */
  public SecurityAsymmetricConfigEcBc getEllipticCurve() {

    return this.ellipticCurve;
  }

  @Override
  public void init(KeyPairGenerator keyPairGenerator, SecureRandom random) {

    try {
      keyPairGenerator.initialize(this.ellipticCurve.getEcParameters(), random);
    } catch (InvalidAlgorithmParameterException e) {
      throw new IllegalArgumentException("Failed to initialize key pair generator for " + this.ellipticCurve.getCurveName(), e);
    }
  }

  @Override
  public SecurityPrivateKeyEcBc deserializePrivateKey(byte[] privateKeyData, KeyFactory keyFactory) throws Exception {

    if (privateKeyData.length > this.compactPrivateKeySpecFactory.getKeyLength()) {
      return (SecurityPrivateKeyEcBc) super.deserializePrivateKey(privateKeyData, keyFactory);
    }
    return getKeyPairFactory().createPrivateKey(privateKeyData, () -> deserializeCompactPrivateKey(privateKeyData, keyFactory));
  }

  private ECPrivateKey deserializeCompactPrivateKey(byte[] privateKeyData, KeyFactory keyFactory) {

    try {
      KeySpec keySpec = this.compactPrivateKeySpecFactory.createKeySpec(privateKeyData);
      return (ECPrivateKey) keyFactory.generatePrivate(keySpec);
    } catch (Exception e) {
      throw creationFailedException(e, ECPrivateKey.class);
    }
  }

  @Override
  public SecurityPublicKey deserializePublicKey(byte[] publicKeyData, KeyFactory keyFactory) throws Exception {

    if (publicKeyData.length > this.compactPublicKeySpecFactory.getKeyLength()) {
      return super.deserializePublicKey(publicKeyData, keyFactory);
    }
    return getKeyPairFactory().createPublicKey(publicKeyData, () -> deserializeCompactPublicKey(publicKeyData, keyFactory));
  }

  private ECPublicKey deserializeCompactPublicKey(byte[] publicKeyData, KeyFactory keyFactory) {

    try {
      KeySpec keySpec = this.compactPublicKeySpecFactory.createKeySpec(publicKeyData);
      return (ECPublicKey) keyFactory.generatePublic(keySpec);
    } catch (Exception e) {
      throw creationFailedException(e, ECPublicKey.class);
    }
  }

  @Override
  public SecurityAsymmetricKeyPair deserializeKeyPair(byte[] keyPairBytes, KeyFactory keyFactory) throws Exception {

    SecurityPrivateKeyEcBc privateKey = deserializePrivateKey(keyPairBytes, keyFactory);
    BCECPrivateKey pk = (BCECPrivateKey) privateKey.getKey();
    BigInteger s = pk.getS();
    ECParameterSpec ecParameters = pk.getParameters();
    ECPoint q = ecParameters.getG().multiply(s);
    ECPublicKeySpec keySpec = new ECPublicKeySpec(q, ecParameters);
    ECPublicKey publicKeyRaw = (ECPublicKey) keyFactory.generatePublic(keySpec);
    SecurityPublicKeyEcBc publicKey = getKeyPairFactory().createPublicKey(publicKeyRaw);
    return getKeyPairFactory().createKeyPair(privateKey, publicKey);
  }

}
