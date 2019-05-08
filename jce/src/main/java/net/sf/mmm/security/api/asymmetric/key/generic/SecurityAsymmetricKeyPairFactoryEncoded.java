package net.sf.mmm.security.api.asymmetric.key.generic;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import net.sf.mmm.security.api.SecurityBinaryFormat;
import net.sf.mmm.security.api.asymmetric.key.AbstractSecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.asymmetric.key.AbstractSecurityAsymmetricKeyPairFactory;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPairFactory;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPairFactorySimple;

/**
 * Implementation of {@link SecurityAsymmetricKeyPairFactory} for {@link SecurityBinaryFormat#FORMAT_ENCODED encoded format}
 * based on {@link PKCS8EncodedKeySpec} and {@link X509EncodedKeySpec}.
 *
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @param <PAIR> type of {@link SecurityAsymmetricKeyPair}.
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyPairFactoryEncoded<PR extends PrivateKey, PU extends PublicKey, PAIR extends AbstractSecurityAsymmetricKeyPair<PR, PU>>
    extends AbstractSecurityAsymmetricKeyPairFactory<PR, PU, PAIR> {

  private SecurityAsymmetricKeyPairFactorySimple<PR, PU, PAIR> keyPairCreator;

  /**
   * The constructor.
   *
   * @param keyFactory the {@link KeyFactory}.
   * @param keyPairCreator the {@link SecurityAsymmetricKeyPairFactorySimple}.
   */
  public SecurityAsymmetricKeyPairFactoryEncoded(KeyFactory keyFactory,
      SecurityAsymmetricKeyPairFactorySimple<PR, PU, PAIR> keyPairCreator) {

    super(keyFactory);
    this.keyPairCreator = keyPairCreator;
  }

  @Override
  public byte[] asData(PR privateKey) {

    return privateKey.getEncoded();
  }

  @Override
  public PR createPrivateKey(byte[] data) {

    return createPrivateKey(new PKCS8EncodedKeySpec(data));
  }

  @Override
  public byte[] asData(PU publicKey) {

    return publicKey.getEncoded();
  }

  @Override
  public PU createPublicKey(byte[] data) {

    return createPublicKey(new X509EncodedKeySpec(data));
  }

  @Override
  public byte[] asData(PAIR keyPair) {

    byte[] privateData = asData(keyPair.getPrivateKey());
    byte[] publicData = asData(keyPair.getPublicKey());
    byte[] data = new byte[privateData.length + publicData.length];
    System.arraycopy(privateData, 0, data, 0, privateData.length);
    System.arraycopy(publicData, 0, data, privateData.length, publicData.length);
    return data;
  }

  @Override
  public PAIR createKeyPair(PR privateKey, PU publicKey) {

    return this.keyPairCreator.createKeyPair(privateKey, publicKey);
  }

  @Override
  public PAIR createKeyPair(byte[] data) {

    // TODO
    int privateDataLength = data.length / 2;
    byte[] privateData = new byte[privateDataLength];
    byte[] publicData = new byte[data.length - privateDataLength];
    System.arraycopy(data, 0, privateData, 0, privateDataLength);
    System.arraycopy(data, privateDataLength, publicData, 0, publicData.length);
    PR privateKey = createPrivateKey(privateData);
    PU publicKey = createPublicKey(publicData);
    return createKeyPair(privateKey, publicKey);
  }

}
