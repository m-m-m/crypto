package net.sf.mmm.security.api.asymmetric.key.ec.bc;

import java.math.BigInteger;
import java.security.KeyFactory;

import net.sf.mmm.security.api.asymmetric.access.ec.bc.SecurityEllipticCurveBc;
import net.sf.mmm.security.api.asymmetric.key.AbstractSecurityAsymmetricKeyPairFactory;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * Abstract base implementation of {@link AbstractSecurityAsymmetricKeyPairFactory} for EC using BouncyCastle.
 *
 * @since 1.0.0
 */
public abstract class SecurityAsymmetricKeyPairFactoryEcBc
    extends AbstractSecurityAsymmetricKeyPairFactory<BCECPrivateKey, BCECPublicKey, SecurityAsymmetricKeyPairEcBc> {

  /** @see SecurityEllipticCurveBc#getEcParameters() */
  protected final ECParameterSpec ecParameters;

  /** @see SecurityEllipticCurveBc#getByteLength() */
  protected final int byteLength;

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec}.
   */
  public SecurityAsymmetricKeyPairFactoryEcBc(ECParameterSpec ecParameters) {

    this(ecParameters, SecurityAsymmetricKeyPairEcBc.getKeyFactory());
  }

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec}.
   * @param keyFactory the {@link KeyFactory}.
   */
  public SecurityAsymmetricKeyPairFactoryEcBc(ECParameterSpec ecParameters, KeyFactory keyFactory) {

    super(keyFactory);
    this.ecParameters = ecParameters;
    this.byteLength = SecurityEllipticCurveBc.getByteLength(this.ecParameters);
  }

  @Override
  public byte[] asData(BCECPrivateKey privateKey) {

    byte[] data = privateKey.getD().toByteArray();
    if (data[0] == 0) {
      // ugly waste but Java does not seem to offer another way to do it
      byte[] compactData = new byte[data.length - 1];
      System.arraycopy(data, 1, compactData, 0, compactData.length);
      data = compactData;
    }
    return data;
  }

  @Override
  public BCECPrivateKey createPrivateKey(byte[] data) {

    if (data.length > this.byteLength) {
      return null;
    }
    BigInteger s = new BigInteger(1, data);
    return SecurityAsymmetricKeyPairEcBc.createPrivateKey(s, this.ecParameters);
  }

  @Override
  public byte[] asData(SecurityAsymmetricKeyPairEcBc keyPair) {

    return asData(keyPair.getPrivateKey());
  }

  @Override
  public SecurityAsymmetricKeyPairEcBc createKeyPair(byte[] data) {

    BCECPrivateKey privateKey = createPrivateKey(data);
    return new SecurityAsymmetricKeyPairEcBc(privateKey);
  }

  @Override
  public SecurityAsymmetricKeyPairEcBc createKeyPair(BCECPrivateKey privateKey, BCECPublicKey publicKey) {

    return new SecurityAsymmetricKeyPairEcBc(privateKey, publicKey);
  }

}
