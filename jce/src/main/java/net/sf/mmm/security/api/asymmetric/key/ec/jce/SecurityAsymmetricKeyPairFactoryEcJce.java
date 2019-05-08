package net.sf.mmm.security.api.asymmetric.key.ec.jce;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import net.sf.mmm.security.api.asymmetric.key.AbstractSecurityAsymmetricKeyPairFactory;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPairFactory;

/**
 * Implementation of {@link SecurityAsymmetricKeyPairFactory} for
 * {@link net.sf.mmm.security.api.algorithm.SecurityAlgorithmEc EC} and {@code bouncy castle}.
 *
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyPairFactoryEcJce
    extends AbstractSecurityAsymmetricKeyPairFactory<ECPrivateKey, ECPublicKey, SecurityAsymmetricKeyPairEcJce> {

  private final ECParameterSpec ecParameters;

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec}.
   */
  public SecurityAsymmetricKeyPairFactoryEcJce(ECParameterSpec ecParameters) {

    super(SecurityAsymmetricKeyPairEcJce.getKeyFactory());
    this.ecParameters = ecParameters;
  }

  @Override
  public byte[] asData(ECPrivateKey privateKey) {

    byte[] data = privateKey.getS().toByteArray();
    if (data[0] == 0) {
      // ugly waste but Java does not seem to offer another way to do it
      byte[] compactData = new byte[data.length - 1];
      System.arraycopy(data, 1, compactData, 0, compactData.length);
      data = compactData;
    }
    return data;
  }

  @Override
  public ECPrivateKey createPrivateKey(byte[] data) {

    BigInteger s = new BigInteger(1, data);
    return SecurityAsymmetricKeyPairEcJce.createPrivateKey(s, this.ecParameters);
  }

  @Override
  public byte[] asData(ECPublicKey publicKey) {

    // TODO
    // publicKey.getW().getEncoded(true);
    return null;
  }

  @Override
  public ECPublicKey createPublicKey(byte[] data) {

    // TODO
    ECPoint w = null;
    return SecurityAsymmetricKeyPairEcJce.createPublicKey(w, this.ecParameters);
  }

  @Override
  public byte[] asData(SecurityAsymmetricKeyPairEcJce keyPair) {

    return asData(keyPair.getPrivateKey());
  }

  @Override
  public SecurityAsymmetricKeyPairEcJce createKeyPair(byte[] data) {

    ECPrivateKey privateKey = createPrivateKey(data);
    return new SecurityAsymmetricKeyPairEcJce(privateKey);
  }

  @Override
  public SecurityAsymmetricKeyPairEcJce createKeyPair(ECPrivateKey privateKey, ECPublicKey publicKey) {

    return new SecurityAsymmetricKeyPairEcJce(privateKey, publicKey);
  }

}
