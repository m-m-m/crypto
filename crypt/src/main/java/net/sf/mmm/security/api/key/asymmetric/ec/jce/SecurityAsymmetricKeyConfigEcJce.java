package net.sf.mmm.security.api.key.asymmetric.ec.jce;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmEc;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfig;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;
import net.sf.mmm.security.api.key.asymmetric.generic.SecurityAsymmetricKeySpecFactoryPkcs8;
import net.sf.mmm.security.api.key.asymmetric.generic.SecurityAsymmetricKeySpecFactoryX509;

/**
 * {@link SecurityAsymmetricKeyConfig} for {@link SecurityAlgorithmEc EC}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyConfigEcJce extends SecurityAsymmetricKeyConfig implements SecurityAlgorithmEc {

  /** {@link #ALGORITHM_EC EC} with a {@link #getKeyLength() key length} of 256 bits. */
  public static final SecurityAsymmetricKeyConfigEcJce EC_256 = new SecurityAsymmetricKeyConfigEcJce(256);

  private ECParameterSpec ecParams;

  /**
   * The constructor.
   *
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   */
  public SecurityAsymmetricKeyConfigEcJce(int keyLength) {

    super(ALGORITHM_EC, keyLength, SecurityAsymmetricKeySpecFactoryPkcs8.INSTANCE, SecurityAsymmetricKeySpecFactoryX509.INSTANCE);
  }

  @Override
  public SecurityAsymmetricKeyPairFactoryEcJce getKeyPairFactory() {

    return SecurityAsymmetricKeyPairFactoryEcJce.get();
  }

  /**
   * @return ecParams
   */
  public ECParameterSpec getEcParams() {

    if (this.ecParams == null) {
      EllipticCurve curve = null;
      ECPoint g = null;
      BigInteger n = null;
      int h = 0;
      this.ecParams = new ECParameterSpec(curve, g, n, h);
    }
    return this.ecParams;
  }

  @Override
  public SecurityPrivateKey deserializePrivateKey(byte[] privateKeyData, KeyFactory keyFactory) throws Exception {

    // TODO Auto-generated method stub
    if (privateKeyData.length <= 33) {

    }
    return super.deserializePrivateKey(privateKeyData, keyFactory);
  }

  @Override
  public SecurityPublicKey deserializePublicKey(byte[] publicKeyData, KeyFactory keyFactory) throws Exception {

    if (publicKeyData.length <= 32) {
      // ECPoint w = null;
      // return new ECPublicKeySpec(w, getEcParams());
    }
    // TODO Auto-generated method stub
    return super.deserializePublicKey(publicKeyData, keyFactory);
  }

  @Override
  public SecurityAsymmetricKeyPair deserializeKeyPair(byte[] keyPairBytes, KeyFactory keyFactory) throws Exception {

    // TODO Auto-generated method stub
    return null;
  }

}
