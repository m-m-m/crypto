package net.sf.mmm.security.api.key.asymmetric;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmCurve25519;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmEcdsa;
import net.sf.mmm.security.api.key.asymmetric.spec.SecurityAsymmetricKeySpecFactoryPkcs8;
import net.sf.mmm.security.api.key.asymmetric.spec.SecurityAsymmetricKeySpecFactoryX509;

/**
 * {@link SecurityAsymmetricKeyConfig} for {@link SecurityAlgorithmCurve25519 curve 25519}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyConfigCurve25519 extends SecurityAsymmetricKeyConfig implements SecurityAlgorithmEcdsa {

  /** {@link #ALGORITHM_ECDSA ECDSA} for {@link SecurityAlgorithmCurve25519 curve 25519}. */
  public static final SecurityAsymmetricKeyConfigCurve25519 CURVE_25519 = new SecurityAsymmetricKeyConfigCurve25519();

  private ECParameterSpec curve25519;

  /**
   * The constructor.
   */
  public SecurityAsymmetricKeyConfigCurve25519() {

    super(ALGORITHM_ECDSA, 256, SecurityAsymmetricKeySpecFactoryPkcs8.INSTANCE, SecurityAsymmetricKeySpecFactoryX509.INSTANCE);
  }

  /**
   * @return the curve25519
   */
  public ECParameterSpec getCurve25519() {

    if (this.curve25519 == null) {
      X9ECParameters ecP = CustomNamedCurves.getByName(SecurityAlgorithmCurve25519.ALGORITHM_CURVE_25519);
      // ECParameterSpec curve25519 = ECNamedCurveTable.getParameterSpec(algorithm);
      this.curve25519 = new ECParameterSpec(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
    }
    return this.curve25519;
  }

  @Override
  public void init(KeyPairGenerator keyPairGenerator, SecureRandom random) {

    try {
      keyPairGenerator.initialize(getCurve25519(), random);
    } catch (InvalidAlgorithmParameterException e) {
      throw new IllegalArgumentException("Failed to initialize key pair generator for " + SecurityAlgorithmCurve25519.ALGORITHM_CURVE_25519, e);
    }
  }

  @Override
  public byte[] serializePublicKey(PublicKey publicKey) {

    // TODO make 32 byte representation normal form
    byte[] encoded = ((ECPublicKey) publicKey).getQ().getEncoded(true);
    return encoded;
  }

  @Override
  public KeySpec deserializePublicKey(byte[] publicKey, boolean lazy) {

    if (publicKey.length == 33) { // TODO make 32 byte representation normal form
      if (lazy) {
        return null;
      }
      ECCurve curve = getCurve25519().getCurve();
      ECPoint q = curve.decodePoint(publicKey);
      return new ECPublicKeySpec(q, this.curve25519);
    } else {
      return super.deserializePublicKey(publicKey, false);
    }
  }

  @Override
  public byte[] serializePrivateKey(PrivateKey privateKey) {

    return ((ECPrivateKey) privateKey).getD().toByteArray();
  }

  @Override
  public KeySpec deserializePrivateKey(byte[] privateKey, boolean lazy) {

    if (privateKey.length == 32) {
      if (lazy) {
        return null;
      }
      BigInteger s = new BigInteger(privateKey);
      return new ECPrivateKeySpec(s, getCurve25519());
    } else {
      return super.deserializePrivateKey(privateKey, false);
    }
  }

}
