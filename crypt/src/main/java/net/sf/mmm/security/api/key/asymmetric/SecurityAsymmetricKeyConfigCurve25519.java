package net.sf.mmm.security.api.key.asymmetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.spec.ECParameterSpec;

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

  /**
   * The constructor.
   */
  public SecurityAsymmetricKeyConfigCurve25519() {

    super(ALGORITHM_ECDSA, 256, SecurityAsymmetricKeySpecFactoryPkcs8.INSTANCE, SecurityAsymmetricKeySpecFactoryX509.INSTANCE);
  }

  @Override
  public void init(KeyPairGenerator keyPairGenerator, SecureRandom random) {

    String algorithm = SecurityAlgorithmCurve25519.ALGORITHM_CURVE_25519;
    try {
      X9ECParameters ecP = CustomNamedCurves.getByName(algorithm);
      ECParameterSpec curve25519 = new ECParameterSpec(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
      // ECParameterSpec curve25519 = ECNamedCurveTable.getParameterSpec(algorithm);
      keyPairGenerator.initialize(curve25519, random);
    } catch (InvalidAlgorithmParameterException e) {
      throw new IllegalArgumentException("Failed to initialize key pair generator for " + algorithm, e);
    }
  }

}
