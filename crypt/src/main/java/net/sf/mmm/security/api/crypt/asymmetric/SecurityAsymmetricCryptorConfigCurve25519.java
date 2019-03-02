package net.sf.mmm.security.api.crypt.asymmetric;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmCurve25519;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmEcIes;
import net.sf.mmm.security.api.key.asymmetric.ec.bc.SecurityAsymmetricKeyConfigCurve25519;
import net.sf.mmm.security.api.key.asymmetric.ec.jce.SecurityAsymmetricKeyConfigEcJce;

/**
 * {@link SecurityAsymmetricCryptorConfig} for {@link SecurityAlgorithmCurve25519 curve 25519}. This cipher is not
 * included in JAC/JCE so you need to use {@link org.bouncycastle.jce.provider.BouncyCastleProvider} as
 * {@link net.sf.mmm.security.api.provider.SecurityProviderBuilder#provider(java.security.Provider) configured
 * provider}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public final class SecurityAsymmetricCryptorConfigCurve25519 extends SecurityAsymmetricCryptorConfig implements SecurityAlgorithmEcIes {

  /**
   * {@link SecurityAlgorithmEcIes ECIES} with a {@link SecurityAsymmetricKeyConfigEcJce#getKeyLength() key length} of 256
   * bits.
   */
  public static final SecurityAsymmetricCryptorConfigCurve25519 CURVE_25519 = new SecurityAsymmetricCryptorConfigCurve25519(
      SecurityAsymmetricKeyConfigCurve25519.CURVE_25519);

  /**
   * The constructor.
   *
   * @param keyAlgorithmConfig the {@link SecurityAsymmetricKeyConfigCurve25519 curve 25519 key configuration}.
   */
  public SecurityAsymmetricCryptorConfigCurve25519(SecurityAsymmetricKeyConfigCurve25519 keyAlgorithmConfig) {

    super(ALGORITHM_ECIES, keyAlgorithmConfig, 0);
  }

}
