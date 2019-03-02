package net.sf.mmm.security.api.crypt.asymmetric;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmEcIes;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmSecp256k1;
import net.sf.mmm.security.api.key.asymmetric.ec.bc.SecurityAsymmetricKeyConfigSecp256k1;
import net.sf.mmm.security.api.key.asymmetric.ec.jce.SecurityAsymmetricKeyConfigEcJce;

/**
 * {@link SecurityAsymmetricCryptorConfig} for {@link SecurityAlgorithmSecp256k1 Secp256k1}. This cipher is not included
 * in JAC/JCE so you need to use {@link org.bouncycastle.jce.provider.BouncyCastleProvider} as
 * {@link net.sf.mmm.security.api.provider.SecurityProviderBuilder#provider(java.security.Provider) configured
 * provider}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public final class SecurityAsymmetricCryptorConfigSecp256k1 extends SecurityAsymmetricCryptorConfig implements SecurityAlgorithmEcIes {

  /**
   * {@link SecurityAlgorithmEcIes ECIES} with a {@link SecurityAsymmetricKeyConfigEcJce#getKeyLength() key length} of 256
   * bits.
   */
  public static final SecurityAsymmetricCryptorConfigSecp256k1 SECP_256K1 = new SecurityAsymmetricCryptorConfigSecp256k1(
      SecurityAsymmetricKeyConfigSecp256k1.SECP_256K1);

  /**
   * The constructor.
   *
   * @param keyAlgorithmConfig the {@link SecurityAsymmetricKeyConfigSecp256k1 SecP256k1 key configuration}.
   */
  public SecurityAsymmetricCryptorConfigSecp256k1(SecurityAsymmetricKeyConfigSecp256k1 keyAlgorithmConfig) {

    super(ALGORITHM_ECIES, keyAlgorithmConfig, 0);
  }

}
