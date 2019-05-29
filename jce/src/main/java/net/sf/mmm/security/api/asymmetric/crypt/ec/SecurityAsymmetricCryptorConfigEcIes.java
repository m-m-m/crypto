package net.sf.mmm.security.api.asymmetric.crypt.ec;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import net.sf.mmm.security.api.asymmetric.crypt.SecurityAsymmetricCryptorConfig;
import net.sf.mmm.security.api.crypt.SecurityCipherTransformation;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecurityAsymmetricCryptorConfig} for ECIES (Elliptic Curve Integrated Encryption Scheme). For details see
 * <a href="https://en.wikipedia.org/wiki/Elliptic_curve_cryptography">ECC</a>.
 *
 * @param <PR> type of {@link ECPrivateKey}.
 * @param <PU> type of {@link ECPublicKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public final class SecurityAsymmetricCryptorConfigEcIes<PR extends ECPrivateKey, PU extends ECPublicKey> extends SecurityAsymmetricCryptorConfig<PR, PU> {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  public static final String ALGORITHM_ECIES = "ECIES";

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider}.
   */
  public SecurityAsymmetricCryptorConfigEcIes(SecurityProvider provider) {

    super(new SecurityCipherTransformation(ALGORITHM_ECIES), 0, provider);
  }

}
