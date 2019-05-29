package net.sf.mmm.crypto.asymmetric.crypt.ec;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import net.sf.mmm.crypto.asymmetric.crypt.AsymmetricCryptorConfig;
import net.sf.mmm.crypto.crypt.CipherTransformation;
import net.sf.mmm.crypto.provider.SecurityProvider;

/**
 * {@link AsymmetricCryptorConfig} for ECIES (Elliptic Curve Integrated Encryption Scheme). For details see
 * <a href="https://en.wikipedia.org/wiki/Elliptic_curve_cryptography">ECC</a>.
 *
 * @param <PR> type of {@link ECPrivateKey}.
 * @param <PU> type of {@link ECPublicKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public final class AsymmetricCryptorConfigEcIes<PR extends ECPrivateKey, PU extends ECPublicKey> extends AsymmetricCryptorConfig<PR, PU> {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  public static final String ALGORITHM_ECIES = "ECIES";

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider}.
   */
  public AsymmetricCryptorConfigEcIes(SecurityProvider provider) {

    super(new CipherTransformation(ALGORITHM_ECIES), 0, provider);
  }

}
