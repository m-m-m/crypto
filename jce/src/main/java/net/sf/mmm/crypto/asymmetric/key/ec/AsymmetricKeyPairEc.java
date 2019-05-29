package net.sf.mmm.crypto.asymmetric.key.ec;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import net.sf.mmm.crypto.asymmetric.key.AbstractAsymmetricKeyPair;
import net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyPair;

/**
 * Abstract base implementation of {@link AsymmetricKeyPair} for {@link ECPrivateKey} and {@link ECPublicKey}.
 *
 * @param <PR> type of {@link #getPrivateKey() private key}.
 * @param <PU> type of {@link #getPublicKey() public key}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class AsymmetricKeyPairEc<PR extends ECPrivateKey, PU extends ECPublicKey>
    extends AbstractAsymmetricKeyPair<PR, PU> {

  /**
   * The {@link net.sf.mmm.crypto.algorithm.CryptoAlgorithm#getAlgorithm() algorithm} name {@value} for
   * <a href="https://en.wikipedia.org/wiki/Elliptic_curve_cryptography">ECC</a>.
   */
  public static final String ALGORITHM_EC = "EC";

  /** Format for compact binary representation. */
  public static final String FORMAT_UNCOMORESSED = "Uncompressed";

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   * @param publicKey the {@link #getPrivateKey() public key}.
   */
  public AsymmetricKeyPairEc(PR privateKey, PU publicKey) {

    super(privateKey, publicKey);
  }

}
