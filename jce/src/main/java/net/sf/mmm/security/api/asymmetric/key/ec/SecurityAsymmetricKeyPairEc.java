package net.sf.mmm.security.api.asymmetric.key.ec;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import net.sf.mmm.security.api.asymmetric.key.AbstractSecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPair;

/**
 * Abstract base implementation of {@link SecurityAsymmetricKeyPair} for {@link ECPrivateKey} and {@link ECPublicKey}.
 *
 * @param <PR> type of {@link #getPrivateKey() private key}.
 * @param <PU> type of {@link #getPublicKey() public key}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyPairEc<PR extends ECPrivateKey, PU extends ECPublicKey>
    extends AbstractSecurityAsymmetricKeyPair<PR, PU> {

  /** Format for compact binary representation. */
  public static final String FORMAT_UNCOMORESSED = "Uncompressed";

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   * @param publicKey the {@link #getPrivateKey() public key}.
   */
  public SecurityAsymmetricKeyPairEc(PR privateKey, PU publicKey) {

    super(privateKey, publicKey);
  }

}
