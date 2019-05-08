package net.sf.mmm.security.api.asymmetric.key.generic;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.asymmetric.key.AbstractSecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPair;

/**
 * A generic implementation of {@link SecurityAsymmetricKeyPair}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyPairGeneric extends AbstractSecurityAsymmetricKeyPair<PrivateKey, PublicKey> {

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   * @param publicKey the {@link #getPrivateKey() public key}.
   */
  public SecurityAsymmetricKeyPairGeneric(PrivateKey privateKey, PublicKey publicKey) {

    super(privateKey, publicKey);
  }

  /**
   * The constructor.
   *
   * @param keyPair the {@link #getKeyPair() key pair}.
   */
  public SecurityAsymmetricKeyPairGeneric(KeyPair keyPair) {

    super(keyPair);
  }

}
