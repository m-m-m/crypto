package net.sf.mmm.crypto.asymmetric.key.generic;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.crypto.asymmetric.key.AbstractAsymmetricKeyPair;
import net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyPair;

/**
 * A generic implementation of {@link AsymmetricKeyPair}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class AsymmetricKeyPairGeneric extends AbstractAsymmetricKeyPair<PrivateKey, PublicKey> {

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   * @param publicKey the {@link #getPrivateKey() public key}.
   */
  public AsymmetricKeyPairGeneric(PrivateKey privateKey, PublicKey publicKey) {

    super(privateKey, publicKey);
  }

  /**
   * The constructor.
   *
   * @param keyPair the {@link #getKeyPair() key pair}.
   */
  public AsymmetricKeyPairGeneric(KeyPair keyPair) {

    super(keyPair);
  }

}
