package net.sf.mmm.security.api.key.asymmetric;

import java.util.HashSet;
import java.util.Set;

import net.sf.mmm.security.api.key.SecurityKeySet;

/**
 * Interface for a key pair consisting of a {@link SecurityPrivateKey} with its corresponding {@link SecurityPublicKey}
 * for asymmetric encryption. The big advantage of asymmetric encryption is that no secret has to be shared between the
 * parties. The {@link SecurityPublicKey public key} can be made public and shared with anybody. Anybody knowing your
 * public key can encrypt data for you that only you as the owner of the corresponding {@link SecurityPrivateKey private
 * key} can decrypt. On the other hand only you can
 * {@link net.sf.mmm.security.api.sign.SecuritySignatureSigner#sign(byte[], boolean) sign} arbitrary data in a
 * way so that everybody can {@link net.sf.mmm.security.api.sign.SecuritySignatureVerifier#verifyAfterUpdate(byte[])
 * verify} this signature using your {@link SecurityPublicKey public key}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAsymmetricKeyPair extends SecurityKeySet {

  /**
   * @return the {@link SecurityPrivateKey private key}. Has to be kept secret.
   */
  SecurityPrivateKey getPrivateKey();

  /**
   * @return the {@link SecurityPublicKey public key}. May be distributed or published.
   */
  SecurityPublicKey getPublicKey();

  @Override
  default Set<SecurityAsymmetricKey<?>> getKeys() {

    Set<SecurityAsymmetricKey<?>> set = new HashSet<>();
    set.add(getPrivateKey());
    set.add(getPublicKey());
    return set;
  }

}
