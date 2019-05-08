package net.sf.mmm.security.api.asymmetric.key;

import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.Set;

import net.sf.mmm.security.api.key.SecurityKeySet;

/**
 * Interface for a key pair consisting of a {@link #getPrivateKey() private key} with its corresponding
 * {@link #getPublicKey() public key} for asymmetric encryption. The big advantage of asymmetric encryption is that no
 * secret has to be shared between the parties. The {@link PublicKey public key} can be made public and shared. Anybody
 * knowing your public key can
 * {@link net.sf.mmm.security.api.asymmetric.crypt.SecurityAsymmetricCryptorFactory#newEncryptor(PublicKey) encrypt}
 * data for you that only you as the owner of the corresponding {@link PrivateKey private key} can
 * {@link net.sf.mmm.security.api.asymmetric.crypt.SecurityAsymmetricCryptorFactory#newDecryptor(PrivateKey) decrypt}.
 * On the other hand only you as the owner of the {@link PrivateKey private key} can
 * {@link net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureSigner#sign(byte[], boolean) sign} arbitrary data in a way so
 * that everybody can {@link net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureVerifier#verifyAfterUpdate(byte[]) verify}
 * this signature using your {@link PublicKey public key}.
 *
 * @param <PR> type of {@link #getPrivateKey()}
 * @param <PU> type of {@link #getPublicKey()}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAsymmetricKeyPair<PR extends PrivateKey, PU extends PublicKey> extends SecurityKeySet {

  /**
   * @return the {@link PrivateKey private key}. Has to be kept secret.
   */
  PR getPrivateKey();

  /**
   * @return the {@link PublicKey public key}. May be distributed or published.
   */
  PU getPublicKey();

  /**
   * @return the private and public key as java standard {@link KeyPair}.
   */
  KeyPair getKeyPair();

  @Override
  default Set<Key> getKeys() {

    Set<Key> set = new HashSet<>();
    set.add(getPrivateKey());
    set.add(getPublicKey());
    return set;
  }

}
