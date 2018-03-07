package net.sf.mmm.security.api.key.store;

import java.security.KeyStore;

import net.sf.mmm.security.api.cert.SecurityCertificatePath;
import net.sf.mmm.security.api.key.SecurityKeySet;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKey;

/**
 * Wrapper for a {@link KeyStore} with ability to {@link #save() save}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityKeyStore {

  /**
   * @return the underlying {@link KeyStore}.
   */
  KeyStore getKeyStore();

  /**
   * @param alias the alias under which the key pair shall be stored.
   * @param password the passphrase used to secure the {@link SecurityKeySet}.
   * @return the {@link SecurityKeySet} loaded from the key store.
   */
  SecurityKeySet getKeyPair(String alias, String password);

  /**
   * @param alias the alias under which the key pair shall be stored.
   * @param keyPair the {@link SecurityAsymmetricKeyPair} to store.
   * @param password the passphrase used to secure the {@link SecurityKeySet}.
   * @param certificatePath the {@link SecurityCertificatePath}.
   */
  void setKeyPair(String alias, SecurityAsymmetricKeyPair keyPair, String password,
      SecurityCertificatePath certificatePath);

  /**
   * @param alias the alias under which the key pair shall be stored.
   * @param key the {@link SecuritySymmetricKey} to store.
   * @param password the passphrase used to secure the {@link SecurityKeySet}.
   */
  void setKeyPair(String alias, SecuritySymmetricKey key, String password);

  /**
   * Saves all the key store with all changes.
   */
  void save();

}
