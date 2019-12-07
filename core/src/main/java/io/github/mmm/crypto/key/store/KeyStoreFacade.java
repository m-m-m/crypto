package io.github.mmm.crypto.key.store;

import java.security.KeyStore;
import java.util.Objects;

import javax.crypto.SecretKey;

import io.github.mmm.crypto.asymmetric.cert.CertificatePath;
import io.github.mmm.crypto.asymmetric.key.AsymmetricKeyPair;
import io.github.mmm.crypto.key.KeySet;
import io.github.mmm.crypto.symmetric.key.SymmetricKey;

/**
 * Wrapper for a {@link KeyStore} with ability to {@link #save() save}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface KeyStoreFacade {

  /**
   * @return the underlying {@link KeyStore}.
   */
  KeyStore getKeyStore();

  /**
   * @param alias the alias under which the key pair shall be stored.
   * @param password the passphrase used to secure the {@link KeySet}.
   * @return the {@link KeySet} loaded from the key store.
   */
  KeySet getKey(String alias, String password);

  /**
   * @param alias the alias under which the key pair shall be stored.
   * @param keyPair the {@link AsymmetricKeyPair} to store.
   * @param password the passphrase used to secure the {@link KeySet}.
   * @param certificatePath the {@link CertificatePath}.
   */
  void setKey(String alias, AsymmetricKeyPair<?, ?> keyPair, String password, CertificatePath certificatePath);

  /**
   * @param alias the alias under which the key pair shall be stored.
   * @param key the {@link SecretKey} to store.
   * @param password the passphrase used to secure the {@link KeySet}.
   */
  void setKey(String alias, SecretKey key, String password);

  /**
   * @param alias the alias under which the key pair shall be stored.
   * @param key the {@link SymmetricKey} to store.
   * @param password the passphrase used to secure the {@link KeySet}.
   */
  default void setKey(String alias, SymmetricKey<?> key, String password) {

    Objects.requireNonNull(key, "key");
    setKey(alias, key.getKey(), password);
  }

  /**
   * Saves this key store with all changes.
   */
  void save();

}
