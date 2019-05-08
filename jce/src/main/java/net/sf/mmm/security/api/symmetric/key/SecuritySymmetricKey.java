package net.sf.mmm.security.api.symmetric.key;

import java.security.Key;
import java.util.Collections;
import java.util.Set;

import javax.crypto.SecretKey;

import net.sf.mmm.security.api.key.SecurityKeySet;

/**
 * Interface for a {@link SecurityKeySet} with a single {@link SecretKey} for symmetric encryption.
 *
 * @param <K> type of {@link SecretKey}.
 * @since 1.0.0
 */
public interface SecuritySymmetricKey<K extends SecretKey> extends SecurityKeySet {

  /**
   * @return the {@link SecretKey}.
   */
  K getKey();

  @Override
  default Set<Key> getKeys() {

    return Collections.singleton(getKey());
  }

}
