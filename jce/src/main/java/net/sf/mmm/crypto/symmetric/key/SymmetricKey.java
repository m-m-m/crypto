package net.sf.mmm.crypto.symmetric.key;

import java.security.Key;
import java.util.Collections;
import java.util.Set;

import javax.crypto.SecretKey;

import net.sf.mmm.crypto.key.KeySet;

/**
 * Interface for a {@link KeySet} with a single {@link SecretKey} for symmetric encryption.
 *
 * @param <K> type of {@link SecretKey}.
 * @since 1.0.0
 */
public interface SymmetricKey<K extends SecretKey> extends KeySet {

  /**
   * @return the {@link SecretKey}.
   */
  K getKey();

  @Override
  default Set<Key> getKeys() {

    return Collections.singleton(getKey());
  }

}
