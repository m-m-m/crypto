package io.github.mmm.crypto.key;

import java.security.Key;
import java.util.Set;

/**
 * Interface for a {@link Set} of {@link java.security.Key}s that belong together.
 *
 * @see io.github.mmm.crypto.asymmetric.key.AsymmetricKeyPair
 * @see io.github.mmm.crypto.symmetric.key.SymmetricKey
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface KeySet {

  /**
   * @return the {@link Set} of {@link Key}s contained in this {@link KeySet}.
   */
  Set<Key> getKeys();

}
