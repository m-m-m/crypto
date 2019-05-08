package net.sf.mmm.security.api.key;

import java.security.Key;
import java.util.Set;

/**
 * Interface for a {@link Set} of {@link java.security.Key}s that belong together.
 *
 * @see net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPair
 * @see net.sf.mmm.security.api.symmetric.key.SecuritySymmetricKey
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityKeySet {

  /**
   * @return the {@link Set} of {@link Key}s contained in this {@link SecurityKeySet}.
   */
  Set<Key> getKeys();

}
