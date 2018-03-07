package net.sf.mmm.security.api.key;

import java.util.Set;

import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKey;

/**
 * Interface for a {@link Set} of {@link SecurityKey}s that strictly belong together.
 *
 * @see SecuritySymmetricKey
 * @see SecurityAsymmetricKeyPair
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityKeySet {

  /**
   * @return the {@link Set} of {@link SecurityKey}s contained in this {@link SecurityKeySet}.
   */
  Set<? extends SecurityKey<?>> getKeys();

}
