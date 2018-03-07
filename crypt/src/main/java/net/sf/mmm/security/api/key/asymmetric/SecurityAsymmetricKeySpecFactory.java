package net.sf.mmm.security.api.key.asymmetric;

import java.security.spec.KeySpec;

/**
 * Interface for a factory used to {@link #createKeySpec(byte[]) create} {@link KeySpec}s from
 * {@link net.sf.mmm.security.api.key.SecurityKey#getData() serialized key data}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAsymmetricKeySpecFactory {

  /**
   * @param key the {@link net.sf.mmm.security.api.key.SecurityKey#getData() raw data} of the key.
   * @return the {@link KeySpec} for the given {@code key} data.
   */
  KeySpec createKeySpec(byte[] key);

}
