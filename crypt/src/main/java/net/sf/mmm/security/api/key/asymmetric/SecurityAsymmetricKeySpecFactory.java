package net.sf.mmm.security.api.key.asymmetric;

import java.security.spec.KeySpec;

import net.sf.mmm.security.api.key.SecurityKey;

/**
 * Interface for a factory used to {@link #createKeySpec(byte[]) create} {@link KeySpec}s from
 * {@link net.sf.mmm.security.api.key.SecurityKey#getData() compact key data} or {@link java.security.Key#getEncoded()
 * encoded key data}.
 *
 * @param <K> type of the {@link SecurityKey} corresponding to the {@link KeySpec}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAsymmetricKeySpecFactory<K extends SecurityKey<?>> {

  /**
   * @param key the {@link net.sf.mmm.util.datatype.api.Binary#getData() raw binary data} in
   *        {@link net.sf.mmm.security.api.key.SecurityKey#getData() compact} or {@link java.security.Key#getEncoded()
   *        encoded} form of the key.
   * @return the {@link KeySpec} for the given {@code key} data.
   */
  KeySpec createKeySpec(byte[] key);

}
