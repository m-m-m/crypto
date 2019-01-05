package net.sf.mmm.security.api.key;

import java.security.Key;

import net.sf.mmm.util.datatype.api.Binary;

/**
 * Abstract interface for a security key used for encryption/decryption and signatures.
 *
 * @see net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKey
 * @see net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKey
 *
 * @param <K> the type of the wrapped {@link #getKey()}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface SecurityKey<K extends Key> extends Binary {

  /**
   * @return the underlying {@link Key}. It may be lazily parsed on the first call of this method.
   */
  K getKey();

}
