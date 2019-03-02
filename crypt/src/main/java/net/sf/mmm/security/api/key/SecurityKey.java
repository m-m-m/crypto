package net.sf.mmm.security.api.key;

import java.security.Key;

import net.sf.mmm.util.datatype.api.Binary;

/**
 * Abstract interface for a security key used for encryption and decryption as well as for signatures. The JCE standard
 * interfaces like {@link Key} are wrapped for several reasons. The most important one is performance. Implementations
 * of this API will create {@link SecurityKey} instances lazily. So you can read keys from their raw data very fast but
 * only parse the underlying key when it is required. Further, this {@link SecurityKey} interface provides access to get
 * the {@link Key} as {@link #getData() compact binary data}. This will be much smaller than the to the universal
 * {@link Key#getEncoded() encoded binary data}. However, the compact data can only be de-serialized using the same
 * {@link SecurityKeyFactory} that created the key. Implementations of {@link SecurityKeyFactory} will accept both forms
 * of binary representations so you do not need to worry.
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
