package io.github.mmm.crypto.crypt;

import java.io.OutputStream;

/**
 * Extends {@link Cryptor} with methods specific for encryption.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface Encryptor extends Cryptor {

  /**
   * @param stream the {@link OutputStream} to wrap.
   * @return the wrapped {@link OutputStream} that writes to the given {@link OutputStream} after performing encryption.
   */
  OutputStream wrapStream(OutputStream stream);

  /**
   * @param encryptors the {@link Encryptor}s to combine with this instance.
   * @return a {@link Encryptor} that combines this {@link Encryptor} with the given
   *         {@link Encryptor}s as a chain in that order.
   */
  Encryptor combine(Encryptor... encryptors);

}
