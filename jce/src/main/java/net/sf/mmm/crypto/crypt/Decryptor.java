package net.sf.mmm.crypto.crypt;

import java.io.InputStream;

/**
 * Extends {@link Cryptor} with methods specific for decryption.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface Decryptor extends Cryptor {

  /**
   * @param stream the {@link InputStream} to wrap.
   * @return the wrapped {@link InputStream} that reads from the given {@link InputStream} after performing decryption.
   */
  InputStream wrapStream(InputStream stream);

  /**
   * @param decryptors the {@link Decryptor}s to combine with this instance.
   * @return a {@link Decryptor} that combines this {@link Decryptor} with the given
   *         {@link Decryptor}s as a chain in that order.
   */
  Decryptor combine(Decryptor... decryptors);

}
