package net.sf.mmm.security.api.crypt;

import java.io.InputStream;

/**
 * Extends {@link SecurityCryptor} with methods specific for decryption.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityDecryptor extends SecurityCryptor {

  /**
   * @param stream the {@link InputStream} to wrap.
   * @return the wrapped {@link InputStream} that reads from the given {@link InputStream} after performing decryption.
   */
  InputStream wrapStream(InputStream stream);

  /**
   * @param decryptors the {@link SecurityDecryptor}s to combine with this instance.
   * @return a {@link SecurityDecryptor} that combines this {@link SecurityDecryptor} with the given
   *         {@link SecurityDecryptor}s as a chain in that order.
   */
  SecurityDecryptor combine(SecurityDecryptor... decryptors);

}
