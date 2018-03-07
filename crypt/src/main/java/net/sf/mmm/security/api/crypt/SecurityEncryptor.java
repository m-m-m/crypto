package net.sf.mmm.security.api.crypt;

import java.io.OutputStream;

/**
 * Extends {@link SecurityCryptor} with methods specific for encryption.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityEncryptor extends SecurityCryptor {

  /**
   * @param stream the {@link OutputStream} to wrap.
   * @return the wrapped {@link OutputStream} that writes to the given {@link OutputStream} after performing encryption.
   */
  OutputStream wrapStream(OutputStream stream);

  /**
   * @param encryptors the {@link SecurityEncryptor}s to combine with this instance.
   * @return a {@link SecurityEncryptor} that combines this {@link SecurityEncryptor} with the given
   *         {@link SecurityEncryptor}s as a chain in that order.
   */
  SecurityEncryptor combine(SecurityEncryptor... encryptors);

}
