package net.sf.mmm.security.api.crypt;

import java.io.OutputStream;

/**
 * Interface to {@link #getNonceSize() get} the nonce size.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractSecurityGetNonceSize {

  /**
   * Unlike {@link javax.crypto.Cipher} this API is designed for ease of use. Some cryptographic algorithms require an
   * {@link javax.crypto.Cipher#getIV() initialization vector} (IV) and others do not. With this API you do not have to
   * care and cannot do things wrong. The nonce will be prepended automatically to the encrypted payload and
   * reconstructed from there on decryption. This works both for {@link SecurityCryptor#crypt(byte[], boolean) crypt}
   * and for {@link SecurityEncryptor#wrapStream(OutputStream) streaming}.
   *
   * @return the size of the nonce in bytes or {@code 0} for none.
   * @see javax.crypto.Cipher#getIV()
   */
  int getNonceSize();

}
