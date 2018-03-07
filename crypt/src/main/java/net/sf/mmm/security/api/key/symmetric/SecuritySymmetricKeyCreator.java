package net.sf.mmm.security.api.key.symmetric;

import javax.crypto.SecretKey;

import net.sf.mmm.security.api.key.SecurityKeyCreator;
import net.sf.mmm.util.lang.api.BinaryType;

/**
 * Extends {@link SecurityKeyCreator} for dealing with symmetric cryptographic keys.
 *
 * @see #createKey(SecretKey)
 * @see #createKey(String)
 * @see #createKey(String)
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface SecuritySymmetricKeyCreator extends SecurityKeyCreator, SecuritySymmetricKeyConstants {

  /**
   * @param password the secret password.
   * @return the according {@link SecuritySymmetricKey}.
   */
  SecuritySymmetricKey createKey(String password);

  /**
   * @param secretKey the raw {@link SecretKey}.
   * @return the wrapped {@link SecuritySymmetricKey}.
   */
  default SecuritySymmetricKey createKey(SecretKey secretKey) {

    return new SecuritySymmetricKeyGeneric(secretKey);
  }

  /**
   * @param key the {@link SecuritySymmetricKey} as raw {@code byte} array.
   * @return the deserialized {@link SecuritySymmetricKey}.
   */
  SecuritySymmetricKey deserializeKey(byte[] key);

  /**
   * @param key the {@link SecuritySymmetricKey} in {@link net.sf.mmm.util.lang.api.BinaryType#getHex() hex
   *        representation}.
   * @return the deserialized {@link SecuritySymmetricKey}.
   */
  default SecuritySymmetricKey deserializeKey(String key) {

    return deserializeKey(BinaryType.parseHex(key));
  }
}
