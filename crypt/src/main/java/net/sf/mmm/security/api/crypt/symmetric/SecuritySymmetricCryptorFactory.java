package net.sf.mmm.security.api.crypt.symmetric;

import javax.crypto.SecretKey;

import net.sf.mmm.security.api.crypt.SecurityCryptorFactory;
import net.sf.mmm.security.api.crypt.SecurityDecryptor;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKey;

/**
 * Extends {@link SecurityCryptorFactory} for {@link SecuritySymmetricKey symmetric} encryption and decryption.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecuritySymmetricCryptorFactory extends SecurityCryptorFactory {

  /**
   * @param encryptionKey the {@link SecretKey} to use for encryption.
   * @return the {@link SecurityEncryptor} for encryption.
   */
  default SecurityEncryptor newEncryptor(SecretKey encryptionKey) {

    return newEncryptorUnsafe(encryptionKey);
  }

  /**
   * @param encryptionKey the {@link SecuritySymmetricKey} to use for encryption.
   * @return the {@link SecurityEncryptor} for encryption.
   */
  default SecurityEncryptor newEncryptor(SecuritySymmetricKey encryptionKey) {

    return newEncryptor(encryptionKey.getKey());
  }

  /**
   * @param decryptionKey the {@link SecretKey} to use for decryption.
   * @return the {@link SecurityDecryptor} for decryption.
   */
  default SecurityDecryptor newDecryptor(SecretKey decryptionKey) {

    return newDecryptorUnsafe(decryptionKey);
  }

  /**
   * @param decryptionKey the {@link SecuritySymmetricKey} to use for decryption.
   * @return the {@link SecurityDecryptor} for decryption.
   */
  default SecurityDecryptor newDecryptor(SecuritySymmetricKey decryptionKey) {

    return newDecryptor(decryptionKey.getKey());
  }

}
