package net.sf.mmm.security.api.symmetric.crypt;

import javax.crypto.SecretKey;

import net.sf.mmm.security.api.crypt.SecurityCryptorFactory;
import net.sf.mmm.security.api.crypt.SecurityDecryptor;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;
import net.sf.mmm.security.api.symmetric.key.SecuritySymmetricKeyCreator;

/**
 * Extends {@link SecurityCryptorFactory} for {@link SecuritySymmetricKeyCreator symmetric} encryption and decryption.
 *
 * @param <K> type of {@link SecretKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecuritySymmetricCryptorFactory<K extends SecretKey> extends SecurityCryptorFactory {

  /**
   * @param encryptionKey the {@link SecretKey} to use for encryption.
   * @return the {@link SecurityEncryptor} for encryption.
   */
  default SecurityEncryptor newEncryptor(K encryptionKey) {

    return newEncryptorUnsafe(encryptionKey);
  }

  /**
   * @param decryptionKey the {@link SecretKey} to use for decryption.
   * @return the {@link SecurityDecryptor} for decryption.
   */
  default SecurityDecryptor newDecryptor(K decryptionKey) {

    return newDecryptorUnsafe(decryptionKey);
  }

}
