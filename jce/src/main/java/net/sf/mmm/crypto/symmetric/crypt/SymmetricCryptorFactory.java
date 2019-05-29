package net.sf.mmm.crypto.symmetric.crypt;

import javax.crypto.SecretKey;

import net.sf.mmm.crypto.crypt.CryptorFactory;
import net.sf.mmm.crypto.crypt.Decryptor;
import net.sf.mmm.crypto.crypt.Encryptor;
import net.sf.mmm.crypto.symmetric.key.SymmetricKeyCreator;

/**
 * Extends {@link CryptorFactory} for {@link SymmetricKeyCreator symmetric} encryption and decryption.
 *
 * @param <K> type of {@link SecretKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SymmetricCryptorFactory<K extends SecretKey> extends CryptorFactory {

  /**
   * @param encryptionKey the {@link SecretKey} to use for encryption.
   * @return the {@link Encryptor} for encryption.
   */
  default Encryptor newEncryptor(K encryptionKey) {

    return newEncryptorUnsafe(encryptionKey);
  }

  /**
   * @param decryptionKey the {@link SecretKey} to use for decryption.
   * @return the {@link Decryptor} for decryption.
   */
  default Decryptor newDecryptor(K decryptionKey) {

    return newDecryptorUnsafe(decryptionKey);
  }

}
