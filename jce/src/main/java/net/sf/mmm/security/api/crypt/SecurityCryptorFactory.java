package net.sf.mmm.security.api.crypt;

import java.security.Key;

import net.sf.mmm.security.api.AbstractSecurityFactory;

/**
 * Abstract interface for a {@link AbstractSecurityFactory factory} to create instances of {@link SecurityCryptor} for
 * asymmetric cryptography. Please use typesafe methods {@code newEncryptor} for encryption and {@code newDecryptor} for
 * decryption from the according sub-interfaces instead of {@link #newEncryptorUnsafe(Key)} and
 * {@link #newDecryptorUnsafe(Key)}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface SecurityCryptorFactory extends AbstractSecurityFactory {

  /**
   * Please use typesafe {@code newDecryptor} method instead to avoid mistakes (passing wrong {@link Key}).
   *
   * @param encryptionKey the {@link Key} to use for encryption.
   * @return the {@link SecurityEncryptor} for encryption.
   */
  SecurityEncryptor newEncryptorUnsafe(Key encryptionKey);

  /**
   * Please use typesafe {@code newEncryptor} method instead to avoid mistakes (passing wrong {@link Key}).
   *
   * @param decryptionKey the {@link Key} to use for decryption.
   * @return the {@link SecurityDecryptor} for decryption.
   */
  SecurityDecryptor newDecryptorUnsafe(Key decryptionKey);

}
