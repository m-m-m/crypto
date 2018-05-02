package net.sf.mmm.security.api.crypt.asymmetric;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.crypt.SecurityDecryptor;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;

/**
 * Extends {@link SecurityAsymmetricCryptorFactory} for cryptography where you can encrypt using
 * {@link java.security.PublicKey} and decrypt using {@link java.security.PrivateKey}. May not necessarily work vice
 * versa as e.g. for {@link SecurityAsymmetricCryptorConfigEcies ECIES}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAsymmetricCryptorFactoryPublicPrivate extends SecurityAsymmetricCryptorFactory {

  /**
   * @param encryptionKey the {@link PublicKey} to use for encryption.
   * @return the {@link SecurityEncryptor} for encryption.
   */
  default SecurityEncryptor newEncryptor(PublicKey encryptionKey) {

    return newEncryptorUnsafe(encryptionKey);
  }

  /**
   * @param encryptionKey the {@link SecurityPublicKey} to use for encryption.
   * @return the {@link SecurityEncryptor} for encryption.
   */
  default SecurityEncryptor newEncryptor(SecurityPublicKey encryptionKey) {

    return newEncryptor(encryptionKey.getKey());
  }

  /**
   * @param decryptionKey the {@link PublicKey} to use for decryption.
   * @return the {@link SecurityDecryptor} for decryption.
   */
  default SecurityDecryptor newDecryptor(PrivateKey decryptionKey) {

    return newDecryptorUnsafe(decryptionKey);
  }

  /**
   * @param decryptionKey the {@link SecurityPrivateKey} to use for decryption.
   * @return the {@link SecurityDecryptor} for decryption.
   */
  default SecurityDecryptor newDecryptor(SecurityPrivateKey decryptionKey) {

    return newDecryptor(decryptionKey.getKey());
  }

}
