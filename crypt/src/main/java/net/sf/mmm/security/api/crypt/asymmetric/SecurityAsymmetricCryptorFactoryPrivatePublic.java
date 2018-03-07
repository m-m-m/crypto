package net.sf.mmm.security.api.crypt.asymmetric;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.crypt.SecurityDecryptor;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;

/**
 * Extends {@link SecurityAsymmetricCryptorFactory} for cryptography where you can encrypt using
 * {@link java.security.PublicKey} and decrypt using {@link java.security.PrivateKey} (but not vice versa) such as e.g.
 * {@link SecurityAsymmetricCryptorConfigEcies ECIES}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAsymmetricCryptorFactoryPrivatePublic extends SecurityAsymmetricCryptorFactory {

  /**
   * @param encryptionKey the {@link PrivateKey} to use for encryption.
   * @return the {@link SecurityEncryptor} for encryption.
   */
  default SecurityEncryptor newEncryptor(PrivateKey encryptionKey) {

    return newEncryptorUnsafe(encryptionKey);
  }

  /**
   * @param encryptionKey the {@link SecurityPrivateKey} to use for encryption.
   * @return the {@link SecurityEncryptor} for encryption.
   */
  default SecurityEncryptor newEncryptor(SecurityPrivateKey encryptionKey) {

    return newEncryptor(encryptionKey.getKey());
  }

  /**
   * @param decryptionKey the {@link PublicKey} to use for decryption.
   * @return the {@link SecurityDecryptor} for decryption.
   */
  default SecurityDecryptor newDecryptor(PublicKey decryptionKey) {

    return newDecryptorUnsafe(decryptionKey);
  }

  /**
   * @param decryptionKey the {@link SecurityPublicKey} to use for decryption.
   * @return the {@link SecurityDecryptor} for decryption.
   */
  default SecurityDecryptor newDecryptor(SecurityPublicKey decryptionKey) {

    return newDecryptor(decryptionKey.getKey());
  }

}
