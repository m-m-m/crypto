package net.sf.mmm.security.api.asymmetric.crypt;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.crypt.SecurityCryptorFactory;
import net.sf.mmm.security.api.crypt.SecurityDecryptor;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;

/**
 * Extends {@link SecurityCryptorFactory} for {@link net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPair
 * asymmetric} encryption and decryption.
 *
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAsymmetricCryptorFactory<PR extends PrivateKey, PU extends PublicKey> extends SecurityCryptorFactory {

  /**
   * @param publicKey the {@link PublicKey} to use for encryption.
   * @return the {@link SecurityEncryptor} for encryption.
   */
  default SecurityEncryptor newEncryptor(PU publicKey) {

    return newEncryptorUnsafe(publicKey);
  }

  /**
   * @param privateKey the {@link PrivateKey} to use for decryption.
   * @return the {@link SecurityDecryptor} for decryption.
   */
  default SecurityDecryptor newDecryptor(PR privateKey) {

    return newDecryptorUnsafe(privateKey);
  }

}
