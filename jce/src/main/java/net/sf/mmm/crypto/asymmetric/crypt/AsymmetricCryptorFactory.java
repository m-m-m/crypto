package net.sf.mmm.crypto.asymmetric.crypt;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.crypto.crypt.CryptorFactory;
import net.sf.mmm.crypto.crypt.Decryptor;
import net.sf.mmm.crypto.crypt.Encryptor;

/**
 * Extends {@link CryptorFactory} for {@link net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyPair
 * asymmetric} encryption and decryption.
 *
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AsymmetricCryptorFactory<PR extends PrivateKey, PU extends PublicKey> extends CryptorFactory {

  /**
   * @param publicKey the {@link PublicKey} to use for encryption.
   * @return the {@link Encryptor} for encryption.
   */
  default Encryptor newEncryptor(PU publicKey) {

    return newEncryptorUnsafe(publicKey);
  }

  /**
   * @param privateKey the {@link PrivateKey} to use for decryption.
   * @return the {@link Decryptor} for decryption.
   */
  default Decryptor newDecryptor(PR privateKey) {

    return newDecryptorUnsafe(privateKey);
  }

}
