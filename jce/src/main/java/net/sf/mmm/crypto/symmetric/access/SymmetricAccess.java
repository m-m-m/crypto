package net.sf.mmm.crypto.symmetric.access;

import java.security.Key;
import java.util.Objects;

import javax.crypto.SecretKey;

import net.sf.mmm.crypto.CryptoAccess;
import net.sf.mmm.crypto.crypt.CryptorConfig;
import net.sf.mmm.crypto.crypt.Decryptor;
import net.sf.mmm.crypto.crypt.DecryptorImplCipher;
import net.sf.mmm.crypto.crypt.Encryptor;
import net.sf.mmm.crypto.crypt.EncryptorImplCiper;
import net.sf.mmm.crypto.key.AbstractGetKeyLength;
import net.sf.mmm.crypto.random.RandomFactory;
import net.sf.mmm.crypto.symmetric.crypt.SymmetricCryptorFactory;
import net.sf.mmm.crypto.symmetric.key.SecuritySymmetricKeyConfig;
import net.sf.mmm.crypto.symmetric.key.SecuritySymmetricKeyCreator;
import net.sf.mmm.crypto.symmetric.key.SecuritySymmetricKeyCreatorImpl;
import net.sf.mmm.crypto.symmetric.key.SecuritySymmetricKeyFactory;

/**
 * Abstract base implementation of factory for {@link SecuritySymmetricKeyCreator key management} and
 * {@link SymmetricCryptorFactory encryption/decryption} based on
 * {@link net.sf.mmm.crypto.symmetric.key.SecuritySymmetricKey symmetric} cryptography.
 *
 * @param <K> type of {@link SecretKey}.
 * @since 1.0.0
 */
public abstract class SymmetricAccess<K extends SecretKey> extends CryptoAccess implements
    SecuritySymmetricKeyFactory<SecuritySymmetricKeyCreator<K>>, SymmetricCryptorFactory<K>, AbstractGetKeyLength {

  private final SecuritySymmetricKeyConfig keyConfig;

  private final CryptorConfig cryptorConfig;

  private RandomFactory randomFactory;

  private SecuritySymmetricKeyCreator<K> keyCreator;

  /**
   * The constructor.
   *
   * @param keyConfig the {@link SecuritySymmetricKeyConfig}.
   * @param cryptorConfig the {@link CryptorConfig}.
   */
  public SymmetricAccess(SecuritySymmetricKeyConfig keyConfig, CryptorConfig cryptorConfig) {

    super();
    Objects.requireNonNull(keyConfig, "keyConfig");
    this.keyConfig = keyConfig;
    Objects.requireNonNull(cryptorConfig, "cryptorConfig");
    this.cryptorConfig = cryptorConfig;
  }

  @Override
  public SecuritySymmetricKeyCreator<K> newKeyCreator() {

    return new SecuritySymmetricKeyCreatorImpl<>(this.keyConfig);
  }

  private SecuritySymmetricKeyCreator<K> getKeyCreatorInternal() {

    if (this.keyCreator == null) {
      this.keyCreator = newKeyCreator();
    }
    return this.keyCreator;
  }

  /**
   * @return the {@link SecuritySymmetricKeyConfig}.
   */
  public SecuritySymmetricKeyConfig getKeyConfig() {

    return this.keyConfig;
  }

  /**
   * @return the {@link CryptorConfig}.
   */
  public CryptorConfig getCryptorConfig() {

    return this.cryptorConfig;
  }

  @Override
  public int getKeyLength() {

    return this.keyConfig.getKeyLength();
  }

  @Override
  public Decryptor newDecryptor(K decryptionKey) {

    getKeyCreatorInternal().verifyKey(decryptionKey);
    return newDecryptorUnsafe(decryptionKey);
  }

  @Override
  public Encryptor newEncryptor(K encryptionKey) {

    getKeyCreatorInternal().verifyKey(encryptionKey);
    return newEncryptorUnsafe(encryptionKey);
  }

  @Override
  public Encryptor newEncryptorUnsafe(Key encryptionKey) {

    return new EncryptorImplCiper(this.randomFactory, this.cryptorConfig, encryptionKey);
  }

  @Override
  public Decryptor newDecryptorUnsafe(Key decryptionKey) {

    return new DecryptorImplCipher(this.randomFactory, this.cryptorConfig, decryptionKey);
  }

}
