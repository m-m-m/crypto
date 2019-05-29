package net.sf.mmm.security.api.symmetric.access;

import java.security.Key;
import java.util.Objects;

import javax.crypto.SecretKey;

import net.sf.mmm.security.api.SecurityAccess;
import net.sf.mmm.security.api.crypt.SecurityCryptorConfig;
import net.sf.mmm.security.api.crypt.SecurityDecryptor;
import net.sf.mmm.security.api.crypt.SecurityDecryptorImplCipher;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;
import net.sf.mmm.security.api.crypt.SecurityEncryptorImplCiper;
import net.sf.mmm.security.api.key.AbstractSecurityGetKeyLength;
import net.sf.mmm.security.api.random.SecurityRandomFactory;
import net.sf.mmm.security.api.symmetric.crypt.SecuritySymmetricCryptorFactory;
import net.sf.mmm.security.api.symmetric.key.SecuritySymmetricKeyConfig;
import net.sf.mmm.security.api.symmetric.key.SecuritySymmetricKeyCreator;
import net.sf.mmm.security.api.symmetric.key.SecuritySymmetricKeyCreatorImpl;
import net.sf.mmm.security.api.symmetric.key.SecuritySymmetricKeyFactory;

/**
 * Abstract base implementation of factory for {@link SecuritySymmetricKeyCreator key management} and
 * {@link SecuritySymmetricCryptorFactory encryption/decryption} based on
 * {@link net.sf.mmm.security.api.symmetric.key.SecuritySymmetricKey symmetric} cryptography.
 *
 * @param <K> type of {@link SecretKey}.
 * @since 1.0.0
 */
public abstract class SecurityAccessSymmetric<K extends SecretKey> extends SecurityAccess implements
    SecuritySymmetricKeyFactory<SecuritySymmetricKeyCreator<K>>, SecuritySymmetricCryptorFactory<K>, AbstractSecurityGetKeyLength {

  private final SecuritySymmetricKeyConfig keyConfig;

  private final SecurityCryptorConfig cryptorConfig;

  private SecurityRandomFactory randomFactory;

  private SecuritySymmetricKeyCreator<K> keyCreator;

  /**
   * The constructor.
   *
   * @param keyConfig the {@link SecuritySymmetricKeyConfig}.
   * @param cryptorConfig the {@link SecurityCryptorConfig}.
   */
  public SecurityAccessSymmetric(SecuritySymmetricKeyConfig keyConfig, SecurityCryptorConfig cryptorConfig) {

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
   * @return the {@link SecurityCryptorConfig}.
   */
  public SecurityCryptorConfig getCryptorConfig() {

    return this.cryptorConfig;
  }

  @Override
  public int getKeyLength() {

    return this.keyConfig.getKeyLength();
  }

  @Override
  public SecurityDecryptor newDecryptor(K decryptionKey) {

    getKeyCreatorInternal().verifyKey(decryptionKey);
    return newDecryptorUnsafe(decryptionKey);
  }

  @Override
  public SecurityEncryptor newEncryptor(K encryptionKey) {

    getKeyCreatorInternal().verifyKey(encryptionKey);
    return newEncryptorUnsafe(encryptionKey);
  }

  @Override
  public SecurityEncryptor newEncryptorUnsafe(Key encryptionKey) {

    return new SecurityEncryptorImplCiper(this.randomFactory, this.cryptorConfig, encryptionKey);
  }

  @Override
  public SecurityDecryptor newDecryptorUnsafe(Key decryptionKey) {

    return new SecurityDecryptorImplCipher(this.randomFactory, this.cryptorConfig, decryptionKey);
  }

}
