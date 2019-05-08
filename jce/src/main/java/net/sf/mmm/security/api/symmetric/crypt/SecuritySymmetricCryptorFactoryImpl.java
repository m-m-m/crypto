package net.sf.mmm.security.api.symmetric.crypt;

import java.security.Key;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.sf.mmm.security.api.crypt.SecurityCryptorConfig;
import net.sf.mmm.security.api.crypt.SecurityCryptorFactoryImpl;
import net.sf.mmm.security.api.crypt.SecurityDecryptor;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;
import net.sf.mmm.security.api.random.SecurityRandomFactory;

/**
 * Implementation of {@link SecuritySymmetricCryptorFactory}.
 *
 * @param <K> type of {@link SecretKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySymmetricCryptorFactoryImpl<K extends SecretKey> extends SecurityCryptorFactoryImpl
    implements SecuritySymmetricCryptorFactory<K> {

  private final SecuritySymmetricCryptorConfig config;

  /**
   * The constructor.
   *
   * @param config the {@link SecuritySymmetricCryptorConfig}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecuritySymmetricCryptorFactoryImpl(SecuritySymmetricCryptorConfig config, SecurityRandomFactory randomFactory) {

    super(config.getProvider(), randomFactory);
    this.config = config;
  }

  @Override
  public SecurityDecryptor newDecryptorUnsafe(Key decryptionKey) {

    Key key = transformKey(decryptionKey);
    return super.newDecryptorUnsafe(key);
  }

  @Override
  public SecurityEncryptor newEncryptorUnsafe(Key encryptionKey) {

    Key key = transformKey(encryptionKey);
    return super.newEncryptorUnsafe(key);
  }

  @Override
  public SecuritySymmetricCryptorConfig getConfig() {

    return this.config;
  }

  private Key transformKey(Key encryptionKey) {

    Key key = encryptionKey;
    String algorithm = getKeyAlgorithm(getConfig());
    if (!encryptionKey.getAlgorithm().equals(algorithm) && (encryptionKey instanceof SecretKey)) {
      key = new SecretKeySpec(encryptionKey.getEncoded(), algorithm);
    }
    return key;
  }

  private static String getKeyAlgorithm(SecurityCryptorConfig config) {

    String algorithm = config.getAlgorithm();
    int firstSlashIndex = algorithm.indexOf('/');
    if (firstSlashIndex > 0) {
      algorithm = algorithm.substring(0, firstSlashIndex);
    }
    return algorithm;
  }

}
