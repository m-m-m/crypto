package io.github.mmm.crypto.symmetric.crypt;

import java.security.Key;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import io.github.mmm.crypto.crypt.CryptorConfig;
import io.github.mmm.crypto.crypt.CryptorFactoryImpl;
import io.github.mmm.crypto.crypt.Decryptor;
import io.github.mmm.crypto.crypt.Encryptor;
import io.github.mmm.crypto.random.RandomFactory;

/**
 * Implementation of {@link SymmetricCryptorFactory}.
 *
 * @param <K> type of {@link SecretKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SymmetricCryptorFactoryImpl<K extends SecretKey> extends CryptorFactoryImpl
    implements SymmetricCryptorFactory<K> {

  private final SymmetricCryptorConfig config;

  /**
   * The constructor.
   *
   * @param config the {@link SymmetricCryptorConfig}.
   * @param randomFactory the {@link RandomFactory}.
   */
  public SymmetricCryptorFactoryImpl(SymmetricCryptorConfig config, RandomFactory randomFactory) {

    super(config.getProvider(), randomFactory);
    this.config = config;
  }

  @Override
  public Decryptor newDecryptorUnsafe(Key decryptionKey) {

    Key key = transformKey(decryptionKey);
    return super.newDecryptorUnsafe(key);
  }

  @Override
  public Encryptor newEncryptorUnsafe(Key encryptionKey) {

    Key key = transformKey(encryptionKey);
    return super.newEncryptorUnsafe(key);
  }

  @Override
  public SymmetricCryptorConfig getConfig() {

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

  private static String getKeyAlgorithm(CryptorConfig config) {

    String algorithm = config.getAlgorithm();
    int firstSlashIndex = algorithm.indexOf('/');
    if (firstSlashIndex > 0) {
      algorithm = algorithm.substring(0, firstSlashIndex);
    }
    return algorithm;
  }

}
