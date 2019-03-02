package net.sf.mmm.security.impl.crypt;

import java.security.Key;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.sf.mmm.security.api.crypt.SecurityCryptorConfig;
import net.sf.mmm.security.api.crypt.SecurityCryptorFactory;
import net.sf.mmm.security.api.crypt.SecurityDecryptor;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;
import net.sf.mmm.security.api.random.SecurityRandomFactory;
import net.sf.mmm.security.impl.AbstractSecurityAlgorithmWithRandom;

/**
 * The implementation of {@link SecurityCryptorFactory} based on {@link Cipher}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecurityCryptorFactoryImpl extends AbstractSecurityAlgorithmWithRandom implements SecurityCryptorFactory {

  /**
   * The constructor.
   *
   * @param provider the security {@link Provider}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecurityCryptorFactoryImpl(Provider provider, SecurityRandomFactory randomFactory) {

    super(provider, randomFactory);
  }

  /**
   * @return the {@link SecurityCryptorConfig}.
   */
  public abstract SecurityCryptorConfig<?> getConfig();

  @Override
  public String getAlgorithm() {

    return getConfig().getAlgorithm();
  }

  @Override
  public SecurityEncryptor newEncryptorUnsafe(Key encryptionKey) {

    Key key = transformKey(encryptionKey);
    return new SecurityEncryptorImplCiper(getProvider(), getRandomFactory(), getConfig(), key);
  }

  @Override
  public SecurityDecryptor newDecryptorUnsafe(Key decryptionKey) {

    Key key = transformKey(decryptionKey);
    return new SecurityDecryptorImplCipher(getProvider(), getRandomFactory(), getConfig(), key);
  }

  private Key transformKey(Key encryptionKey) {

    Key key = encryptionKey;
    String algorithm = getKeyAlgorithm(getConfig());
    if (!encryptionKey.getAlgorithm().equals(algorithm) && (encryptionKey instanceof SecretKey)) {
      key = new SecretKeySpec(encryptionKey.getEncoded(), algorithm);
    }
    return key;
  }

  private static String getKeyAlgorithm(SecurityCryptorConfig<?> config) {

    String algorithm = config.getAlgorithm();
    int firstSlashIndex = algorithm.indexOf('/');
    if (firstSlashIndex > 0) {
      algorithm = algorithm.substring(0, firstSlashIndex);
    }
    return algorithm;
  }

}
