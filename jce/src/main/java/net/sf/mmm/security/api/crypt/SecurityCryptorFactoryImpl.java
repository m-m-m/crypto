package net.sf.mmm.security.api.crypt;

import java.security.Key;

import javax.crypto.Cipher;

import net.sf.mmm.security.api.AbstractSecurityAlgorithmWithRandom;
import net.sf.mmm.security.api.provider.SecurityProvider;
import net.sf.mmm.security.api.random.SecurityRandomFactory;

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
   * @param provider the security {@link SecurityProvider}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecurityCryptorFactoryImpl(SecurityProvider provider, SecurityRandomFactory randomFactory) {

    super(provider, randomFactory);
  }

  /**
   * @return the {@link SecurityCryptorConfig}.
   */
  public abstract SecurityCryptorConfig getConfig();

  @Override
  public String getAlgorithm() {

    return getConfig().getAlgorithm();
  }

  @Override
  public SecurityEncryptor newEncryptorUnsafe(Key encryptionKey) {

    return new SecurityEncryptorImplCiper(getRandomFactory(), getConfig(), encryptionKey);
  }

  @Override
  public SecurityDecryptor newDecryptorUnsafe(Key decryptionKey) {

    return new SecurityDecryptorImplCipher(getRandomFactory(), getConfig(), decryptionKey);
  }

}
