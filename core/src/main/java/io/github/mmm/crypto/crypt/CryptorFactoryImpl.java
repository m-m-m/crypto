package io.github.mmm.crypto.crypt;

import java.security.Key;

import javax.crypto.Cipher;

import io.github.mmm.crypto.algorithm.AbstractCryptoAlgorithmWithRandom;
import io.github.mmm.crypto.provider.SecurityProvider;
import io.github.mmm.crypto.random.RandomFactory;

/// The implementation of [CryptorFactory] based on [Cipher].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public abstract class CryptorFactoryImpl extends AbstractCryptoAlgorithmWithRandom implements CryptorFactory {

  /// The constructor.
  ///
  /// @param provider the security [SecurityProvider].
  /// @param randomFactory the [RandomFactory].
  public CryptorFactoryImpl(SecurityProvider provider, RandomFactory randomFactory) {

    super(provider, randomFactory);
  }

  /// @return the [CryptorConfig].
  public abstract CryptorConfig getConfig();

  @Override
  public String getAlgorithm() {

    return getConfig().getAlgorithm();
  }

  @Override
  public Encryptor newEncryptorUnsafe(Key encryptionKey) {

    return new EncryptorImplCiper(getRandomFactory(), getConfig(), encryptionKey);
  }

  @Override
  public Decryptor newDecryptorUnsafe(Key decryptionKey) {

    return new DecryptorImplCipher(getRandomFactory(), getConfig(), decryptionKey);
  }

}
