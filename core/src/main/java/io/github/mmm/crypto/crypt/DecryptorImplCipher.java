package io.github.mmm.crypto.crypt;

import java.security.Key;

import io.github.mmm.crypto.random.RandomFactory;

/// Implementation of [Decryptor] based on [javax.crypto.Cipher].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class DecryptorImplCipher extends CryptorImplCipher implements AbstractDecryptor {

  /// The constructor.
  ///
  /// @param randomFactory the [RandomFactory] to use.
  /// @param config the [CryptorConfig].
  /// @param key the [Key] to use.
  public DecryptorImplCipher(RandomFactory randomFactory, CryptorConfig config, Key key) {

    super(randomFactory, config, key);
  }

  @Override
  protected boolean isEncryptor() {

    return false;
  }

}
