package io.github.mmm.crypto.asymmetric.crypt;

import java.security.PrivateKey;
import java.security.PublicKey;

import io.github.mmm.crypto.crypt.CryptorFactoryImpl;
import io.github.mmm.crypto.random.RandomFactory;

/// Implementation of [AsymmetricCryptorFactory].
///
/// @param <PR> type of [PrivateKey].
/// @param <PU> type of [PublicKey].
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class AsymmetricCryptorFactoryImpl<PR extends PrivateKey, PU extends PublicKey> extends CryptorFactoryImpl
    implements AsymmetricCryptorFactory<PR, PU> {

  private final AsymmetricCryptorConfig<PR, PU> config;

  /// The constructor.
  ///
  /// @param config the [AsymmetricCryptorConfig].
  /// @param randomFactory the [RandomFactory].
  public AsymmetricCryptorFactoryImpl(AsymmetricCryptorConfig<PR, PU> config, RandomFactory randomFactory) {

    super(config.getProvider(), randomFactory);
    this.config = config;
  }

  @Override
  public AsymmetricCryptorConfig<PR, PU> getConfig() {

    return this.config;
  }

}
