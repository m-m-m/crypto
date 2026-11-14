package io.github.mmm.crypto.symmetric.crypt;

import io.github.mmm.crypto.crypt.CipherTransformation;
import io.github.mmm.crypto.crypt.CryptorConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/// [CryptorConfig] for [symmetric encryption][SymmetricCryptorFactory].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class SymmetricCryptorConfig extends CryptorConfig {

  /// The constructor.
  ///
  /// @param transformation the [transfomation][#getTransformation()] for the [javax.crypto.Cipher].
  /// @param nonceSize the [nonce size][#getNonceSize()].
  /// @param provider the [SecurityProvider].
  public SymmetricCryptorConfig(CipherTransformation transformation, SecurityProvider provider, int nonceSize) {

    super(transformation, provider, nonceSize);
  }

}
