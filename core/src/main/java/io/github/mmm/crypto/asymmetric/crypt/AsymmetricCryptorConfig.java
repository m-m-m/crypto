package io.github.mmm.crypto.asymmetric.crypt;

import java.security.PrivateKey;
import java.security.PublicKey;

import io.github.mmm.crypto.crypt.CipherTransformation;
import io.github.mmm.crypto.crypt.CryptorConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/// [CryptorConfig] for [asymmetric cryptography][io.github.mmm.crypto.asymmetric.key.AsymmetricKeyPair].
///
/// @param <PR> type of [PrivateKey].
/// @param <PU> type of [PublicKey].
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public abstract class AsymmetricCryptorConfig<PR extends PrivateKey, PU extends PublicKey> extends CryptorConfig {

  /// The constructor.
  ///
  /// @param transformation the [transfomation][#getTransformation()] for the [javax.crypto.Cipher].
  /// @param nonceSize the [nonce size][#getNonceSize()].
  /// @param provider the [SecurityProvider].
  public AsymmetricCryptorConfig(CipherTransformation transformation, int nonceSize, SecurityProvider provider) {

    super(transformation, provider, nonceSize);
  }

  /// @return `true` if the underlying asymmetric encryption algorithm is bidirectional and also allows to encrypt with
  ///         private key and decrypt with public key (like e.g. RSA), `false` otherwise (default).
  public boolean isBidirectional() {

    return false;
  }

}
