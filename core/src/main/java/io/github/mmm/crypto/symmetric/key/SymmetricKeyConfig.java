package io.github.mmm.crypto.symmetric.key;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import io.github.mmm.crypto.key.KeyConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/// [KeyConfig] for symmetric cryptography.
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public abstract class SymmetricKeyConfig extends KeyConfig {

  private final SymmetricKeySpecFactory keySpecFactory;

  /// The constructor.
  ///
  /// @param algorithm the [algorithm][#getAlgorithm()].
  /// @param provider the [SecurityProvider].
  /// @param keyLength the [key length][#getKeyLength()] in bits.
  /// @param keySpecFactory the [key spec factory][#getKeySpecFactory()].
  public SymmetricKeyConfig(String algorithm, SecurityProvider provider, int keyLength,
      SymmetricKeySpecFactory keySpecFactory) {

    super(algorithm, provider, keyLength);
    this.keySpecFactory = keySpecFactory;
  }

  /// @return the [SymmetricKeySpecFactory].
  public SymmetricKeySpecFactory getKeySpecFactory() {

    return this.keySpecFactory;
  }

  /// @param key the [SecretKey].
  /// @param keyFactory the [SecretKeyFactory].
  /// @return the [key length][#getKeyLength()] of the given [SecretKey].
  public abstract int getKeyLength(SecretKey key, SecretKeyFactory keyFactory);
}
