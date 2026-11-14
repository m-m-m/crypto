package io.github.mmm.crypto.key;

import io.github.mmm.crypto.algorithm.CryptoAlgorithmConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/// Abstract base class of an [algorithm configuration][CryptoAlgorithmConfig] for dealing with
/// [java.security.Key]s.
///
/// @see KeyCreatorFactory
/// @see KeyCreator
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public abstract class KeyConfig extends CryptoAlgorithmConfig implements AbstractGetKeyLength {

  private final int keyLength;

  /// The constructor.
  ///
  /// @param algorithm the [algorithm][#getAlgorithm()].
  /// @param provider the [SecurityProvider].
  /// @param keyLength the [key length][#getKeyLength()] in bits.
  public KeyConfig(String algorithm, SecurityProvider provider, int keyLength) {

    super(algorithm, provider);
    this.keyLength = keyLength;
  }

  @Override
  public int getKeyLength() {

    return this.keyLength;
  }

}
