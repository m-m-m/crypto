package io.github.mmm.crypto.random;

import io.github.mmm.crypto.algorithm.CryptoAlgorithm;

/// The interface for a creator of secure [random data][#nextRandom(int)]. It is similar to
/// [java.security.SecureRandom] but gives additional abstraction.
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface RandomCreator extends CryptoAlgorithm, RandomConstants {

  /// @param bytes the requested number of random bytes.
  /// @return the `byte` array with the given number of random bytes.
  /// @see java.security.SecureRandom#nextBytes(byte[])
  byte[] nextRandom(int bytes);

}
