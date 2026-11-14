package io.github.mmm.crypto.hash;

import java.security.MessageDigest;

import io.github.mmm.crypto.AbstractGetIterationCount;
import io.github.mmm.crypto.provider.SecurityProvider;

/// This is an implementation of [HashCreator] that [calculates hashes][#hash(boolean)] in multiple
/// rounds. Therefore, the actual [data][#update(byte[])] is hashed once and then for the number of rounds given at
/// construction time the initial hash is hashed again with the same hash algorithm.
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class HashCreatorImplMultipleRounds extends HashCreatorImplDigest {

  private final MessageDigest roundDigest;

  private final int iterationCount;

  /// The constructor.
  ///
  /// @param hashAlgorithm the name of the hash algorithm to use (e.g. "SHA-256").
  /// @param iterationCount [AbstractGetIterationCount]. Has to be greater than `1`.
  /// @param provider the [SecurityProvider] to use.
  public HashCreatorImplMultipleRounds(String hashAlgorithm, SecurityProvider provider, int iterationCount) {

    super(hashAlgorithm, provider);
    if (iterationCount <= 1) {
      throw new IllegalArgumentException("Iteration count (" + iterationCount + ") has to be greater than 1!");
    }
    this.roundDigest = getProvider().createDigest(hashAlgorithm);
    this.iterationCount = iterationCount;
  }

  @Override
  public byte[] hash(boolean reset) {

    byte[] hash = super.hash(reset);
    for (int i = 1; i < this.iterationCount; i++) {
      hash = this.roundDigest.digest(hash);
    }
    return hash;
  }

}
