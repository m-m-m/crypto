package io.github.mmm.crypto.asymmetric.key.ec;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import io.github.mmm.crypto.asymmetric.key.AbstractAsymmetricKeyPair;
import io.github.mmm.crypto.asymmetric.key.AsymmetricKeyPair;

/// Abstract base implementation of [AsymmetricKeyPair] for [ECPrivateKey] and [ECPublicKey].
///
/// @param <PR> type of [private key][#getPrivateKey()].
/// @param <PU> type of [public key][#getPublicKey()].
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class AsymmetricKeyPairEc<PR extends ECPrivateKey, PU extends ECPublicKey>
    extends AbstractAsymmetricKeyPair<PR, PU> {

  /// The [algorithm][io.github.mmm.crypto.algorithm.CryptoAlgorithm#getAlgorithm()] name {@value} for
  /// <a href="https://en.wikipedia.org/wiki/Elliptic_curve_cryptography">ECC</a>.
  public static final String ALGORITHM_EC = "EC";

  /// Format for compact binary representation.
  public static final String FORMAT_UNCOMORESSED = "Uncompressed";

  /// The constructor.
  ///
  /// @param privateKey the [private key][#getPrivateKey()].
  /// @param publicKey the [public key][#getPrivateKey()].
  public AsymmetricKeyPairEc(PR privateKey, PU publicKey) {

    super(privateKey, publicKey);
  }

}
