package io.github.mmm.crypto.asymmetric.key;

import java.security.PrivateKey;
import java.security.PublicKey;

/// Interface for factory to create instances of [AsymmetricKeyPair] from [PrivateKey] and
/// [PublicKey]. It only provides low-level wrapping functionality. For higher level usage see
/// [AsymmetricKeyCreator].
///
/// @param <PR> type of [PrivateKey].
/// @param <PU> type of [PublicKey].
/// @param <PAIR> type of [AsymmetricKeyPair].
/// @since 1.0.0
public interface AsymmetricKeyPairFactorySimple<PR extends PrivateKey, PU extends PublicKey, PAIR extends AsymmetricKeyPair<PR, PU>> {

  /// @param privateKey the [PrivateKey].
  /// @param publicKey the corresponding [PublicKey].
  /// @return the [AsymmetricKeyPair].
  PAIR createKeyPair(PR privateKey, PU publicKey);

}
