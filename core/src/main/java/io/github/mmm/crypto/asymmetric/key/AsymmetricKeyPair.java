package io.github.mmm.crypto.asymmetric.key;

import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.Set;

import io.github.mmm.crypto.key.KeySet;

/// Interface for a key pair consisting of a [private key][#getPrivateKey()] with its corresponding
/// [public key][#getPublicKey()] for asymmetric encryption. The big advantage of asymmetric encryption is that no secret
/// has to be shared between the parties. The [public key][PublicKey] can be made public and shared. Anybody knowing your
/// public key can [encrypt][io.github.mmm.crypto.asymmetric.crypt.AsymmetricCryptorFactory#newEncryptor(PublicKey)] data
/// for you that only you as the owner of the corresponding [private key][PrivateKey] can
/// [decrypt][io.github.mmm.crypto.asymmetric.crypt.AsymmetricCryptorFactory#newDecryptor(PrivateKey)]. On the other hand
/// only you as the owner of the [private key][PrivateKey] can
/// [sign][io.github.mmm.crypto.asymmetric.sign.SignatureSigner#sign(byte\[\], boolean)] arbitrary data in a way so that
/// everybody can [verify][io.github.mmm.crypto.asymmetric.sign.SignatureVerifier#verifyAfterUpdate(byte\[\])] this
/// signature using your [public key][PublicKey].
///
/// @param <PR> type of [#getPrivateKey()]
/// @param <PU> type of [#getPublicKey()].
/// @since 1.0.0
public interface AsymmetricKeyPair<PR extends PrivateKey, PU extends PublicKey> extends KeySet {

  /// @return the [private key][PrivateKey]. Has to be kept secret.
  PR getPrivateKey();

  /// @return the [public key][PublicKey]. May be distributed or published.
  PU getPublicKey();

  /// @return the private and public key as java standard [KeyPair].
  KeyPair getKeyPair();

  @Override
  default Set<Key> getKeys() {

    Set<Key> set = new HashSet<>();
    set.add(getPrivateKey());
    set.add(getPublicKey());
    return set;
  }

}
