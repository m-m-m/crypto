package io.github.mmm.crypto;

/// Interface for the concept and constants of different formats of a [binary representation][CryptoBinary]. The
/// formats [#FORMAT_ENCODED] and [#FORMAT_COMPACT] shall always be accepted. For generic implementations
/// that only support a single format both formats can be used synonymously. Specific implementations may also support
/// additional supports such as e.g. [io.github.mmm.crypto.asymmetric.key.ec.AsymmetricKeyPairEc#FORMAT_UNCOMORESSED].
///
/// @see io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#createPrivateKey(byte[], String)
/// @see io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#createPublicKey(byte[])
/// @see io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#createKeyPair(byte[], String)
/// @see io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#asData(java.security.PrivateKey, String)
/// @see io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#asData(java.security.PublicKey, String)
/// @see io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#asData(io.github.mmm.crypto.asymmetric.key.AsymmetricKeyPair, String)
///
/// @since 1.0.0
public interface CryptoBinaryFormat {

  /// The format for the encoded binary representation. This is the most universal, portable and standardized format.
  /// However, it is also a large representation according to the [length][CryptoBinary#getLength()]. If you want to
  /// store the [raw data][CryptoBinary#getData()] in the most efficient way use [#FORMAT_COMPACT] instead.
  ///
  /// @see java.security.Key#getEncoded()
  String FORMAT_ENCODED = "Encoded";

  /// The format for compact binary representation. This is the smallest representation that is supported.
  String FORMAT_COMPACT = "Compact";

}
