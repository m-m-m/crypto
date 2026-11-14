package io.github.mmm.crypto.hash;

import io.github.mmm.crypto.CryptoBinary;

/// Simple datatype as container for a [hash][HashCreator#hash()].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class Hash extends CryptoBinary {

  /// The constructor.
  ///
  /// @param data the raw binary [data][#getData()].
  public Hash(byte[] data) {

    super(data);
  }

  /// @param hash the raw representation.
  /// @return the parsed [Hash] or `null` in case `hash` was `null`.
  public static Hash of(byte[] hash) {

    if (hash == null) {
      return null;
    }
    return new Hash(hash);
  }

  /// @param hex the [data][#getData()] as [hex][#formatHex()].
  /// @return the parsed [Hash] or `null` in case `hex` was `null`.
  public static Hash ofHex(String hex) {

    if (hex == null) {
      return null;
    }
    return new Hash(parseHex(hex));
  }

}
