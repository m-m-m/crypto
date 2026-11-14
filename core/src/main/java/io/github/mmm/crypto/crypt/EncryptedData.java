package io.github.mmm.crypto.crypt;

import io.github.mmm.crypto.CryptoBinary;

/// Simple datatype as container for a [encrypted data][Encryptor#crypt(CryptoBinary, boolean)].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class EncryptedData extends CryptoBinary {

  /// The constructor.
  ///
  /// @param data the raw binary [data][#getData()].
  public EncryptedData(byte[] data) {

    super(data);
  }

  /// @param hash the raw representation.
  /// @return the parsed [EncryptedData] or `null` in case `hash` was `null`.
  public static EncryptedData of(byte[] hash) {

    if (hash == null) {
      return null;
    }
    return new EncryptedData(hash);
  }

  /// @param base64 the [data][#getData()] as [base64][#formatBase64()].
  /// @return the parsed [EncryptedData] or `null` in case `base64` was `null`.
  public static EncryptedData ofBase64(String base64) {

    if (base64 == null) {
      return null;
    }
    return new EncryptedData(parseBase64(base64));
  }

  /// @param hex the [data][#getData()] as [hex][#formatHex()].
  /// @return the parsed [EncryptedData] or `null` in case `base64` was `null`.
  public static EncryptedData ofHex(String hex) {

    if (hex == null) {
      return null;
    }
    return new EncryptedData(parseHex(hex));
  }

}
