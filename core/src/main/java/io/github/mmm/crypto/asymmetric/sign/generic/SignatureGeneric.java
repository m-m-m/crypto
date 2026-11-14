package io.github.mmm.crypto.asymmetric.sign.generic;

import io.github.mmm.crypto.asymmetric.sign.SignatureBinary;

/// Generic implementation of [SignatureBinary].
///
/// @since 1.0.0
public class SignatureGeneric extends SignatureBinary {

  /// The constructor.
  ///
  /// @param data the raw [binary data][#getData()].
  public SignatureGeneric(byte[] data) {

    super(data);
  }

  /// @param base64 the [data][#getData()] as [base64][#formatBase64()].
  /// @return the parsed [SignatureBinary] or `null` in case `base64` was `null`.
  public static SignatureGeneric ofBase64(String base64) {

    if (base64 == null) {
      return null;
    }
    return new SignatureGeneric(parseBase64(base64));
  }

  /// @param hex the [data][#getData()] as [hex][#formatHex()].
  /// @return the parsed [SignatureBinary] or `null` in case `base64` was `null`.
  public static SignatureGeneric ofHex(String hex) {

    if (hex == null) {
      return null;
    }
    return new SignatureGeneric(parseHex(hex));
  }

}
