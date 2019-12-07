package io.github.mmm.crypto.asymmetric.sign.generic;

import io.github.mmm.crypto.asymmetric.sign.SignatureBinary;

/**
 * Generic implementation of {@link SignatureBinary}.
 *
 * @since 1.0.0
 */
public class SignatureGeneric extends SignatureBinary {

  /**
   * The constructor.
   *
   * @param data the raw {@link #getData() binary data}.
   */
  public SignatureGeneric(byte[] data) {

    super(data);
  }

  /**
   * @param base64 the {@link #getData() data} as {@link #formatBase64() base64}.
   * @return the parsed {@link SignatureBinary} or {@code null} in case {@code base64} was {@code null}.
   */
  public static SignatureGeneric ofBase64(String base64) {

    if (base64 == null) {
      return null;
    }
    return new SignatureGeneric(parseBase64(base64));
  }

  /**
   * @param hex the {@link #getData() data} as {@link #formatHex() hex}.
   * @return the parsed {@link SignatureBinary} or {@code null} in case {@code base64} was {@code null}.
   */
  public static SignatureGeneric ofHex(String hex) {

    if (hex == null) {
      return null;
    }
    return new SignatureGeneric(parseHex(hex));
  }

}
