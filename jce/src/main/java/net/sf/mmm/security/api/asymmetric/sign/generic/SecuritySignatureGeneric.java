package net.sf.mmm.security.api.asymmetric.sign.generic;

import net.sf.mmm.security.api.asymmetric.sign.SecuritySignature;

/**
 * Generic implementation of {@link SecuritySignature}.
 *
 * @since 1.0.0
 */
public class SecuritySignatureGeneric extends SecuritySignature {

  /**
   * The constructor.
   *
   * @param data the raw {@link #getData() binary data}.
   */
  public SecuritySignatureGeneric(byte[] data) {

    super(data);
  }

  /**
   * @param base64 the {@link #getData() data} as {@link #formatBase64() base64}.
   * @return the parsed {@link SecuritySignature} or {@code null} in case {@code base64} was {@code null}.
   */
  public static SecuritySignatureGeneric ofBase64(String base64) {

    if (base64 == null) {
      return null;
    }
    return new SecuritySignatureGeneric(parseBase64(base64));
  }

  /**
   * @param hex the {@link #getData() data} as {@link #formatHex() hex}.
   * @return the parsed {@link SecuritySignature} or {@code null} in case {@code base64} was {@code null}.
   */
  public static SecuritySignatureGeneric ofHex(String hex) {

    if (hex == null) {
      return null;
    }
    return new SecuritySignatureGeneric(parseHex(hex));
  }

}
