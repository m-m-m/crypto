package net.sf.mmm.security.api.sign;

import net.sf.mmm.security.api.SecurityBinaryType;

/**
 * Simple datatype as container for a {@link SecuritySignatureSigner#sign(boolean) signature}. Allows abstraction of
 * actual implementations (such as bouncy-castle) for portability. Further, it is simple and fast to read and store
 * until real semantic parsing and usage is required.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignature extends SecurityBinaryType {

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   */
  public SecuritySignature(byte[] data) {

    super(data);
  }

  /**
   * The constructor.
   *
   * @param base64 the {@link #getData() data} as {@link #getHex() base64}.
   */
  public SecuritySignature(String base64) {

    super(base64);
  }

  /**
   * @param base64 the {@link #getData() data} as {@link #getBase64() base64}.
   * @return the parsed {@link SecuritySignature} or {@code null} in case {@code base64} was {@code null}.
   */
  public static SecuritySignature ofBase64(String base64) {

    if (base64 == null) {
      return null;
    }
    return new SecuritySignature(base64);
  }

  /**
   * @param hex the {@link #getData() data} as {@link #getBase64() base64}.
   * @return the parsed {@link SecuritySignature} or {@code null} in case {@code base64} was {@code null}.
   */
  public static SecuritySignature ofHex(String hex) {

    if (hex == null) {
      return null;
    }
    return new SecuritySignature(parseHex(hex));
  }

}
