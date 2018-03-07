package net.sf.mmm.security.api.sign;

import net.sf.mmm.util.lang.api.BinaryType;

/**
 * Simple datatype as container for a {@link SecuritySignatureSigner#sign(boolean) signature}. Allows abstraction of actual
 * implementations (such as bouncy-castle) for portability. Further, it is simple and fast to read and store until real
 * semantic parsing and usage is required.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignature extends BinaryType {

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
   * @param hex the {@link #getData() data} as {@link #getHex() hex}.
   */
  public SecuritySignature(String hex) {

    super(hex);
  }

  /**
   * @param hex the {@link #getHex() hexadecimal} representation.
   * @return the parsed {@link SecuritySignature} or {@code null} in case {@code hex} was {@code null}.
   */
  public static SecuritySignature of(String hex) {

    if (hex == null) {
      return null;
    }
    return new SecuritySignature(hex);
  }

}
