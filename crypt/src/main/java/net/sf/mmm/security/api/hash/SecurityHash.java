package net.sf.mmm.security.api.hash;

import net.sf.mmm.security.api.SecurityBinaryType;

/**
 * Simple datatype as container for a {@link SecurityHashCreator#hash() hash}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityHash extends SecurityBinaryType {

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   */
  public SecurityHash(byte[] data) {

    super(data);
  }

  /**
   * The constructor.
   *
   * @param base64 the {@link #getData() data} as {@link #getBase64() base64}.
   */
  public SecurityHash(String base64) {

    super(base64);
  }

  /**
   * @param hash the raw representation.
   * @return the parsed {@link SecurityHash} or {@code null} in case {@code hash} was {@code null}.
   */
  public static SecurityHash of(byte[] hash) {

    if (hash == null) {
      return null;
    }
    return new SecurityHash(hash);
  }

  /**
   * @param base64 the {@link #getData() data} as {@link #getBase64() base64}.
   * @return the parsed {@link SecurityHash} or {@code null} in case {@code base64} was {@code null}.
   */
  public static SecurityHash ofBase64(String base64) {

    if (base64 == null) {
      return null;
    }
    return new SecurityHash(base64);
  }

  /**
   * @param hex the {@link #getData() data} as {@link #getHex() hex}.
   * @return the parsed {@link SecurityHash} or {@code null} in case {@code hex} was {@code null}.
   */
  public static SecurityHash ofHex(String hex) {

    if (hex == null) {
      return null;
    }
    return new SecurityHash(parseHex(hex));
  }

}
