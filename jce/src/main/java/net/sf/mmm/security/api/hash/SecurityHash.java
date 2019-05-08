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
   * @param hex the {@link #getData() data} as {@link #formatHex() hex}.
   * @return the parsed {@link SecurityHash} or {@code null} in case {@code hex} was {@code null}.
   */
  public static SecurityHash ofHex(String hex) {

    if (hex == null) {
      return null;
    }
    return new SecurityHash(parseHex(hex));
  }

}
