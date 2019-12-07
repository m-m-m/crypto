package io.github.mmm.crypto.hash;

import io.github.mmm.crypto.CryptoBinary;

/**
 * Simple datatype as container for a {@link HashCreator#hash() hash}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class Hash extends CryptoBinary {

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   */
  public Hash(byte[] data) {

    super(data);
  }

  /**
   * @param hash the raw representation.
   * @return the parsed {@link Hash} or {@code null} in case {@code hash} was {@code null}.
   */
  public static Hash of(byte[] hash) {

    if (hash == null) {
      return null;
    }
    return new Hash(hash);
  }

  /**
   * @param hex the {@link #getData() data} as {@link #formatHex() hex}.
   * @return the parsed {@link Hash} or {@code null} in case {@code hex} was {@code null}.
   */
  public static Hash ofHex(String hex) {

    if (hex == null) {
      return null;
    }
    return new Hash(parseHex(hex));
  }

}
