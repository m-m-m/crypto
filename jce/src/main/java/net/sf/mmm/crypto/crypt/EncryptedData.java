package net.sf.mmm.crypto.crypt;

import net.sf.mmm.crypto.CryptoBinary;

/**
 * Simple datatype as container for a {@link Encryptor#crypt(CryptoBinary, boolean) encrypted data}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class EncryptedData extends CryptoBinary {

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   */
  public EncryptedData(byte[] data) {

    super(data);
  }

  /**
   * @param hash the raw representation.
   * @return the parsed {@link EncryptedData} or {@code null} in case {@code hash} was {@code null}.
   */
  public static EncryptedData of(byte[] hash) {

    if (hash == null) {
      return null;
    }
    return new EncryptedData(hash);
  }

  /**
   * @param base64 the {@link #getData() data} as {@link #formatBase64() base64}.
   * @return the parsed {@link EncryptedData} or {@code null} in case {@code base64} was {@code null}.
   */
  public static EncryptedData ofBase64(String base64) {

    if (base64 == null) {
      return null;
    }
    return new EncryptedData(parseBase64(base64));
  }

  /**
   * @param hex the {@link #getData() data} as {@link #formatHex() hex}.
   * @return the parsed {@link EncryptedData} or {@code null} in case {@code base64} was {@code null}.
   */
  public static EncryptedData ofHex(String hex) {

    if (hex == null) {
      return null;
    }
    return new EncryptedData(parseHex(hex));
  }

}
