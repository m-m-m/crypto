package net.sf.mmm.security.api.crypt;

import net.sf.mmm.security.api.SecurityBinaryType;

/**
 * Simple datatype as container for a {@link SecurityEncryptor#crypt(SecurityBinaryType, boolean) encrypted data}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityEncryptedData extends SecurityBinaryType {

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   */
  public SecurityEncryptedData(byte[] data) {

    super(data);
  }

  /**
   * The constructor.
   *
   * @param base64 the {@link #getData() data} as {@link #getBase64() base64}.
   */
  public SecurityEncryptedData(String base64) {

    super(base64);
  }

  /**
   * @param hash the raw representation.
   * @return the parsed {@link SecurityEncryptedData} or {@code null} in case {@code hash} was {@code null}.
   */
  public static SecurityEncryptedData of(byte[] hash) {

    if (hash == null) {
      return null;
    }
    return new SecurityEncryptedData(hash);
  }

  /**
   * @param base64 the {@link #getData() data} as {@link #getBase64() base64}.
   * @return the parsed {@link SecurityEncryptedData} or {@code null} in case {@code base64} was {@code null}.
   */
  public static SecurityEncryptedData ofBase64(String base64) {

    if (base64 == null) {
      return null;
    }
    return new SecurityEncryptedData(base64);
  }

  /**
   * @param hex the {@link #getData() data} as {@link #getBase64() base64}.
   * @return the parsed {@link SecurityEncryptedData} or {@code null} in case {@code base64} was {@code null}.
   */
  public static SecurityEncryptedData ofHex(String hex) {

    if (hex == null) {
      return null;
    }
    return new SecurityEncryptedData(parseHex(hex));
  }

}
