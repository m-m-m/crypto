package net.sf.mmm.crypto.asymmetric.sign.rsa;

import net.sf.mmm.crypto.asymmetric.sign.SignatureBinary;

/**
 * {@link SignatureBinary} for {@link net.sf.mmm.crypto.asymmetric.access.rsa.Rsa}.
 *
 * @since 1.0.0
 */
public class SignatureRsa extends SignatureBinary {

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   */
  public SignatureRsa(byte[] data) {

    super(data);
  }

}
