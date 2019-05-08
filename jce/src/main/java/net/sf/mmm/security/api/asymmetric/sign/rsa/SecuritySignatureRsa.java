package net.sf.mmm.security.api.asymmetric.sign.rsa;

import net.sf.mmm.security.api.asymmetric.sign.SecuritySignature;

/**
 * {@link SecuritySignature} for {@link net.sf.mmm.security.api.algorithm.SecurityAlgorithmRsa RSA}.
 *
 * @since 1.0.0
 */
public class SecuritySignatureRsa extends SecuritySignature {

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   */
  public SecuritySignatureRsa(byte[] data) {

    super(data);
  }

}
