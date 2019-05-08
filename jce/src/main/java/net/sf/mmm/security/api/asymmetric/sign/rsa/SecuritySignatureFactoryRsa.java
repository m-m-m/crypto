package net.sf.mmm.security.api.asymmetric.sign.rsa;

import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureFactory;

/**
 * Implementation of {@link SecuritySignatureFactory} for {@link net.sf.mmm.security.api.algorithm.SecurityAlgorithmRsa
 * RSA}.
 *
 * @since 1.0.0
 */
public class SecuritySignatureFactoryRsa implements SecuritySignatureFactory<SecuritySignatureRsa> {

  private static final SecuritySignatureFactoryRsa INSTANCE = new SecuritySignatureFactoryRsa();

  @Override
  public SecuritySignatureRsa createSignature(byte[] data) {

    return new SecuritySignatureRsa(data);
  }

  /**
   * @return the singleton instance of {@link SecuritySignatureFactoryRsa}.
   */
  public static SecuritySignatureFactoryRsa get() {

    return INSTANCE;
  }

}
