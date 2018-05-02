package net.sf.mmm.security.api.sign;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmConfig;

/**
 * {@link SecurityAlgorithmConfig} for {@link SecuritySignatureSigner#sign(byte[], boolean) signing}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureConfig extends SecurityAlgorithmConfig {

  /**
   * The {@link java.security.Signature#getAlgorithm() signature algorithm} ECDSA (Elliptic Curve Digital Signature
   * Algorithm). This constant is using NONE as hash algorithm to separate the plain signing algorithm from
   * {@link net.sf.mmm.security.api.hash.SecurityHashFactory hashing} algorithm. For details see
   * <a href="https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm">ECDSA</a>. See also
   * <a href="https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html">Anroid fix</a>.
   */
  public static final String SIGNATURE_ALGORITHM_ECDSA = "NONEwithECDSA";

  /**
   * The constructor.
   *
   * @param algorithm the {@link java.security.MessageDigest#getAlgorithm() hash algorithm}.
   */
  public SecuritySignatureConfig(String algorithm) {

    super(algorithm);
  }

}
