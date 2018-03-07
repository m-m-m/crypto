package net.sf.mmm.security.api.algorithm;

/**
 * The {@link SecurityAlgorithm} RSA (Ron Rivest, Adi Shamir and Leonard Adleman) used by GPG and many others. For
 * details see <a href="https://en.wikipedia.org/wiki/PKCS_1">PKCS #1</a>.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAlgorithmRsa extends SecurityAlgorithm {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  String ALGORITHM_RSA = "RSA";

  @Override
  default String getAlgorithm() {

    return ALGORITHM_RSA;
  }

}
