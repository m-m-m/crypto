package net.sf.mmm.security.api.algorithm;

/**
 * The {@link SecurityAlgorithm} SHA1PRNG.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAlgorithmSha1Prng extends SecurityAlgorithm {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  String ALGORITHM_SHA1PRNG = "SHA1PRNG";

  @Override
  default String getAlgorithm() {

    return ALGORITHM_SHA1PRNG;
  }

}
