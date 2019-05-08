package net.sf.mmm.security.api.algorithm;

/**
 * The {@link SecurityAlgorithm} SHA-2 (Secure Hash Algorithm 2). It is actually a family of algorithms such as
 * {@link #ALGORITHM_SHA_256} or {@link #ALGORITHM_SHA_512}. For details see
 * <a href="https://en.wikipedia.org/wiki/SHA-2">SHA-2</a>.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAlgorithmSha2 extends SecurityAlgorithm {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  String ALGORITHM_SHA_224 = "SHA-224";

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  String ALGORITHM_SHA_256 = "SHA-256";

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  String ALGORITHM_SHA_384 = "SHA-384";

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  String ALGORITHM_SHA_512 = "SHA-512";

}
