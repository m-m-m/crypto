package net.sf.mmm.security.api.random;

/**
 * {@link SecurityRandomConfig} for SHA1PRNG.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityRandomConfigSha1Prng extends SecurityRandomConfig {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  public static final String ALGORITHM_SHA1PRNG = "SHA1PRNG";

  /** Simple singleton instance. */
  public static final SecurityRandomConfigSha1Prng SHA1PRNG = new SecurityRandomConfigSha1Prng();

  /**
   * The constructor.
   */
  public SecurityRandomConfigSha1Prng() {

    super(ALGORITHM_SHA1PRNG);
  }

  /**
   * The constructor.
   *
   * @param reseedCount the {@link #getReseedCount() re-seed count}.
   */
  public SecurityRandomConfigSha1Prng(int reseedCount) {

    super(ALGORITHM_SHA1PRNG, reseedCount);
  }

}
