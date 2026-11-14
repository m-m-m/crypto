package io.github.mmm.crypto.random;

/// [RandomConfig] for SHA1PRNG.
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class RandomConfigSha1Prng extends RandomConfig {

  /// The [algorithm][#getAlgorithm()] name {@value}.
  public static final String ALGORITHM_SHA1PRNG = "SHA1PRNG";

  /// Simple singleton instance.
  public static final RandomConfigSha1Prng SHA1PRNG = new RandomConfigSha1Prng();

  /// The constructor.
  public RandomConfigSha1Prng() {

    super(ALGORITHM_SHA1PRNG);
  }

  /// The constructor.
  ///
  /// @param reseedCount the [re-seed count][#getReseedCount()].
  public RandomConfigSha1Prng(int reseedCount) {

    super(ALGORITHM_SHA1PRNG, reseedCount);
  }

}
