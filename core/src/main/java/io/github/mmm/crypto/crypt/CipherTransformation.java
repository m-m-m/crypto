package io.github.mmm.crypto.crypt;

import java.util.Objects;

import io.github.mmm.crypto.algorithm.CryptoAlgorithm;

/// Simple representation of a [javax.crypto.Cipher] [transformation][#getTransformation()]. Please be careful not to
/// confuse or mix [algorithm][#getAlgorithm()] and [transformation][#getTransformation()].
///
/// @since 1.0.0
public class CipherTransformation implements CryptoAlgorithm {

  /// [Padding][#getPadding()] value {@value}.
  public static final String PADDING_NONE = "NoPadding";

  /// [Mode][#getMode()] value {@value} for [Galois Counter Mode](https://en.wikipedia.org/wiki/Galois/Counter%20Mode).
  public static final String MODE_GCM = "GCM";

  private static final String SEPARATOR = "/";

  private final String algorithm;

  private final String mode;

  private final String padding;

  private final String transformation;

  /// The constructor. Be careful not to confuse with [#of(String)] to create from transformation.
  ///
  /// @param algorithm - see [#getAlgorithm()].
  public CipherTransformation(String algorithm) {

    this(algorithm, null, null);
  }

  /// The constructor.
  ///
  /// @param algorithm - see [#getAlgorithm()].
  /// @param mode - see [#getMode()].
  /// @param padding - see [#getPadding()].
  public CipherTransformation(String algorithm, String mode, String padding) {

    super();
    Objects.requireNonNull(algorithm, "algorithm");
    this.algorithm = algorithm;
    this.mode = mode;
    this.padding = padding;
    if (padding == null) {
      if (mode == null) {
        this.transformation = algorithm;
      } else {
        this.transformation = algorithm + SEPARATOR + mode;
      }
    } else {
      this.transformation = algorithm + SEPARATOR + mode + SEPARATOR + padding;
    }
  }

  /// @return the [encryption algorithm][javax.crypto.Cipher#getAlgorithm()]. See [Cipher
  ///         Algorithm Names](https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#cipher-algorithm-names).
  @Override
  public String getAlgorithm() {

    return this.algorithm;
  }

  /// @return the
  ///         [cipher][javax.crypto.Cipher#getAlgorithm()] [mode](https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#cipher-algorithm-modes).
  public String getMode() {

    return this.mode;
  }

  /// @return the
  ///         [cipher padding][javax.crypto.Cipher#getAlgorithm()] [padding](https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#cipher-algorithm-modes).
  public String getPadding() {

    return this.padding;
  }

  /// @return the [cipher transformation][javax.crypto.Cipher#getInstance(String)] composed of
  ///         [algorithm][#getAlgorithm()], [mode][#getMode()], and [padding][#getPadding()].
  public String getTransformation() {

    return this.transformation;
  }

  @Override
  public int hashCode() {

    return this.transformation.hashCode();
  }

  @Override
  public boolean equals(Object obj) {

    if (obj == this) {
      return true;
    }
    if ((obj == null) || !(obj instanceof CipherTransformation)) {
      return false;
    }
    CipherTransformation other = (CipherTransformation) obj;
    if (!Objects.equals(this.transformation, other.transformation)) {
      return false;
    }
    return true;
  }

  @Override
  public String toString() {

    return this.transformation;
  }

  /// @param transformation the [transformation][#getTransformation()].
  /// @return the parsed [CipherTransformation].
  public static CipherTransformation of(String transformation) {

    if ((transformation == null) || transformation.isEmpty()) {
      return null;
    }
    String[] segments = transformation.split(SEPARATOR);
    if (segments.length == 1) {
      return new CipherTransformation(segments[0], null, null);
    } else if (segments.length == 2) {
      return new CipherTransformation(segments[0], segments[1], null);
    } else if (segments.length == 3) {
      return new CipherTransformation(segments[0], segments[1], segments[2]);
    }
    throw new IllegalArgumentException(transformation);
  }

}
