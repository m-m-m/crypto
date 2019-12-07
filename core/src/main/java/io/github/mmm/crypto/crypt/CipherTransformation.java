package io.github.mmm.crypto.crypt;

import java.util.Objects;

import io.github.mmm.crypto.algorithm.CryptoAlgorithm;

/**
 * Simple representation of a {@link javax.crypto.Cipher} {@link #getTransformation() transformation}. Please be careful
 * not to confuse or mix {@link #getAlgorithm() algorithm} and {@link #getTransformation() transformation}.
 *
 * @since 1.0.0
 */
public class CipherTransformation implements CryptoAlgorithm {

  /** {@link #getPadding() Padding} value {@value}. */
  public static final String PADDING_NONE = "NoPadding";

  /**
   * {@link #getMode() Mode} value {@value} (<a href="https://en.wikipedia.org/wiki/Galois/Counter_Mode">Galois/Counter
   * Mode</a>).
   */
  public static final String MODE_GCM = "GCM";

  private static final String SEPARATOR = "/";

  private final String algorithm;

  private final String mode;

  private final String padding;

  private final String transformation;

  /**
   * The constructor. Be careful not to confuse with {@link #of(String)} to create from transformation.
   *
   * @param algorithm - see {@link #getAlgorithm()}.
   */
  public CipherTransformation(String algorithm) {

    this(algorithm, null, null);
  }

  /**
   * The constructor.
   *
   * @param algorithm - see {@link #getAlgorithm()}.
   * @param mode - see {@link #getMode()}.
   * @param padding - see {@link #getPadding()}.
   */
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

  /**
   * @return the {@link javax.crypto.Cipher#getAlgorithm() encryption algorithm}. See <a href=
   *         "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#cipher-algorithm-names">Cipher
   *         Algorithm Names</a>.
   */
  @Override
  public String getAlgorithm() {

    return this.algorithm;
  }

  /**
   * @return the {@link javax.crypto.Cipher#getAlgorithm() cipher mode} <a href=
   *         "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#cipher-algorithm-modes">mode</a>.
   */
  public String getMode() {

    return this.mode;
  }

  /**
   * @return the {@link javax.crypto.Cipher#getAlgorithm() cipher padding} <a href=
   *         "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#cipher-algorithm-modes">padding</a>.
   */
  public String getPadding() {

    return this.padding;
  }

  /**
   * @return the {@link javax.crypto.Cipher#getInstance(String) cipher transformation} composed of
   *         {@link #getAlgorithm() algorithm}, {@link #getMode() mode}, and {@link #getPadding() padding}.
   */
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

  /**
   * @param transformation the {@link #getTransformation() transformation}.
   * @return the parsed {@link CipherTransformation}.
   */
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
