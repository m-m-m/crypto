package net.sf.mmm.security.api.crypt;

import java.util.Objects;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithm;

/**
 * Simple representation of a {@link javax.crypto.Cipher} {@link #getTransformation() transformation}. Please be careful
 * not to confuse or mix {@link #getAlgorithm() algorithm} and {@link #getTransformation() transformation}.
 *
 * @since 1.0.0
 */
public class SecurityCipherTransformation implements SecurityAlgorithm {

  /**
   *
   */
  private static final String SEPARATOR = "/";

  private final String algorithm;

  private final String mode;

  private final String padding;

  private final String transformation;

  /**
   * The constructor.
   *
   * @param algorithm - see {@link #getAlgorithm()}.
   * @param mode - see {@link #getMode()}.
   * @param padding - see {@link #getPadding()}.
   */
  public SecurityCipherTransformation(String algorithm, String mode, String padding) {

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
    if ((obj == null) || !(obj instanceof SecurityCipherTransformation)) {
      return false;
    }
    SecurityCipherTransformation other = (SecurityCipherTransformation) obj;
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
   * @return the parsed {@link SecurityCipherTransformation}.
   */
  public static SecurityCipherTransformation of(String transformation) {

    if ((transformation == null) || transformation.isEmpty()) {
      return null;
    }
    String[] segments = transformation.split(SEPARATOR);
    if (segments.length == 1) {
      return new SecurityCipherTransformation(segments[0], null, null);
    } else if (segments.length == 2) {
      return new SecurityCipherTransformation(segments[0], segments[1], null);
    } else if (segments.length == 3) {
      return new SecurityCipherTransformation(segments[0], segments[1], segments[2]);
    }
    throw new IllegalArgumentException(transformation);
  }

}
