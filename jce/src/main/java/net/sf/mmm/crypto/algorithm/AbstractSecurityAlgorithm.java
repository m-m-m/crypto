package net.sf.mmm.crypto.algorithm;

import java.security.InvalidKeyException;

/**
 * The abstract base implementation of {@link CryptoAlgorithm}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class AbstractSecurityAlgorithm implements CryptoAlgorithm {

  /**
   * The constructor.
   */
  public AbstractSecurityAlgorithm() {

    super();
  }

  /**
   * @param algorithms the combined algorithms.
   * @return the combined algorithm {@link String}.
   * @see #getAlgorithm()
   */
  protected static String getAlgorithm(CryptoAlgorithm[] algorithms) {

    StringBuilder buffer = new StringBuilder();
    for (CryptoAlgorithm algorithm : algorithms) {
      if (buffer.length() > 0) {
        buffer.append('+');
      }
      buffer.append(algorithm);
    }
    return buffer.toString();
  }

  /**
   * @param cause the {@link Exception#getCause() cause} of the error.
   * @param objectType the type of the object that could not be created.
   * @return the wrapped {@link RuntimeException}.
   */
  protected RuntimeException creationFailedException(Exception cause, Class<?> objectType) {

    return creationFailedException(cause, objectType.getSimpleName());
  }

  /**
   * @param cause the {@link Exception#getCause() cause} of the error.
   * @param objectType the type of the object that could not be created.
   * @return the wrapped {@link RuntimeException}.
   */
  protected RuntimeException creationFailedException(Exception cause, String objectType) {

    return creationFailedException(cause, objectType, getAlgorithm());
  }

  /**
   * @param cause the {@link Exception#getCause() cause} of the error.
   * @param objectType the type of the object that could not be created.
   * @param variant the {@link #getAlgorithm() algorithm} or type.
   * @return the wrapped {@link RuntimeException}.
   */
  public static RuntimeException creationFailedException(Exception cause, Class<?> objectType, String variant) {

    return creationFailedException(cause, objectType.getSimpleName(), variant);
  }

  /**
   * @param cause the {@link Exception#getCause() cause} of the error.
   * @param objectType the type of the object that could not be created.
   * @param variant the {@link #getAlgorithm() algorithm} or type.
   * @return the wrapped {@link RuntimeException}.
   */
  public static RuntimeException creationFailedException(Exception cause, String objectType, String variant) {

    String suffix = "";
    boolean limitedJurisdictionPolicy = false;
    if (cause instanceof InvalidKeyException) {
      if (cause.getMessage().contains("key size")) {
        limitedJurisdictionPolicy = true;
      }
    } else if (cause instanceof IllegalArgumentException) {
      if (cause.getMessage().contains("not an EC key")) {
        limitedJurisdictionPolicy = true;
      }
    }
    if (limitedJurisdictionPolicy) {
      suffix = " Thanks to U.S. law (see https://en.wikipedia.org/wiki/Export_of_cryptography_from_the_United_States) your Java installation has limited "
          + "cryptography and prevents secure encryption. To resolve this problem upgrade to a most recent version of Java. "
          + "Otherwise you have to install Jurisdiction Policy Files (http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html).";
    }
    return new IllegalStateException("Failed to create " + objectType + " for '" + variant + "'." + suffix, cause);
  }

  @Override
  public String toString() {

    return getAlgorithm();
  }

}
