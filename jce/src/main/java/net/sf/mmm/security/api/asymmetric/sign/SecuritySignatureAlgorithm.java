package net.sf.mmm.security.api.asymmetric.sign;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithm;
import net.sf.mmm.security.api.hash.SecurityHashConfig;

/**
 * Little helper to workaround quirks in JCE/JCA for {@link java.security.Signature#getAlgorithm() signature algorithm}
 * names.
 *
 * @since 1.0.0
 */
public final class SecuritySignatureAlgorithm implements SecurityAlgorithm {

  private static final String SEPARATOR = "with";

  private static final Map<String, String> DIGEST2SIGNATURE_MAP = new HashMap<>();

  private static final Map<String, String> SIGNATURE2DIGEST_MAP = new HashMap<>();

  static {
    register("SHA-224");
    register("SHA-256");
    register("SHA-384");
    register("SHA-512");
    register("SHA-512/224");
    register("SHA-512/256");
  }

  private final String hashAlgorithm;

  private final String signingAlgorithm;

  private final String algorithm;

  private SecuritySignatureAlgorithm(String hashAlgorithm, String signingAlgorithm, String algorithm) {

    super();
    this.hashAlgorithm = hashAlgorithm;
    this.signingAlgorithm = signingAlgorithm;
    this.algorithm = algorithm;
  }

  private static void register(String digest) {

    register(digest, digest.replace("SHA-", "SHA"));
  }

  private static void register(String digest, String signaturePrefix) {

    DIGEST2SIGNATURE_MAP.put(digest, signaturePrefix);
    SIGNATURE2DIGEST_MAP.put(signaturePrefix, digest);
  }

  private static String require(String value, String name) {

    if ((value == null) || value.isEmpty()) {
      throw new IllegalArgumentException("Value for " + name + " is required and must not be '" + value + "'!");
    }
    return value;
  }

  @Override
  public String getAlgorithm() {

    return this.algorithm;
  }

  /**
   * @return the hash algorithm to perform of the message payload before signing.
   */
  public String getHashAlgorithm() {

    return this.hashAlgorithm;
  }

  /**
   * @return {@code true} if {@link #getHashAlgorithm() hash algorithm} is {@link SecurityHashConfig#ALGORITHM_NONE
   *         NONE}.
   */
  public boolean isNoHashing() {

    return SecurityHashConfig.ALGORITHM_NONE.equals(this.hashAlgorithm);
  }

  /**
   * @return the raw signing algorithm (e.g. RSA, DSA, or ECDSA).
   */
  public String getSigningAlgorithm() {

    return this.signingAlgorithm;
  }

  @Override
  public int hashCode() {

    return this.algorithm.hashCode();
  }

  @Override
  public boolean equals(Object obj) {

    if (this == obj) {
      return true;
    }
    if ((obj == null) || (getClass() != obj.getClass())) {
      return false;
    }
    SecuritySignatureAlgorithm other = (SecuritySignatureAlgorithm) obj;
    if (!Objects.equals(this.algorithm, other.algorithm)) {
      return false;
    }
    return true;
  }

  @Override
  public String toString() {

    return this.algorithm;
  }

  /**
   * @param hashAlgorithm the {@link #getHashAlgorithm()}.
   * @param signingAlgorithm the {@link #getSigningAlgorithm()}.
   * @return the {@link SecuritySignatureAlgorithm} instance.
   */
  public static SecuritySignatureAlgorithm of(String hashAlgorithm, String signingAlgorithm) {

    register(signingAlgorithm, "signingAlgorithm");
    String algorithm;
    if (hashAlgorithm == null) {
      algorithm = signingAlgorithm;
    } else {
      algorithm = hash2sign(hashAlgorithm) + SEPARATOR + signingAlgorithm;
    }
    return new SecuritySignatureAlgorithm(hashAlgorithm, signingAlgorithm, algorithm);
  }

  private static String hash2sign(String hashingAlgorithm) {

    String signaturePrefix = DIGEST2SIGNATURE_MAP.get(hashingAlgorithm);
    if (signaturePrefix != null) {
      return signaturePrefix;
    }
    return hashingAlgorithm;
  }

  /**
   * @param algorithm the {@link #getAlgorithm() signature algorithm}.
   * @return the {@link SecuritySignatureAlgorithm} instance.
   */
  public static SecuritySignatureAlgorithm of(String algorithm) {

    require(algorithm, "algorithm");
    int separatorStartIndex = algorithm.indexOf(SEPARATOR);
    String hashAlgorithm;
    String signingAlgorithm;
    String signatureAlgorithm;
    if (separatorStartIndex < 0) {
      hashAlgorithm = null;
      signingAlgorithm = algorithm;
      signatureAlgorithm = algorithm;
    } else {
      assert (separatorStartIndex > 0);
      hashAlgorithm = sign2hash(algorithm.substring(0, separatorStartIndex));
      signingAlgorithm = algorithm.substring(separatorStartIndex + SEPARATOR.length());
      signatureAlgorithm = hash2sign(hashAlgorithm) + SEPARATOR + signingAlgorithm;
    }
    return new SecuritySignatureAlgorithm(hashAlgorithm, signingAlgorithm, signatureAlgorithm);
  }

  private static String sign2hash(String signaturePrefix) {

    String hashing = SIGNATURE2DIGEST_MAP.get(signaturePrefix);
    if (hashing != null) {
      return hashing;
    }
    return signaturePrefix;
  }

}
