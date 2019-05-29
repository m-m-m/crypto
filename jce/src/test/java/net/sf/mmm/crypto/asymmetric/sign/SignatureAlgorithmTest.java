package net.sf.mmm.crypto.asymmetric.sign;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

import net.sf.mmm.crypto.asymmetric.sign.SignatureAlgorithm;

import org.assertj.core.api.Assertions;
import org.junit.Ignore;
import org.junit.Test;

/**
 * Test of {@link SignatureAlgorithm}.
 */
@Ignore("JDK is unstable and supported algorithms may come and go - relying on bouncy castle is a good option")
public class SignatureAlgorithmTest extends Assertions {

  @Test
  public void test() throws NoSuchAlgorithmException {

    check("NONE", "RSA", "NONEwithRSA");
    check("MD2", "RSA", "MD2withRSA");
    check("MD5", "RSA", "MD5withRSA");
    check("SHA-224", "RSA", "SHA224withRSA");
    check("SHA-256", "RSA", "SHA256withRSA");
    check("SHA-384", "RSA", "SHA384withRSA");
    check("SHA-512", "RSA", "SHA512withRSA");
    // check("SHA-512/224", "RSA", "SHA512/224withRSA");
    // check("SHA-512/256", "RSA", "SHA512/256withRSA");
    String javaVersion = System.getProperty("java.version");
    boolean java1_8_or_earlier = javaVersion.startsWith("1.");
    if (java1_8_or_earlier) {
      check("SHA3-224", "RSA", "SHA3-224withRSA");
      check("SHA3-256", "RSA", "SHA3-256withRSA");
      check("SHA3-384", "RSA", "SHA3-384withRSA");
      check("SHA3-512", "RSA", "SHA3-512withRSA");
    }

    check(null, "RSASSA-PSS", "RSASSA-PSS", !java1_8_or_earlier);

    check("NONE", "DSA", "NONEwithDSA");
    check("SHA1", "DSA", "SHA1withDSA");
    check("SHA-224", "DSA", "SHA224withDSA");
    check("SHA-256", "DSA", "SHA256withDSA");
    if (java1_8_or_earlier) {
      check("SHA-384", "DSA", "SHA384withDSA");
      check("SHA-512", "DSA", "SHA512withDSA");
      check("SHA3-224", "DSA", "SHA3-224withDSA");
      check("SHA3-256", "DSA", "SHA3-256withDSA");
      check("SHA3-384", "DSA", "SHA3-384withDSA");
      check("SHA3-512", "DSA", "SHA3-512withDSA");
    }

    check("NONE", "ECDSA", "NONEwithECDSA");
    check("SHA1", "ECDSA", "SHA1withECDSA");
    check("SHA-224", "ECDSA", "SHA224withECDSA");
    check("SHA-256", "ECDSA", "SHA256withECDSA");
    check("SHA-384", "ECDSA", "SHA384withECDSA");
    check("SHA-512", "ECDSA", "SHA512withECDSA");
    if (java1_8_or_earlier) {
      check("SHA3-224", "ECDSA", "SHA3-224withECDSA");
      check("SHA3-256", "ECDSA", "SHA3-256withECDSA");
      check("SHA3-384", "ECDSA", "SHA3-384withECDSA");
      check("SHA3-512", "ECDSA", "SHA3-512withECDSA");
    }
  }

  private void check(String hashAlgorithm, String signingAlgorithm, String expectedAlgorithm) throws NoSuchAlgorithmException {

    check(hashAlgorithm, signingAlgorithm, expectedAlgorithm, true);
  }

  private void check(String hashAlgorithm, String signingAlgorithm, String expectedAlgorithm, boolean jce) throws NoSuchAlgorithmException {

    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.of(hashAlgorithm, signingAlgorithm);
    assertThat(signatureAlgorithm.getHashAlgorithm()).isEqualTo(hashAlgorithm);
    assertThat(signatureAlgorithm.getSigningAlgorithm()).isEqualTo(signingAlgorithm);
    assertThat(signatureAlgorithm.getAlgorithm()).isEqualTo(expectedAlgorithm);
    if (jce) {
      if (!signatureAlgorithm.isNoHashing() && (hashAlgorithm != null)) {
        MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
        assertThat(digest.getAlgorithm()).isEqualTo(hashAlgorithm);
      }
      Signature signature = Signature.getInstance(expectedAlgorithm);
      assertThat(signature.getAlgorithm()).isEqualTo(expectedAlgorithm);
    }

    SignatureAlgorithm signatureAlgorithm2;
    signatureAlgorithm2 = SignatureAlgorithm.of(expectedAlgorithm);
    assertThat(signatureAlgorithm2.getAlgorithm()).isEqualTo(expectedAlgorithm);
    assertThat(signatureAlgorithm2.getHashAlgorithm()).isEqualTo(hashAlgorithm);
    assertThat(signatureAlgorithm2.getSigningAlgorithm()).isEqualTo(signingAlgorithm);
    assertThat(signatureAlgorithm2).isEqualTo(signatureAlgorithm);
  }

}
