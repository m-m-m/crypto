package net.sf.mmm.security.api.symmetric.access.pbe;

import javax.crypto.interfaces.PBEKey;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmPbkdf2;
import net.sf.mmm.security.api.symmetric.access.SecurityAccessSymmetricTest;
import net.sf.mmm.security.api.symmetric.key.SecuritySymmetricKeyCreator;

import org.junit.Test;

/**
 * Test of {@link SecurityAccessPbkdf2}.
 */
public class SecurityAccessPbkdf2Test extends SecurityAccessSymmetricTest {

  /**
   * Test of {@link SecurityAccessPbkdf2#ofPbkdf2HmacSha256()}.
   */
  @Test
  public void testPbkdf2HmacSha256() {

    SecurityAccessPbkdf2 pbkdf2 = SecurityAccessPbkdf2.ofPbkdf2HmacSha256();
    SecuritySymmetricKeyCreator<PBEKey> keyCreator = pbkdf2.newKeyCreator();
    assertThat(keyCreator.getAlgorithm()).isEqualTo(SecurityAlgorithmPbkdf2.ALGORITHM_PBKDF2_WITH_HMAC_SHA256);
    assertThat(keyCreator.getKeyLength()).isEqualTo(256);
    check(pbkdf2);
  }

}
