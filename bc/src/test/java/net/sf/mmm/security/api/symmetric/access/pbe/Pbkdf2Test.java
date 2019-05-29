package net.sf.mmm.security.api.symmetric.access.pbe;

import javax.crypto.interfaces.PBEKey;

import net.sf.mmm.security.api.symmetric.access.SecurityAccessSymmetricTest;
import net.sf.mmm.security.api.symmetric.key.SecuritySymmetricKeyCreator;

import org.junit.Test;

/**
 * Test of {@link Pbkdf2}.
 */
public class Pbkdf2Test extends SecurityAccessSymmetricTest {

  /**
   * Test of {@link Pbkdf2WithHmacSha256#of256()}.
   */
  @Test
  public void testPbkdf2HmacSha256() {

    Pbkdf2 pbkdf2 = Pbkdf2WithHmacSha256.of256();
    SecuritySymmetricKeyCreator<PBEKey> keyCreator = pbkdf2.newKeyCreator();
    assertThat(keyCreator.getAlgorithm()).isEqualTo("PBKDF2WithHmacSHA256");
    assertThat(keyCreator.getKeyLength()).isEqualTo(256);
    check(pbkdf2);
  }

}
