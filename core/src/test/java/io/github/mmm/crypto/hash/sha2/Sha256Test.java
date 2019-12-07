package io.github.mmm.crypto.hash.sha2;

import org.junit.jupiter.api.Test;

import io.github.mmm.crypto.hash.access.HashAccessTest;
import io.github.mmm.crypto.hash.sha2.Sha256;

/**
 * Test of {@link Sha256}.
 */
public class Sha256Test extends HashAccessTest {

  /** Test of {@link Sha256#SecurityHashConfigSha256.SHA_256}. */
  @Test
  public void testSingle() {

    Sha256 hash = Sha256.SHA_256;
    check(hash, "Hello world!", "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a");
  }

  /** Test of {@link Sha256#SHA_256_X2}. */
  @Test
  public void testDouble() {

    Sha256 hash = Sha256.SHA_256_X2;
    check(hash, "Hello world!", "7982970534e089b839957b7e174725ce1878731ed6d700766e59cb16f1c25e27");
  }

  /** Test of {@link Sha256#SecurityHashConfigSha256(int)} with 3 iterations. */
  @Test
  public void testTripple() {

    Sha256 hash = new Sha256(3);
    check(hash, "Hello world!", "906475e60e973462446187675dcb986678931d2e3593abbdbbdefcd95c73872f");
  }

}
