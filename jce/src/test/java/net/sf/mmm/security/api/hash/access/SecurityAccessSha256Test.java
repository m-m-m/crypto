package net.sf.mmm.security.api.hash.access;

import org.junit.Test;

/**
 * Test of {@link SecurityAccessSha256}.
 */
public class SecurityAccessSha256Test extends SecurityAccessHashTest {

  /** Test of {@link SecurityAccessSha256#of()}. */
  @Test
  public void testSingle() {

    SecurityAccessSha256 hash = SecurityAccessSha256.of();
    check(hash, "Hello world!", "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a");
  }

  /** Test of {@link SecurityAccessSha256#of2x()}. */
  @Test
  public void testDouble() {

    SecurityAccessSha256 hash = SecurityAccessSha256.of2x();
    check(hash, "Hello world!", "7982970534e089b839957b7e174725ce1878731ed6d700766e59cb16f1c25e27");
  }

  /** Test of {@link SecurityAccessSha256#of(int)} with 3 iterations. */
  @Test
  public void testTripple() {

    SecurityAccessSha256 hash = SecurityAccessSha256.of(3);
    check(hash, "Hello world!", "906475e60e973462446187675dcb986678931d2e3593abbdbbdefcd95c73872f");
  }

}
