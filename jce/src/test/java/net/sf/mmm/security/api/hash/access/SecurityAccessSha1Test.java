package net.sf.mmm.security.api.hash.access;

import org.junit.Test;

/**
 * Test of {@link SecurityAccessSha1}.
 */
public class SecurityAccessSha1Test extends SecurityAccessHashTest {

  /** Test of {@link SecurityAccessSha1#of()}. */
  @Test
  public void testSingle() {

    SecurityAccessSha1 hash = SecurityAccessSha1.of();
    check(hash, "Hello world!", "d3486ae9136e7856bc42212385ea797094475802");
  }

}
