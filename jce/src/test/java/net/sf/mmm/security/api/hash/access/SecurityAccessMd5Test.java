package net.sf.mmm.security.api.hash.access;

import org.junit.Test;

/**
 * Test of {@link SecurityAccessMd5}.
 */
public class SecurityAccessMd5Test extends SecurityAccessHashTest {

  /** Test of {@link SecurityAccessMd5#of()}. */
  @Test
  public void testSingle() {

    SecurityAccessMd5 hash = SecurityAccessMd5.of();
    check(hash, "Hello world!", "86fb269d190d2c85f6e0468ceca42a20");
  }

}
