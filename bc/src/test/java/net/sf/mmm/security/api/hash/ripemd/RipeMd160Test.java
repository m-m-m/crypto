package net.sf.mmm.security.api.hash.ripemd;

import net.sf.mmm.security.api.hash.access.SecurityAccessHash;
import net.sf.mmm.security.api.hash.access.SecurityAccessHashTest;

import org.junit.Test;

/**
 * Test of {@link RipeMd160}.
 */
public class RipeMd160Test extends SecurityAccessHashTest {

  /** Test of {@link RipeMd160#RIPEMD_160}. */
  @Test
  public void testSingle() {

    SecurityAccessHash hash = SecurityAccessHash.of(RipeMd160.RIPEMD_160);
    check(hash, "The quick brown fox jumps over the lazy dog", "37f332f68db77bd9d7edd4969571ad671cf9dd3b");
  }

}
