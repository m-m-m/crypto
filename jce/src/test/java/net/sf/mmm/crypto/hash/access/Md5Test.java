package net.sf.mmm.crypto.hash.access;

import net.sf.mmm.crypto.hash.md5.Md5;

import org.junit.Test;

/**
 * Test of {@link Md5}.
 */
public class Md5Test extends HashAccessTest {

  /** Test of {@link Md5#of()}. */
  @Test
  public void testSingle() {

    Md5 hash = Md5.MD5;
    check(hash, "Hello world!", "86fb269d190d2c85f6e0468ceca42a20");
  }

}
