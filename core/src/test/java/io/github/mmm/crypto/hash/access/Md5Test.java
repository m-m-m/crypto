package io.github.mmm.crypto.hash.access;

import org.junit.jupiter.api.Test;

import io.github.mmm.crypto.hash.md5.Md5;

/**
 * Test of {@link Md5}.
 */
public class Md5Test extends HashAccessTest {

  /** Test of {@link Md5#of()}. */
  @Test
  void testSingle() {

    Md5 hash = Md5.MD5;
    check(hash, "Hello world!", "86fb269d190d2c85f6e0468ceca42a20");
  }

}
