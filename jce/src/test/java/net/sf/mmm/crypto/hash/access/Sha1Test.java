package net.sf.mmm.crypto.hash.access;

import net.sf.mmm.crypto.hash.sha1.Sha1;

import org.junit.Test;

/**
 * Test of {@link Sha1}.
 */
public class Sha1Test extends HashAccessTest {

  /** Test of {@link Sha1#of()}. */
  @Test
  public void testSingle() {

    Sha1 hash = Sha1.SHA1;
    check(hash, "Hello world!", "d3486ae9136e7856bc42212385ea797094475802");
  }

}
