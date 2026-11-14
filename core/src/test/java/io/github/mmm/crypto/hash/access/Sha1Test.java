package io.github.mmm.crypto.hash.access;

import org.junit.jupiter.api.Test;

import io.github.mmm.crypto.hash.sha1.Sha1;

/// Test of [Sha1].
public class Sha1Test extends HashAccessTest {

  /// Test of [Sha1#of()].
  @Test
  void testSingle() {

    Sha1 hash = Sha1.SHA1;
    check(hash, "Hello world!", "d3486ae9136e7856bc42212385ea797094475802");
  }

}
