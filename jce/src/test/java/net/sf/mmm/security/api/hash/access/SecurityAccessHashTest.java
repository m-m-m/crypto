package net.sf.mmm.security.api.hash.access;

import java.nio.charset.StandardCharsets;

import net.sf.mmm.binary.api.BinaryType;

import org.assertj.core.api.Assertions;

/**
 * Abstract base test for {@link SecurityAccessHash}.
 */
public abstract class SecurityAccessHashTest extends Assertions {

  protected void check(SecurityAccessHash access, String message, String expectedHashHex) {

    byte[] input = message.getBytes(StandardCharsets.UTF_8);
    byte[] hash = access.newHashCreator().hash(input, true);
    String hex = BinaryType.formatHex(hash);
    assertThat(hex).as("Hash of message:" + message).isEqualTo(expectedHashHex);
  }

}
