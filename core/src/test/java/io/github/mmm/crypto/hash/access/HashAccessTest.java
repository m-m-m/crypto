package io.github.mmm.crypto.hash.access;

import java.nio.charset.StandardCharsets;

import org.assertj.core.api.Assertions;

import io.github.mmm.binary.BinaryType;
import io.github.mmm.crypto.hash.HashConfig;

/**
 * Abstract base test for {@link HashConfig}.
 */
public abstract class HashAccessTest extends Assertions {

  /**
   * @param hashConfig the {@link HashConfig}.
   * @param message the message text to hash.
   * @param expectedHashHex the expected hash in hexadecimal encoding.
   */
  protected void check(HashConfig hashConfig, String message, String expectedHashHex) {

    byte[] input = message.getBytes(StandardCharsets.UTF_8);
    byte[] hash = hashConfig.newHashCreator().hash(input, true);
    String hex = BinaryType.formatHex(hash);
    assertThat(hex).as("Hash of message:" + message).isEqualTo(expectedHashHex);
  }

}
