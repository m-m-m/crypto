package net.sf.mmm.crypto.symmetric.access;

import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

import net.sf.mmm.crypto.symmetric.key.SymmetricKeyCreator;

import org.assertj.core.api.Assertions;

/**
 * Abstract base test of {@link SymmetricAccess}.
 */
public abstract class SymmetricAccessTest extends Assertions {

  /**
   * @param <K> type of {@link SecretKey}.
   * @param access the {@link SymmetricAccess} to test.
   */
  protected <K extends SecretKey> void check(SymmetricAccess<K> access) {

    SymmetricKeyCreator<K> keyCreator = access.newKeyCreator();
    String password = "$4cr4t";
    K key = keyCreator.createKey(password);
    // assertThat(keyCreator.getKeyLength(key)).isEqualTo(keyCreator.getKeyLength());

    byte[] rawMessage = "Secret message".getBytes(StandardCharsets.UTF_8);
    byte[] encryptedMessage = access.newEncryptor(key).crypt(rawMessage, true);
    byte[] decryptedMessage = access.newDecryptor(key).crypt(encryptedMessage, true);
    assertThat(decryptedMessage).isEqualTo(rawMessage);

  }

}
