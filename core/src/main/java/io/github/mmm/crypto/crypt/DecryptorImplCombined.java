package io.github.mmm.crypto.crypt;

/**
 * Implementation of {@link Decryptor} that combines multiple {@link Decryptor}s.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class DecryptorImplCombined extends CryptorImplCombined implements AbstractDecryptor {

  /**
   * The constructor.
   *
   * @param decryptors the {@link Encryptor}s to combine.
   */
  public DecryptorImplCombined(Decryptor[] decryptors) {
    super(decryptors);
  }

}
