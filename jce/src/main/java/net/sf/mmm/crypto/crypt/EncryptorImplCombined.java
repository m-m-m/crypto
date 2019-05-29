package net.sf.mmm.crypto.crypt;

/**
 * Implementation of {@link Encryptor} that combines multiple {@link Encryptor}s.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class EncryptorImplCombined extends CryptorImplCombined implements AbstractEncryptor {

  /**
   * The constructor.
   *
   * @param encryptors the {@link Encryptor}s to combine.
   */
  public EncryptorImplCombined(Encryptor[] encryptors) {
    super(encryptors);
  }

}
