package net.sf.mmm.security.api.crypt;

/**
 * Implementation of {@link SecurityEncryptor} that combines multiple {@link SecurityEncryptor}s.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityEncryptorImplCombined extends SecurityCryptorImplCombined implements AbstractSecurityEncryptor {

  /**
   * The constructor.
   *
   * @param encryptors the {@link SecurityEncryptor}s to combine.
   */
  public SecurityEncryptorImplCombined(SecurityEncryptor[] encryptors) {
    super(encryptors);
  }

}
