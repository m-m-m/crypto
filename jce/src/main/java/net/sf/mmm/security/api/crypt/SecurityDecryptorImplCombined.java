package net.sf.mmm.security.api.crypt;

/**
 * Implementation of {@link SecurityDecryptor} that combines multiple {@link SecurityDecryptor}s.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityDecryptorImplCombined extends SecurityCryptorImplCombined implements AbstractSecurityDecryptor {

  /**
   * The constructor.
   *
   * @param decryptors the {@link SecurityEncryptor}s to combine.
   */
  public SecurityDecryptorImplCombined(SecurityDecryptor[] decryptors) {
    super(decryptors);
  }

}
