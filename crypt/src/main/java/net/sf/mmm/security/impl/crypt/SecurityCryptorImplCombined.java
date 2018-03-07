package net.sf.mmm.security.impl.crypt;

import net.sf.mmm.security.api.crypt.SecurityCryptor;
import net.sf.mmm.security.impl.AbstractSecurityAlgorithm;

/**
 * An implementation of {@link SecurityCryptor} that combines multiple {@link SecurityCryptor}s.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecurityCryptorImplCombined extends AbstractSecurityAlgorithm implements SecurityCryptor {

  private SecurityCryptor[] cryptors;

  /**
   * The constructor.
   *
   * @param cryptors the {@link SecurityCryptor}s to combine.
   */
  public SecurityCryptorImplCombined(SecurityCryptor[] cryptors) {
    super();
    this.cryptors = cryptors;
  }

  @Override
  public String getAlgorithm() {

    return getAlgorithm(this.cryptors);
  }

  @Override
  public int getNonceSize() {

    return getLastCryptor().getNonceSize();
  }

  /**
   * @return the last {@link SecurityCryptor} from the chain.
   */
  protected SecurityCryptor getLastCryptor() {

    return this.cryptors[this.cryptors.length - 1];
  }

  @Override
  public byte[] crypt(byte[] input, int offset, int length, boolean complete) {

    byte[] result = null;
    for (SecurityCryptor cryptor : this.cryptors) {
      if (result == null) {
        result = cryptor.crypt(input, offset, length, complete);
      } else {
        result = cryptor.crypt(result, complete);
      }
    }
    return result;
  }

  @Override
  public void reset() {

    for (SecurityCryptor cryptor : this.cryptors) {
      cryptor.reset();
    }
  }

}
