package io.github.mmm.crypto.crypt;

import io.github.mmm.crypto.algorithm.AbstractSecurityAlgorithm;

/**
 * An implementation of {@link Cryptor} that combines multiple {@link Cryptor}s.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class CryptorImplCombined extends AbstractSecurityAlgorithm implements Cryptor {

  private Cryptor[] cryptors;

  /**
   * The constructor.
   *
   * @param cryptors the {@link Cryptor}s to combine.
   */
  public CryptorImplCombined(Cryptor[] cryptors) {
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
   * @return the last {@link Cryptor} from the chain.
   */
  protected Cryptor getLastCryptor() {

    return this.cryptors[this.cryptors.length - 1];
  }

  @Override
  public byte[] crypt(byte[] input, int offset, int length, boolean complete) {

    byte[] result = null;
    for (Cryptor cryptor : this.cryptors) {
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

    for (Cryptor cryptor : this.cryptors) {
      cryptor.reset();
    }
  }

}
