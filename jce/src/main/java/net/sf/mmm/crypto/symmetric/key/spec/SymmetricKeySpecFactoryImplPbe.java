package net.sf.mmm.crypto.symmetric.key.spec;

import java.security.spec.KeySpec;

import javax.crypto.spec.PBEKeySpec;

import net.sf.mmm.crypto.symmetric.key.SymmetricKeySpecFactory;

/**
 * Implementation of {@link SymmetricKeySpecFactory} for PBE ({@link PBEKeySpec}). For sufficient security
 * strength you should use a salt of {@code 20} bytes, a {@link #getKeyLength() key length} of {@code 256} bits (never
 * use less than {@code 128} bits) and a high number of iterations (e.g. {@code 65536}).
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SymmetricKeySpecFactoryImplPbe implements SymmetricKeySpecFactory {

  private byte[] salt;

  private int iterationCount;

  private int keyLength;

  /**
   * The constructor.
   */
  public SymmetricKeySpecFactoryImplPbe() {

    this(null, 0, 0);
  }

  /**
   * The constructor.
   *
   * @param salt the {@link PBEKeySpec#getSalt() salt} or {@code null} for no salting.
   */
  public SymmetricKeySpecFactoryImplPbe(byte[] salt) {

    this(salt, 0, 0);
  }

  /**
   * The constructor.
   *
   * @param salt the {@link PBEKeySpec#getSalt() salt} or {@code null} for no salting.
   * @param iterationCount the {@link #getIterationCount() iteration count}.
   */
  public SymmetricKeySpecFactoryImplPbe(byte[] salt, int iterationCount) {

    this(salt, iterationCount, 0);
  }

  /**
   * The constructor.
   *
   * @param salt the {@link PBEKeySpec#getSalt() salt} or {@code null} for no salting.
   * @param iterationCount the {@link #getIterationCount() iteration count}.
   * @param keyLength the {@link #getKeyLength() key length}.
   */
  public SymmetricKeySpecFactoryImplPbe(byte[] salt, int iterationCount, int keyLength) {
    super();
    if (iterationCount < 0) {
      throw new IllegalArgumentException("iterationCount: " + iterationCount);
    }
    if (keyLength < 0) {
      throw new IllegalArgumentException("keyLength: " + keyLength);
    }
    if (salt == null) {
      if ((iterationCount != 0) || (keyLength != 0)) {
        throw new IllegalArgumentException("No iterationCount or keyLength can be specified if salt is null!");
      }
      this.salt = null;
    } else {
      this.salt = salt.clone();
    }
    this.keyLength = keyLength;
    this.iterationCount = iterationCount;
  }

  @Override
  public KeySpec createKeySpec(String password) {

    char[] pwd = password.toCharArray();
    if (this.salt == null) {
      assert (this.iterationCount == 0);
      assert (this.keyLength == 0);
      return new PBEKeySpec(pwd);
    } else if (this.keyLength <= 0) {
      return new PBEKeySpec(pwd, this.salt, this.iterationCount);
    } else {
      return new PBEKeySpec(pwd, this.salt, this.iterationCount, this.keyLength);
    }
  }

  /**
   * @return the {@link PBEKeySpec#getIterationCount() iteration count} or {@code 0} for no iterations.
   */
  public int getIterationCount() {

    return this.iterationCount;
  }

  /**
   * @return the {@link PBEKeySpec#getKeyLength() key length} in bits or {@code 0} if unspecified (to use defaults).
   */
  public int getKeyLength() {

    return this.keyLength;
  }
}
