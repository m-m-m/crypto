package io.github.mmm.crypto.symmetric.key.spec;

import java.security.spec.KeySpec;

import javax.crypto.spec.PBEKeySpec;

import io.github.mmm.crypto.symmetric.key.SymmetricKeySpecFactory;

/// Implementation of [SymmetricKeySpecFactory] for PBE ([PBEKeySpec]). For sufficient security
/// strength you should use a salt of `20` bytes, a [key length][#getKeyLength()] of `256` bits (never
/// use less than `128` bits) and a high number of iterations (e.g. `65536`).
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class SymmetricKeySpecFactoryImplPbe implements SymmetricKeySpecFactory {

  private byte[] salt;

  private int iterationCount;

  private int keyLength;

  /// The constructor.
  public SymmetricKeySpecFactoryImplPbe() {

    this(null, 0, 0);
  }

  /// The constructor.
  ///
  /// @param salt the [salt][PBEKeySpec#getSalt()] or `null` for no salting.
  public SymmetricKeySpecFactoryImplPbe(byte[] salt) {

    this(salt, 0, 0);
  }

  /// The constructor.
  ///
  /// @param salt the [salt][PBEKeySpec#getSalt()] or `null` for no salting.
  /// @param iterationCount the [iteration count][#getIterationCount()].
  public SymmetricKeySpecFactoryImplPbe(byte[] salt, int iterationCount) {

    this(salt, iterationCount, 0);
  }

  /// The constructor.
  ///
  /// @param salt the [salt][PBEKeySpec#getSalt()] or `null` for no salting.
  /// @param iterationCount the [iteration count][#getIterationCount()].
  /// @param keyLength the [key length][#getKeyLength()].
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

  /// @return the [iteration count][PBEKeySpec#getIterationCount()] or `0` for no iterations.
  public int getIterationCount() {

    return this.iterationCount;
  }

  /// @return the [key length][PBEKeySpec#getKeyLength()] in bits or `0` if unspecified (to use defaults).
  public int getKeyLength() {

    return this.keyLength;
  }
}
