package io.github.mmm.crypto;

import io.github.mmm.crypto.algorithm.CryptoAlgorithm;

/**
 * Interface to {@link #getIterationCount() get} the {@link #getIterationCount() iteration count}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractGetIterationCount {

  /**
   * @return the iteration count representing the number of repetitive iterations of an
   *         {@link CryptoAlgorithm#getAlgorithm() algorithm} such as a hash function. A value of {@code 1} means that
   *         the algorithm is applied only a single time. This can be fine for simple hashing. Any higher number means
   *         an according repetition of the algorithm. The higher the number the higher the computation time. While e.g.
   *         for password checks a high iteration count may only mean an overhead of roughly one second, an attacker who
   *         wants to try every password with a brute force attack will require an extra ordinary magnitude of
   *         additional computing power. Therefore in case of a password algorithm such as PBKDF2 a higher number will
   *         mean higher security. However, the value is always a trade-off between usability and security. Further, a
   *         too high number might even open the door to denial of service attacks (DoS). A good value can only be
   *         defined for a particular algorithm in combination of the current hardware resources and computation power
   *         that increase over time.
   * @see javax.crypto.spec.PBEKeySpec#getIterationCount()
   */
  int getIterationCount();

}
