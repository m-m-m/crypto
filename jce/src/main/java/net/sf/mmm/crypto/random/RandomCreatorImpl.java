package net.sf.mmm.crypto.random;

import java.security.SecureRandom;

/**
 * Implementation of {@link RandomCreator}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class RandomCreatorImpl implements RandomCreator {

  private final SecureRandom secureRandom;

  private final int reseedCount;

  private int count;

  /**
   * The constructor.
   *
   * @param secureRandom the underlying {@link SecureRandom}.
   * @param reseedCount the
   *        {@link net.sf.mmm.crypto.random.RandomConfig#getReseedCount() re-seed
   *        count}.
   */
  public RandomCreatorImpl(SecureRandom secureRandom, int reseedCount) {
    super();
    this.secureRandom = secureRandom;
    this.reseedCount = reseedCount;
  }

  @Override
  public String getAlgorithm() {

    return this.secureRandom.getAlgorithm();
  }

  @Override
  public byte[] nextRandom(int bytes) {

    if (this.count >= this.reseedCount) {
      this.secureRandom.setSeed(this.secureRandom.generateSeed(64 + (this.secureRandom.nextInt() & 0x0FF)));
      this.count = 0;
    }
    byte[] data = new byte[bytes];
    this.secureRandom.nextBytes(data);
    this.count++;
    return data;
  }

}
