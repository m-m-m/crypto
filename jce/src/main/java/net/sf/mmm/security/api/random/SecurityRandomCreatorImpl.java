package net.sf.mmm.security.api.random;

import java.security.SecureRandom;

/**
 * Implementation of {@link SecurityRandomCreator}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityRandomCreatorImpl implements SecurityRandomCreator {

  private final SecureRandom secureRandom;

  private final int reseedCount;

  private int count;

  /**
   * The constructor.
   *
   * @param secureRandom the underlying {@link SecureRandom}.
   * @param reseedCount the
   *        {@link net.sf.mmm.security.api.random.SecurityRandomConfig#getReseedCount() re-seed
   *        count}.
   */
  public SecurityRandomCreatorImpl(SecureRandom secureRandom, int reseedCount) {
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
