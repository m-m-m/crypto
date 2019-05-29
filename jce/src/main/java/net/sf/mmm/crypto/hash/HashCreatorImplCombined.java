package net.sf.mmm.crypto.hash;

import java.io.OutputStream;
import java.security.MessageDigest;

import net.sf.mmm.crypto.algorithm.AbstractSecurityAlgorithm;

/**
 * This is a simple implementation of {@link HashCreator} that only wraps {@link MessageDigest}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class HashCreatorImplCombined extends AbstractSecurityAlgorithm implements HashCreator {

  private final HashCreator[] generators;

  /**
   * The constructor.
   *
   * @param generators the {@link HashCreator}s to combine sequentially.
   */
  public HashCreatorImplCombined(HashCreator[] generators) {
    super();
    this.generators = generators;
  }

  @Override
  public String getAlgorithm() {

    return getAlgorithm(this.generators);
  }

  @Override
  public OutputStream wrapStream(OutputStream out) {

    return new HashOutputStream(this, out);
  }

  @Override
  public void update(byte[] input, int offset, int length) {

    this.generators[0].update(input, offset, length);
  }

  @Override
  public byte[] hash(boolean reset) {

    byte[] hash = null;
    for (HashCreator generator : this.generators) {
      if (hash != null) {
        generator.update(hash);
      }
      hash = generator.hash(reset);
    }
    return hash;
  }

  @Override
  public void reset() {

    for (HashCreator generator : this.generators) {
      generator.reset();
    }
  }

}
