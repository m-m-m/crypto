package net.sf.mmm.security.impl.hash;

import java.io.OutputStream;
import java.security.MessageDigest;

import net.sf.mmm.security.api.hash.SecurityHashCreator;
import net.sf.mmm.security.impl.AbstractSecurityAlgorithm;

/**
 * This is a simple implementation of {@link SecurityHashCreator} that only wraps {@link MessageDigest}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityHashCreatorImplCombine extends AbstractSecurityAlgorithm implements SecurityHashCreator {

  private final SecurityHashCreator[] generators;

  /**
   * The constructor.
   *
   * @param generators the {@link SecurityHashCreator}s to combine sequentially.
   */
  public SecurityHashCreatorImplCombine(SecurityHashCreator[] generators) {
    super();
    this.generators = generators;
  }

  @Override
  public String getAlgorithm() {

    return getAlgorithm(this.generators);
  }

  @Override
  public OutputStream wrapStream(OutputStream out) {

    return new SecurityHashOutputStream(this, out);
  }

  @Override
  public void update(byte[] input, int offset, int length) {

    this.generators[0].update(input, offset, length);
  }

  @Override
  public byte[] hash(boolean reset) {

    byte[] hash = null;
    for (SecurityHashCreator generator : this.generators) {
      if (hash != null) {
        generator.update(hash);
      }
      hash = generator.hash(reset);
    }
    return hash;
  }

  @Override
  public void reset() {

    for (SecurityHashCreator generator : this.generators) {
      generator.reset();
    }
  }

}
