package net.sf.mmm.security.api.asymmetric.sign;

import net.sf.mmm.security.api.algorithm.AbstractSecurityAlgorithm;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithm;
import net.sf.mmm.security.api.hash.SecurityHashCreator;

/**
 * Implementation of {@link SecuritySignatureProcessor} combining a {@link SecuritySignatureSigner} with a
 * {@link SecurityHashCreator}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecuritySignatureProcessorImplWithHash extends AbstractSecurityAlgorithm implements SecuritySignatureProcessor {

  private final SecurityHashCreator hashGenerator;

  /**
   * The constructor.
   *
   * @param hashGenerator the {@link SecurityHashCreator} to apply as extension.
   */
  public SecuritySignatureProcessorImplWithHash(SecurityHashCreator hashGenerator) {

    super();
    this.hashGenerator = hashGenerator;
  }

  /**
   * @return the {@link SecurityAlgorithm} to extend.
   */
  protected abstract SecurityAlgorithm getSignatureAlgorithm();

  /**
   * @return the {@link SecurityHashCreator} to apply as extension.
   */
  protected SecurityHashCreator getHashGenerator() {

    return this.hashGenerator;
  }

  @Override
  public String getAlgorithm() {

    return this.hashGenerator.getAlgorithm() + "+" + getSignatureAlgorithm().getAlgorithm();
  }

  @Override
  public void update(byte[] input, int offset, int length) {

    this.hashGenerator.update(input, offset, length);
  }

  @Override
  public void reset() {

    this.hashGenerator.reset();
  }

}
