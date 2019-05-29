package net.sf.mmm.crypto.asymmetric.sign;

import net.sf.mmm.crypto.algorithm.AbstractSecurityAlgorithm;
import net.sf.mmm.crypto.algorithm.CryptoAlgorithm;
import net.sf.mmm.crypto.hash.HashCreator;

/**
 * Implementation of {@link SignatureProcessor} combining a {@link SignatureSigner} with a
 * {@link HashCreator}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SignatureProcessorImplWithHash extends AbstractSecurityAlgorithm implements SignatureProcessor {

  private final HashCreator hashGenerator;

  /**
   * The constructor.
   *
   * @param hashGenerator the {@link HashCreator} to apply as extension.
   */
  public SignatureProcessorImplWithHash(HashCreator hashGenerator) {

    super();
    this.hashGenerator = hashGenerator;
  }

  /**
   * @return the {@link CryptoAlgorithm} to extend.
   */
  protected abstract CryptoAlgorithm getSignatureAlgorithm();

  /**
   * @return the {@link HashCreator} to apply as extension.
   */
  protected HashCreator getHashGenerator() {

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
