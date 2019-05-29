package net.sf.mmm.crypto.hash;

import java.io.OutputStream;
import java.security.MessageDigest;

import net.sf.mmm.crypto.algorithm.CryptoAlgorithmImpl;
import net.sf.mmm.crypto.provider.SecurityProvider;

/**
 * This is a simple implementation of {@link HashCreator} that only wraps {@link MessageDigest}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class HashCreatorImplDigest extends CryptoAlgorithmImpl implements HashCreator {

  private final MessageDigest digest;

  /**
   * The constructor.
   *
   * @param hashAlgorithm the name of the hash algorithm to use (e.g. "SHA-256").
   * @param provider the {@link SecurityProvider} to use.
   */
  public HashCreatorImplDigest(String hashAlgorithm, SecurityProvider provider) {

    super(hashAlgorithm, provider);
    this.digest = getProvider().createDigest(hashAlgorithm);
  }

  @Override
  public OutputStream wrapStream(OutputStream out) {

    return new HashOutputStream(this, out);
  }

  @Override
  public void update(byte[] input, int offset, int length) {

    this.digest.update(input, offset, length);
  }

  @Override
  public byte[] hash(boolean reset) {

    MessageDigest messageDigest = getOrCloneMessageDigest(this.digest, !reset);
    return messageDigest.digest();
  }

  /**
   * @param messageDigest the original {@link MessageDigest}.
   * @param clone - {@code true} to return a clone or copy of the original {@link MessageDigest}, {@code false}
   *        otherwise.
   * @return the original {@link MessageDigest} or a {@link #clone() clone} of it in case the given {@code clone} flag
   *         was {@code true}.
   */
  protected static MessageDigest getOrCloneMessageDigest(MessageDigest messageDigest, boolean clone) {

    if (!clone) {
      return messageDigest;
    }
    try {
      return (MessageDigest) messageDigest.clone();
    } catch (CloneNotSupportedException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public void reset() {

    this.digest.reset();
  }

}
