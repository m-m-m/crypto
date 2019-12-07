package io.github.mmm.crypto.hash;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;

import io.github.mmm.crypto.io.OutputStreamWrapper;

/**
 * An {@link OutputStream} that writes to a {@link MessageDigest}. Unlike {@link java.security.DigestOutputStream} it
 * does not wrap an {@link OutputStream} to write through.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class HashOutputStream extends OutputStreamWrapper {

  private final HashCreator hashGenerator;

  /**
   * The constructor.
   *
   * @param hashGenerator the {@link HashCreator}.
   */
  public HashOutputStream(HashCreator hashGenerator) {
    this(hashGenerator, null);
  }

  /**
   * The constructor.
   *
   * @param hashGenerator the {@link HashCreator}.
   * @param delegate the {@link #getDelegate() delegate}. May be {@code null}.
   */
  public HashOutputStream(HashCreator hashGenerator, OutputStream delegate) {

    super(delegate);
    this.hashGenerator = hashGenerator;
  }

  @Override
  public void write(byte[] b, int off, int len) throws IOException {

    super.write(b, off, len);
    this.hashGenerator.update(b, off, len);
  }

  @Override
  public void write(int b) throws IOException {

    super.write(b);
    this.hashGenerator.update(new byte[] { (byte) b });
  }

}
