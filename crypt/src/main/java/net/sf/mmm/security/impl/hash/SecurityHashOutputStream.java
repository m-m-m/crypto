package net.sf.mmm.security.impl.hash;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;

import net.sf.mmm.security.api.hash.SecurityHashCreator;
import net.sf.mmm.security.impl.io.OutputStreamWrapper;

/**
 * An {@link OutputStream} that writes to a {@link MessageDigest}. Unlike {@link java.security.DigestOutputStream} it
 * does not wrap an {@link OutputStream} to write through.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityHashOutputStream extends OutputStreamWrapper {

  private final SecurityHashCreator hashGenerator;

  /**
   * The constructor.
   *
   * @param hashGenerator the {@link SecurityHashCreator}.
   */
  public SecurityHashOutputStream(SecurityHashCreator hashGenerator) {
    this(hashGenerator, null);
  }

  /**
   * The constructor.
   *
   * @param hashGenerator the {@link SecurityHashCreator}.
   * @param delegate the {@link #getDelegate() delegate}. May be {@code null}.
   */
  public SecurityHashOutputStream(SecurityHashCreator hashGenerator, OutputStream delegate) {

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
