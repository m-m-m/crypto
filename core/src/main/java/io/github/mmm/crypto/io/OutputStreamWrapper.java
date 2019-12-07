package io.github.mmm.crypto.io;

import java.io.IOException;
import java.io.OutputStream;

/**
 * An {@link OutputStream} that wraps another {@link OutputStream} to delegate to.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class OutputStreamWrapper extends OutputStream {

  private final OutputStream delegate;

  private boolean closed;

  /**
   * The constructor.
   */
  public OutputStreamWrapper() {
    this(null);
  }

  /**
   * The constructor.
   *
   * @param delegate the {@link #getDelegate() delegate}. May be {@code null}.
   */
  public OutputStreamWrapper(OutputStream delegate) {

    super();
    this.delegate = delegate;
    this.closed = false;
  }

  /**
   * @return the wrapped {@link OutputStream} to delegate to. May be {@code null} for none ({@code /dev/null}.
   */
  protected OutputStream getDelegate() {

    return this.delegate;
  }

  /**
   * @throws IOException if the stream has already been closed.
   */
  protected void requireNotClosed() throws IOException {

    if (this.closed) {
      throw new IOException("Stream already closed.");
    }
  }

  @Override
  public final void write(byte[] b) throws IOException {

    write(b, 0, b.length);
  }

  @Override
  public void write(byte[] b, int off, int len) throws IOException {

    requireNotClosed();
    if (this.delegate != null) {
      this.delegate.write(b, off, len);
    }
  }

  @Override
  public void write(int b) throws IOException {

    requireNotClosed();
    if (this.delegate != null) {
      this.delegate.write(b);
    }
  }

  @Override
  public void close() throws IOException {

    this.closed = false;
  }

  /**
   * @return {@code true} if {@link #close() closed}, {@code false} otherwise.
   */
  protected boolean isClosed() {

    return this.closed;
  }

}
