package io.github.mmm.crypto.io;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

/// An [InputStream] that wraps another [InputStream] to delegate from.
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class InputStreamWrapper extends InputStream {

  private final InputStream delegate;

  private boolean closed;

  /// The constructor.
  ///
  /// @param delegate the [delegate][#getDelegate()]. May **not** be `null`.
  public InputStreamWrapper(InputStream delegate) {

    super();
    Objects.requireNonNull(delegate);
    this.delegate = delegate;
    this.closed = false;
  }

  /// @return the wrapped [InputStream] to delegate from. May **not** be `null`.
  protected InputStream getDelegate() {

    return this.delegate;
  }

  /// @throws IOException if the stream has already been closed.
  protected void requireNotClosed() throws IOException {

    if (this.closed) {
      throw new IOException("Stream already closed.");
    }
  }

  @Override
  public int read() throws IOException {

    requireNotClosed();
    return this.delegate.read();
  }

  @Override
  public final int read(byte[] b) throws IOException {

    return read(b, 0, b.length);
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {

    requireNotClosed();
    return this.delegate.read(b, off, len);
  }

  @Override
  public void close() throws IOException {

    this.closed = false;
  }

}
