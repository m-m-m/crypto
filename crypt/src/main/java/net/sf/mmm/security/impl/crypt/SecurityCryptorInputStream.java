package net.sf.mmm.security.impl.crypt;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

import net.sf.mmm.security.api.crypt.SecurityCryptor;
import net.sf.mmm.security.api.crypt.SecurityDecryptor;
import net.sf.mmm.security.impl.io.InputStreamWrapper;
import net.sf.mmm.security.impl.io.OutputStreamWrapper;

/**
 * Implementation of {@link InputStream} for {@link SecurityDecryptor#wrapStream(InputStream)} based on
 * {@link OutputStreamWrapper}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityCryptorInputStream extends InputStreamWrapper {

  private SecurityCryptor cryptor;

  private final byte[] inBuffer;

  private byte[] outBuffer;

  private int outStart;

  private int outEnd;

  private boolean done; // delegate stream has been consumed?

  /**
   * The constructor.
   *
   * @param cryptor the {@link SecurityCryptor}.
   * @param delegate the {@link InputStream} to wrap.
   */
  public SecurityCryptorInputStream(SecurityCryptor cryptor, InputStream delegate) {
    super(delegate);
    Objects.requireNonNull(cryptor, "cryptor");
    this.cryptor = cryptor;
    this.inBuffer = new byte[512];
    this.outBuffer = null;
    this.outStart = 0;
    this.done = false;
  }

  private int fillBuffer() throws IOException {

    if (this.done) {
      return -1;
    }

    int bytesRead = 0;
    while (bytesRead == 0) {
      bytesRead = getDelegate().read(this.inBuffer);
    }
    if (bytesRead == -1) {
      this.done = true;
      this.outBuffer = this.cryptor.doFinal();
      if ((this.outBuffer == null) || (this.outBuffer.length == 0)) {
        return -1;
      }
    } else {
      this.outBuffer = this.cryptor.crypt(this.inBuffer, 0, bytesRead, false);
    }
    this.outStart = 0;
    this.outEnd = this.outBuffer.length;
    return this.outEnd;
  }

  private boolean hasData() throws IOException {

    if (this.outStart < this.outEnd) {
      return true;
    }
    int bytesRead = 0;
    while (bytesRead == 0) {
      bytesRead = fillBuffer();
    }
    return (bytesRead > 0);
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {

    requireNotClosed();
    if (!hasData()) {
      return -1;
    }
    if ((len <= 0) || (b == null)) {
      return 0;
    }
    int available = this.outEnd - this.outStart;
    if (len < available) {
      available = len;
    }
    System.arraycopy(this.outBuffer, this.outStart, b, off, available);
    this.outStart += available;
    return available;
  }

  @Override
  public int read() throws IOException {

    requireNotClosed();
    if (!hasData()) {
      return -1;
    }
    int result = this.outBuffer[this.outStart++];
    return result & 0xff;
  }

  @Override
  public long skip(long n) throws IOException {

    int skip = this.outEnd - this.outStart;
    if (skip > n) {
      skip = (int) n;
    }
    this.outStart += skip;
    return skip;
  }

  @Override
  public int available() throws IOException {

    return (this.outEnd - this.outStart);
  }

  @Override
  public void close() throws IOException {

    super.close();
    if (this.cryptor != null) {
      try {
        this.cryptor.doFinal();
      } catch (Exception e) {
        // ignore...
      }
    }
    this.cryptor = null;
  }

}
