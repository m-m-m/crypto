package net.sf.mmm.security.impl.crypt;

import java.io.IOException;
import java.io.OutputStream;

import net.sf.mmm.security.api.crypt.SecurityCryptor;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;
import net.sf.mmm.security.impl.io.OutputStreamWrapper;

/**
 * Implementation of {@link OutputStream} for {@link SecurityEncryptor#wrapStream(OutputStream)} based on
 * {@link OutputStreamWrapper}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityCryptorOutputStream extends OutputStreamWrapper {

  private SecurityCryptor cryptor;

  /**
   * The constructor.
   *
   * @param cryptor the {@link SecurityCryptor}.
   * @param delegate the {@link OutputStream} to wrap.
   */
  public SecurityCryptorOutputStream(SecurityCryptor cryptor, OutputStream delegate) {
    super(delegate);
    this.cryptor = cryptor;
  }

  @Override
  public void write(byte[] b, int off, int len) throws IOException {

    requireNotClosed();
    byte[] data = this.cryptor.crypt(b, off, len, false);
    super.write(data);
  }

  @Override
  public void write(int b) throws IOException {

    byte[] data = this.cryptor.crypt(new byte[] { (byte) b }, false);
    super.write(data);
  }

  @Override
  public void close() throws IOException {

    if (!isClosed()) {
      byte[] data = this.cryptor.doFinal();
      if ((data != null) && (data.length > 0)) {
        super.write(data);
      }
    }
    super.close();
    this.cryptor = null;
  }

}
