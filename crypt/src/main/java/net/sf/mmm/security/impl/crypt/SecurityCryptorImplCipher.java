package net.sf.mmm.security.impl.crypt;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import net.sf.mmm.security.api.crypt.SecurityCryptor;
import net.sf.mmm.security.api.crypt.SecurityCryptorConfig;
import net.sf.mmm.security.api.crypt.SecurityDecryptor;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;
import net.sf.mmm.security.api.random.SecurityRandomFactory;
import net.sf.mmm.security.impl.AbstractSecurityAlgorithmWithRandom;
import net.sf.mmm.util.datatype.api.Binary;

/**
 * Abstract implementation of {@link SecurityCryptor} based on {@link Cipher}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecurityCryptorImplCipher extends AbstractSecurityAlgorithmWithRandom implements SecurityCryptor {

  private final SecurityCryptorConfig<?> config;

  private final Key key;

  private final int nonceSize;

  private Cipher cipher;

  private byte[] nonce;

  /** Index in {@link #nonce} or {@code -1} if nonce has completely been processed. */
  private int nonceIndex;

  /**
   * The constructor.
   *
   * @param provider the optional security {@link Provider}.
   * @param randomFactory the {@link SecurityRandomFactory} to use.
   * @param config the {@link SecurityCryptorConfig}.
   * @param key the {@link Key} to use.
   */
  public SecurityCryptorImplCipher(Provider provider, SecurityRandomFactory randomFactory,
      SecurityCryptorConfig<?> config, Key key) {

    super(provider, randomFactory);
    this.key = key;
    this.config = config;
    this.nonceSize = config.getNonceSize();
  }

  @Override
  public String getAlgorithm() {

    return this.config.getAlgorithm();
  }

  @Override
  public int getNonceSize() {

    return this.nonceSize;
  }

  /**
   * @return the underlying {@link Cipher}.
   */
  protected Cipher getCipher() {

    if (this.cipher == null) {
      Provider provider = getProvider();
      try {
        if (provider == null) {
          this.cipher = Cipher.getInstance(getAlgorithm());
        } else {
          this.cipher = Cipher.getInstance(getAlgorithm(), provider);
        }
        int opmode;
        AlgorithmParameterSpec parameters = null;
        SecureRandom secureRandom = getRandomFactory().newSecureRandom();
        boolean encryptor = isEncryptor();
        if (encryptor) {
          opmode = Cipher.ENCRYPT_MODE;
          if ((this.nonceSize > 0) && this.config.isCreateRandomNonce()) {
            this.nonce = new byte[this.nonceSize];
            secureRandom.nextBytes(this.nonce);
            parameters = new IvParameterSpec(this.nonce);
          }
        } else {
          opmode = Cipher.DECRYPT_MODE;
          if (this.nonceSize > 0) {
            Objects.requireNonNull(this.nonce, "nonce");
            if (this.nonce.length != this.nonceSize) {
              throw new IllegalStateException(
                  "Required nonce size is " + this.nonceSize + " but " + this.nonce.length + " was found!");
            }
            parameters = new IvParameterSpec(this.nonce);
            this.nonce = null;
          }
          this.nonceIndex = -1;
        }
        if (parameters == null) {
          this.cipher.init(opmode, this.key, secureRandom);
        } else {
          this.cipher.init(opmode, this.key, parameters, secureRandom);
        }
        if (encryptor && (this.nonceSize > 0) && !this.config.isCreateRandomNonce()) {
          this.nonce = this.cipher.getIV();
          assert (this.nonceSize == this.nonce.length);
        }
      } catch (Exception e) {
        throw creationFailedException(e, Cipher.class);
      }
    }
    return this.cipher;
  }

  /**
   * @return {@code true} if {@link SecurityEncryptor}, {@code false} if {@link SecurityDecryptor}.
   */
  protected abstract boolean isEncryptor();

  /**
   * @return the {@link SecurityCryptorConfig}.
   */
  public final SecurityCryptorConfig<?> getConfig() {

    return this.config;
  }

  /**
   * @return "decryption" for {@link SecurityDecryptor} and "encryption" for {@link SecurityEncryptor}.
   */
  protected String getMode() {

    if (isEncryptor()) {
      return "encryption";
    } else {
      return "decryption";
    }
  }

  private int readNonce(byte[] input, int off, int len) {

    assert (this.nonceIndex >= 0);
    if (this.nonce == null) {
      this.nonce = new byte[this.nonceSize];
      this.nonceIndex = 0;
    }
    int nonceBytes = this.nonce.length - this.nonceIndex;
    if (nonceBytes > 0) {
      if (nonceBytes > len) {
        nonceBytes = len;
      }
      System.arraycopy(input, off, this.nonce, this.nonceIndex, nonceBytes);
      this.nonceIndex += nonceBytes;
      return nonceBytes;
    } else {
      return 0;
    }
  }

  @Override
  public byte[] crypt(byte[] input, int offset, int length, boolean complete) {

    try {
      int off = offset;
      int len = length;
      if ((this.nonceSize > 0) && (this.nonceIndex >= 0) && !isEncryptor()) {
        int nonceBytes = readNonce(input, off, len);
        off += nonceBytes;
        len -= nonceBytes;
        if (len <= 0) {
          return Binary.EMPTY_BYTE_ARRAY;
        }
      }
      byte[] result;
      if (complete) {
        result = getCipher().doFinal(input, off, len);
      } else {
        result = getCipher().update(input, off, len);
      }
      if ((this.nonceSize > 0) && (this.nonceIndex == 0) && isEncryptor()) {
        byte[] data = new byte[result.length + this.nonceSize];
        System.arraycopy(this.nonce, 0, data, 0, this.nonceSize);
        this.nonceIndex = -1;
        System.arraycopy(result, 0, data, this.nonceSize, result.length);
        result = data;
      }
      return result;
    } catch (GeneralSecurityException e) {
      throw wrapSecurityException(e);
    }
  }

  /**
   * @param e the {@link Exception} to wrap.
   * @return the wrapped {@link RuntimeException}.
   */
  protected RuntimeException wrapSecurityException(Exception e) {

    return new IllegalStateException("The " + getMode() + " failed: " + e.getMessage(), e);
  }

  @Override
  public void reset() {

    if (this.cipher != null) {
      try {
        this.cipher.doFinal();
      } catch (Exception e) {
        // ignore...
      }
      this.cipher = null;
    }
    this.nonce = null;
    this.nonceIndex = 0;
  }

}
