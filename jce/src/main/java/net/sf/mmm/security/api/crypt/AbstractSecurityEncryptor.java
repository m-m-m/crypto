package net.sf.mmm.security.api.crypt;

import java.io.OutputStream;

/**
 * Abstract implementation of {@link SecurityEncryptor}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractSecurityEncryptor extends SecurityEncryptor {

  @Override
  default OutputStream wrapStream(OutputStream stream) {

    return new SecurityCryptorOutputStream(this, stream);
  }

  @Override
  default SecurityEncryptor combine(SecurityEncryptor... encryptors) {

    if ((encryptors == null) || (encryptors.length == 0)) {
      return this;
    }
    SecurityEncryptor[] encryptorChain = new SecurityEncryptor[encryptors.length + 1];
    System.arraycopy(encryptors, 0, encryptorChain, 1, encryptors.length);
    encryptorChain[0] = this;
    return new SecurityEncryptorImplCombined(encryptorChain);
  }

}
