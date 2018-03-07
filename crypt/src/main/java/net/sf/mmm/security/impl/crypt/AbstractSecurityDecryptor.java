package net.sf.mmm.security.impl.crypt;

import java.io.InputStream;

import net.sf.mmm.security.api.crypt.SecurityDecryptor;

/**
 * Abstract implementation of {@link SecurityDecryptor}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractSecurityDecryptor extends SecurityDecryptor {

  @Override
  default InputStream wrapStream(InputStream stream) {

    return new SecurityCryptorInputStream(this, stream);
  }

  @Override
  default SecurityDecryptor combine(SecurityDecryptor... decryptors) {

    if ((decryptors == null) || (decryptors.length == 0)) {
      return this;
    }
    SecurityDecryptor[] decryptorChain = new SecurityDecryptor[decryptors.length + 1];
    System.arraycopy(decryptors, 0, decryptorChain, 1, decryptors.length);
    decryptorChain[0] = this;
    return new SecurityDecryptorImplCombined(decryptorChain);
  }

}
