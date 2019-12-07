package io.github.mmm.crypto.crypt;

import java.io.OutputStream;

/**
 * Abstract implementation of {@link Encryptor}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractEncryptor extends Encryptor {

  @Override
  default OutputStream wrapStream(OutputStream stream) {

    return new CryptorOutputStream(this, stream);
  }

  @Override
  default Encryptor combine(Encryptor... encryptors) {

    if ((encryptors == null) || (encryptors.length == 0)) {
      return this;
    }
    Encryptor[] encryptorChain = new Encryptor[encryptors.length + 1];
    System.arraycopy(encryptors, 0, encryptorChain, 1, encryptors.length);
    encryptorChain[0] = this;
    return new EncryptorImplCombined(encryptorChain);
  }

}
