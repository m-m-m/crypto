package net.sf.mmm.crypto.crypt;

import java.io.InputStream;

/**
 * Abstract implementation of {@link Decryptor}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractDecryptor extends Decryptor {

  @Override
  default InputStream wrapStream(InputStream stream) {

    return new CryptorInputStream(this, stream);
  }

  @Override
  default Decryptor combine(Decryptor... decryptors) {

    if ((decryptors == null) || (decryptors.length == 0)) {
      return this;
    }
    Decryptor[] decryptorChain = new Decryptor[decryptors.length + 1];
    System.arraycopy(decryptors, 0, decryptorChain, 1, decryptors.length);
    decryptorChain[0] = this;
    return new DecryptorImplCombined(decryptorChain);
  }

}
