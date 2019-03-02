package net.sf.mmm.security.api.key.asymmetric.rsa;

import java.security.interfaces.RSAPublicKey;
import java.util.function.Supplier;

import net.sf.mmm.security.api.key.asymmetric.AbstractSecurityPublicKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;

/**
 * Implementation of {@link SecurityPublicKey} for {@link RSAPublicKey}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityPublicKeyRsa extends AbstractSecurityPublicKey<RSAPublicKey> {

  /**
   * The constructor.
   *
   * @param key the {@link #getKey() key}.
   */
  public SecurityPublicKeyRsa(RSAPublicKey key) {

    super(key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param key the {@link #getKey() key}.
   */
  public SecurityPublicKeyRsa(byte[] data, RSAPublicKey key) {

    super(data, key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param keySupplier the {@link Supplier} for the {@link #getKey() key}.
   */
  public SecurityPublicKeyRsa(byte[] data, Supplier<RSAPublicKey> keySupplier) {

    super(data, keySupplier);
  }

}
