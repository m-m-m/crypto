package net.sf.mmm.security.api.key.asymmetric.rsa;

import java.security.interfaces.RSAPrivateKey;
import java.util.function.Supplier;

import net.sf.mmm.security.api.key.asymmetric.AbstractSecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;

/**
 * Implementation of {@link SecurityPrivateKey} for {@link RSAPrivateKey}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityPrivateKeyRsa extends AbstractSecurityPrivateKey<RSAPrivateKey> {

  /**
   * The constructor.
   *
   * @param key the {@link #getKey() key}.
   */
  public SecurityPrivateKeyRsa(RSAPrivateKey key) {

    super(key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param key the {@link #getKey() key}.
   */
  public SecurityPrivateKeyRsa(byte[] data, RSAPrivateKey key) {

    super(data, key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param keySupplier the {@link Supplier} of the {@link #getKey() key}.
   */
  public SecurityPrivateKeyRsa(byte[] data, Supplier<RSAPrivateKey> keySupplier) {

    super(data, keySupplier);
  }

}
