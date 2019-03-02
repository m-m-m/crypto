package net.sf.mmm.security.api.key.asymmetric.generic;

import java.security.PrivateKey;
import java.util.function.Supplier;

import net.sf.mmm.security.api.key.asymmetric.AbstractSecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;

/**
 * This is a generic implementation of {@link SecurityPrivateKey}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityPrivateKeyGeneric extends AbstractSecurityPrivateKey<PrivateKey> {

  /**
   * The constructor.
   *
   * @param key the {@link #getKey() key}.
   */
  public SecurityPrivateKeyGeneric(PrivateKey key) {

    super(key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param key the {@link #getKey() key}.
   */
  public SecurityPrivateKeyGeneric(byte[] data, PrivateKey key) {

    super(data, key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param keySupplier the {@link Supplier} of the {@link #getKey() key}.
   */
  public SecurityPrivateKeyGeneric(byte[] data, Supplier<PrivateKey> keySupplier) {

    super(data, keySupplier);
  }

  /**
   * The constructor.
   *
   * @param base64 the {@link #getData() data} as {@link #getBase64() base64}.
   * @param key the {@link #getKey() key}.
   */
  public SecurityPrivateKeyGeneric(String base64, PrivateKey key) {

    super(base64, key);
  }

  /**
   * The constructor.
   *
   * @param base64 the {@link #getData() data} as {@link #getBase64() base64}.
   * @param keySupplier the {@link Supplier} of the {@link #getKey() key}.
   */
  public SecurityPrivateKeyGeneric(String base64, Supplier<PrivateKey> keySupplier) {

    super(base64, keySupplier);
  }

}
