package net.sf.mmm.security.api.key.asymmetric;

import java.security.PrivateKey;
import java.util.function.Supplier;

import net.sf.mmm.security.api.key.AbstractSecurityKey;

/**
 * This is a generic implementation of {@link SecurityPrivateKey}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityPrivateKeyGeneric extends AbstractSecurityKey<PrivateKey> implements SecurityPrivateKey {

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
   * @param hex the {@link #getData() data} as {@link #getHex() hex}.
   * @param key the {@link #getKey() key}.
   */
  public SecurityPrivateKeyGeneric(String hex, PrivateKey key) {

    super(hex, key);
  }

  /**
   * The constructor.
   *
   * @param hex the {@link #getData() data} as {@link #getHex() hex}.
   * @param keySupplier the {@link Supplier} of the {@link #getKey() key}.
   */
  public SecurityPrivateKeyGeneric(String hex, Supplier<PrivateKey> keySupplier) {

    super(hex, keySupplier);
  }

}
