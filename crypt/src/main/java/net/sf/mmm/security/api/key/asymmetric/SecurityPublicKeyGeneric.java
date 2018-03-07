package net.sf.mmm.security.api.key.asymmetric;

import java.security.PublicKey;
import java.util.function.Supplier;

import net.sf.mmm.security.api.key.AbstractSecurityKey;

/**
 * This is a generic implementation of {@link SecurityPublicKey}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityPublicKeyGeneric extends AbstractSecurityKey<PublicKey> implements SecurityPublicKey {

  /**
   * The constructor.
   *
   * @param key the {@link #getKey() key}.
   */
  public SecurityPublicKeyGeneric(PublicKey key) {

    super(key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param key the {@link #getKey() key}.
   */
  public SecurityPublicKeyGeneric(byte[] data, PublicKey key) {

    super(data, key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param keySupplier the {@link Supplier} for the {@link #getKey() key}.
   */
  public SecurityPublicKeyGeneric(byte[] data, Supplier<PublicKey> keySupplier) {

    super(data, keySupplier);
  }

  /**
   * The constructor.
   *
   * @param hex the {@link #getData() data} as {@link #getHex() hex}.
   * @param key the {@link #getKey() key}.
   */
  public SecurityPublicKeyGeneric(String hex, PublicKey key) {

    super(hex, key);
  }

  /**
   * The constructor.
   *
   * @param hex the {@link #getData() data} as {@link #getHex() hex}.
   * @param keySupplier the {@link Supplier} for the {@link #getKey() key}.
   */
  public SecurityPublicKeyGeneric(String hex, Supplier<PublicKey> keySupplier) {

    super(hex, keySupplier);
  }

}
