package net.sf.mmm.security.api.key.asymmetric;

import java.security.PublicKey;
import java.util.function.Supplier;

import net.sf.mmm.security.api.key.AbstractSecurityKey;

/**
 * Abstract base implementation of {@link SecurityPublicKey}.
 *
 * @param <K> the type of the wrapped {@link #getKey() key}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class AbstractSecurityPublicKey<K extends PublicKey> extends AbstractSecurityKey<PublicKey, K> implements SecurityPublicKey {

  /**
   * The constructor.
   *
   * @param key the {@link #getKey() key}.
   */
  public AbstractSecurityPublicKey(K key) {

    super(key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param key the {@link #getKey() key}.
   */
  public AbstractSecurityPublicKey(byte[] data, K key) {

    super(data, key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param keySupplier the {@link Supplier} of the {@link #getKey() key}.
   */
  public AbstractSecurityPublicKey(byte[] data, Supplier<K> keySupplier) {

    super(data, keySupplier);
  }

  /**
   * The constructor.
   *
   * @param base64 the {@link #getData() data} as {@link #getBase64() base64}.
   * @param key the {@link #getKey() key}.
   */
  public AbstractSecurityPublicKey(String base64, K key) {

    super(base64, key);
  }

  /**
   * The constructor.
   *
   * @param base64 the {@link #getData() data} as {@link #getBase64() base64}.
   * @param keySupplier the {@link Supplier} of the {@link #getKey() key}.
   */
  public AbstractSecurityPublicKey(String base64, Supplier<K> keySupplier) {

    super(base64, keySupplier);
  }

}
