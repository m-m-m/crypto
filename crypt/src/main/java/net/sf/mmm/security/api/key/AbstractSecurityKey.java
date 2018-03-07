package net.sf.mmm.security.api.key;

import java.security.Key;
import java.security.PrivateKey;
import java.util.function.Supplier;

import net.sf.mmm.util.lang.api.BinaryType;

/**
 * Simple datatype as container for a {@link PrivateKey} (see {@link #getKey()}). Allows simple and fast reading and
 * storing as {@link BinaryType} until real semantic parsing and usage is required.
 *
 * @param <K> the type of the wrapped {@link #getKey()}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class AbstractSecurityKey<K extends Key> extends BinaryType implements SecurityKey<K> {

  private K key;

  private Supplier<K> keySupplier;

  /**
   * The constructor.
   *
   * @param key the {@link #getKey() key}.
   */
  public AbstractSecurityKey(K key) {

    this(key.getEncoded(), key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param key the {@link #getKey() key}.
   */
  public AbstractSecurityKey(byte[] data, K key) {

    super(data);
    this.key = key;
    this.keySupplier = null;
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param keySupplier the {@link Supplier} of the {@link #getKey() key}.
   */
  public AbstractSecurityKey(byte[] data, Supplier<K> keySupplier) {

    super(data);
    this.key = null;
    this.keySupplier = keySupplier;
  }

  /**
   * The constructor.
   *
   * @param hex the {@link #getData() data} as {@link #getHex() hex}.
   * @param key the {@link #getKey() key}.
   */
  public AbstractSecurityKey(String hex, K key) {

    super(hex);
    this.key = key;
    this.keySupplier = null;
  }

  /**
   * The constructor.
   *
   * @param hex the {@link #getData() data} as {@link #getHex() hex}.
   * @param keySupplier the {@link Supplier} of the {@link #getKey() key}.
   */
  public AbstractSecurityKey(String hex, Supplier<K> keySupplier) {

    super(hex);
    this.key = null;
    this.keySupplier = keySupplier;
  }

  @Override
  public K getKey() {

    if ((this.key == null) && (this.keySupplier != null)) {
      this.key = this.keySupplier.get();
      this.keySupplier = null;
    }
    return this.key;
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   */
  public AbstractSecurityKey(byte[] data) {

    super(data);
  }

  /**
   * The constructor.
   *
   * @param hex the {@link #getData() data} as {@link #getHex() hex}.
   */
  public AbstractSecurityKey(String hex) {

    super(hex);
  }

}
