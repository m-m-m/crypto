package net.sf.mmm.security.api.key;

import java.security.Key;
import java.security.PrivateKey;
import java.util.function.Supplier;

import net.sf.mmm.security.api.SecurityBinaryType;
import net.sf.mmm.util.datatype.api.BinaryType;

/**
 * Simple datatype as container for a {@link PrivateKey} (see {@link #getKey()}). Allows simple and fast reading and
 * storing as {@link BinaryType} until real semantic parsing and usage is required.
 *
 * @param <KT> the type of the {@link #getKey() key} for {@link SecurityKey}.
 * @param <K> the type of the wrapped {@link #getKey() key}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class AbstractSecurityKey<KT extends Key, K extends KT> extends SecurityBinaryType implements SecurityKey<KT> {

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
   * @param base64 the {@link #getData() data} as {@link #getBase64() base64}.
   * @param key the {@link #getKey() key}.
   */
  public AbstractSecurityKey(String base64, K key) {

    super(base64);
    this.key = key;
    this.keySupplier = null;
  }

  /**
   * The constructor.
   *
   * @param base64 the {@link #getData() data} as {@link #getBase64() base64}.
   * @param keySupplier the {@link Supplier} of the {@link #getKey() key}.
   */
  public AbstractSecurityKey(String base64, Supplier<K> keySupplier) {

    super(base64);
    this.key = null;
    this.keySupplier = keySupplier;
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
   * @param base64 the {@link #getData() data} as {@link #getBase64() base64}.
   */
  public AbstractSecurityKey(String base64) {

    super(base64);
  }

  @Override
  public K getKey() {

    if ((this.key == null) && (this.keySupplier != null)) {
      this.key = this.keySupplier.get();
      this.keySupplier = null;
    }
    return this.key;
  }

}
