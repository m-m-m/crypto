package net.sf.mmm.security.api.key.symmetric;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Supplier;

import javax.crypto.SecretKey;

import net.sf.mmm.security.api.key.AbstractSecurityKey;

/**
 * This is a generic implementation of {@link SecuritySymmetricKey}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySymmetricKeyGeneric extends AbstractSecurityKey<SecretKey, SecretKey> implements SecuritySymmetricKey {

  /**
   * The constructor.
   *
   * @param key the {@link #getKey() key}.
   */
  public SecuritySymmetricKeyGeneric(SecretKey key) {

    super(key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param key the {@link #getKey() key}.
   */
  public SecuritySymmetricKeyGeneric(byte[] data, SecretKey key) {

    super(data, key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param keySupplier the {@link Supplier} of the {@link #getKey() key}.
   */
  public SecuritySymmetricKeyGeneric(byte[] data, Supplier<SecretKey> keySupplier) {

    super(data, keySupplier);
  }

  /**
   * The constructor.
   *
   * @param base64 the {@link #getData() data} as {@link #getBase64() base64}.
   * @param key the {@link #getKey() key}.
   */
  public SecuritySymmetricKeyGeneric(String base64, SecretKey key) {

    super(base64, key);
  }

  /**
   * The constructor.
   *
   * @param base64 the {@link #getData() data} as {@link #getBase64() base64}.
   * @param keySupplier the {@link Supplier} of the {@link #getKey() key}.
   */
  public SecuritySymmetricKeyGeneric(String base64, Supplier<SecretKey> keySupplier) {

    super(base64, keySupplier);
  }

  @Override
  public Set<SecuritySymmetricKey> getKeys() {

    Set<SecuritySymmetricKey> set = new HashSet<>();
    set.add(this);
    return set;
  }

}
