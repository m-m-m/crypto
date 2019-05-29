package net.sf.mmm.crypto.symmetric.key;

import java.util.Objects;

import javax.crypto.SecretKey;

/**
 * Generic implementation of {@link SecuritySymmetricKey}.
 *
 * @param <K> type of {@link SecretKey}.
 * @since 1.0.0
 */
public class SecuritySymmetricKeyGeneric<K extends SecretKey> implements SecuritySymmetricKey<K> {

  private final K key;

  /**
   * The constructor.
   *
   * @param key the {@link SecretKey}.
   */
  public SecuritySymmetricKeyGeneric(K key) {

    super();
    Objects.requireNonNull(key, "key");
    this.key = key;
  }

  @Override
  public K getKey() {

    return this.key;
  }

  @Override
  public int hashCode() {

    return Objects.hash(this.key);
  }

  @Override
  public boolean equals(Object obj) {

    if (this == obj) {
      return true;
    }
    if ((obj == null) || (getClass() != obj.getClass())) {
      return false;
    }
    SecuritySymmetricKeyGeneric<?> other = (SecuritySymmetricKeyGeneric<?>) obj;
    if (!Objects.equals(this.key, other.key)) {
      return false;
    }
    return true;
  }

  @Override
  public String toString() {

    return this.key.toString();
  }

}
