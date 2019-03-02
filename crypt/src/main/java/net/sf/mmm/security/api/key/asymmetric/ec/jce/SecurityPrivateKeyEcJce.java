package net.sf.mmm.security.api.key.asymmetric.ec.jce;

import java.security.interfaces.ECPrivateKey;
import java.util.function.Supplier;

import net.sf.mmm.security.api.key.asymmetric.AbstractSecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;

/**
 * Implementation of {@link SecurityPublicKey} for {@link ECPrivateKey}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityPrivateKeyEcJce extends AbstractSecurityPrivateKey<ECPrivateKey> {

  /**
   * The constructor.
   *
   * @param key the {@link #getKey() key}.
   */
  public SecurityPrivateKeyEcJce(ECPrivateKey key) {

    // super(key.getS().toByteArray(), key);
    super(key.getEncoded(), key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param key the {@link #getKey() key}.
   */
  public SecurityPrivateKeyEcJce(byte[] data, ECPrivateKey key) {

    super(data, key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param keySupplier the {@link Supplier} for the {@link #getKey() key}.
   */
  public SecurityPrivateKeyEcJce(byte[] data, Supplier<ECPrivateKey> keySupplier) {

    super(data, keySupplier);
  }

}
