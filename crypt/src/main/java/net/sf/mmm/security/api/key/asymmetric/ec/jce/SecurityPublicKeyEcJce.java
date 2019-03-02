package net.sf.mmm.security.api.key.asymmetric.ec.jce;

import java.security.interfaces.ECPublicKey;
import java.util.function.Supplier;

import net.sf.mmm.security.api.key.asymmetric.AbstractSecurityPublicKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;

/**
 * Implementation of {@link SecurityPublicKey} for {@link ECPublicKey}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityPublicKeyEcJce extends AbstractSecurityPublicKey<ECPublicKey> {

  /**
   * The constructor.
   *
   * @param key the {@link #getKey() key}.
   */
  public SecurityPublicKeyEcJce(ECPublicKey key) {

    // super(key.getW().getAffineX().toByteArray(), key);
    super(key.getEncoded(), key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param key the {@link #getKey() key}.
   */
  public SecurityPublicKeyEcJce(byte[] data, ECPublicKey key) {

    super(data, key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param keySupplier the {@link Supplier} for the {@link #getKey() key}.
   */
  public SecurityPublicKeyEcJce(byte[] data, Supplier<ECPublicKey> keySupplier) {

    super(data, keySupplier);
  }

}
