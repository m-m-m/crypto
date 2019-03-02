package net.sf.mmm.security.api.key.asymmetric.ec.bc;

import java.util.function.Supplier;

import net.sf.mmm.security.api.key.asymmetric.AbstractSecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;

import org.bouncycastle.jce.interfaces.ECPrivateKey;

/**
 * Implementation of {@link SecurityPublicKey} for {@link ECPrivateKey}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityPrivateKeyEcBc extends AbstractSecurityPrivateKey<ECPrivateKey> {

  /**
   * The constructor.
   *
   * @param key the {@link #getKey() key}.
   */
  public SecurityPrivateKeyEcBc(ECPrivateKey key) {

    super(key.getD().toByteArray(), key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param key the {@link #getKey() key}.
   */
  public SecurityPrivateKeyEcBc(byte[] data, ECPrivateKey key) {

    super(data, key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param keySupplier the {@link Supplier} for the {@link #getKey() key}.
   */
  public SecurityPrivateKeyEcBc(byte[] data, Supplier<ECPrivateKey> keySupplier) {

    super(data, keySupplier);
  }

}
