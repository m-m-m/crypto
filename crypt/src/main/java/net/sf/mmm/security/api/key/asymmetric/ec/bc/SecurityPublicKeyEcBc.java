package net.sf.mmm.security.api.key.asymmetric.ec.bc;

import java.util.function.Supplier;

import net.sf.mmm.security.api.key.asymmetric.AbstractSecurityPublicKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;

import org.bouncycastle.jce.interfaces.ECPublicKey;

/**
 * Implementation of {@link SecurityPublicKey} for {@link ECPublicKey}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityPublicKeyEcBc extends AbstractSecurityPublicKey<ECPublicKey> {

  /**
   * The constructor.
   *
   * @param key the {@link #getKey() key}.
   */
  public SecurityPublicKeyEcBc(ECPublicKey key) {

    super(key.getQ().getEncoded(true), key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param key the {@link #getKey() key}.
   */
  public SecurityPublicKeyEcBc(byte[] data, ECPublicKey key) {

    super(data, key);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   * @param keySupplier the {@link Supplier} for the {@link #getKey() key}.
   */
  public SecurityPublicKeyEcBc(byte[] data, Supplier<ECPublicKey> keySupplier) {

    super(data, keySupplier);
  }

}
