package net.sf.mmm.security.api.asymmetric.sign;

import net.sf.mmm.security.api.SecurityBinaryType;

/**
 * Simple datatype as container for a {@link SecuritySignatureSigner#signAfterUpdate(boolean) signature}. Allows
 * abstraction of actual implementations (such as bouncy-castle) for portability. Further, it is simple and fast to read
 * and store until real semantic parsing and usage is required.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecuritySignature extends SecurityBinaryType {

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   */
  public SecuritySignature(byte[] data) {

    super(data);
  }

}
