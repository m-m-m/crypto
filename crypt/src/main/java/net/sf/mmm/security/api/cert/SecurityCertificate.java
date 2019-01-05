package net.sf.mmm.security.api.cert;

import java.security.cert.Certificate;

import net.sf.mmm.util.datatype.api.Binary;

/**
 * Interface for a {@link Certificate}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityCertificate extends Binary {

  /**
   * @return the wrapped {@link Certificate}. It may be lazily parsed on the first call of this method.
   */
  Certificate getCertificate();

}
