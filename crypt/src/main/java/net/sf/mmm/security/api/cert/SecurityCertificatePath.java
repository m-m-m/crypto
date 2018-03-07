package net.sf.mmm.security.api.cert;

import java.util.List;

/**
 * Interface for a {@link java.security.cert.CertPath path} (also called chain) of
 * {@link java.security.cert.Certificate}s.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityCertificatePath {

  /**
   * @return an {@link java.util.Collections#unmodifiableList(List) immutable} {@code SecurityCertificate}.
   */
  List<SecurityCertificate> getCertificates();
}
