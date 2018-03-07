package net.sf.mmm.security.api.cert;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Generic implementation of {@link SecurityCertificatePath}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityCertificatePathGeneric implements SecurityCertificatePath {

  private final List<SecurityCertificate> certificates;

  /**
   * The constructor.
   *
   * @param certificates the {@link #getCertificates() certificates}.
   */
  public SecurityCertificatePathGeneric(Collection<SecurityCertificate> certificates) {
    super();
    List<SecurityCertificate> certificateList;
    if (certificates instanceof List) {
      certificateList = (List<SecurityCertificate>) certificates;
    } else {
      certificateList = new ArrayList<>(certificates);
    }
    this.certificates = Collections.unmodifiableList(certificateList);
  }

  /**
   * The constructor.
   *
   * @param certificates the {@link #getCertificates() certificates}.
   */
  public SecurityCertificatePathGeneric(SecurityCertificate... certificates) {
    super();
    this.certificates = Collections.unmodifiableList(Arrays.asList(certificates));
  }

  @Override
  public List<SecurityCertificate> getCertificates() {

    return this.certificates;
  }

}
