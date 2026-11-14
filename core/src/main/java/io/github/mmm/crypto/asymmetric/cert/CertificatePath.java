package io.github.mmm.crypto.asymmetric.cert;

import java.security.cert.Certificate;
import java.util.List;

/// Interface for a [path][java.security.cert.CertPath] (also called chain) of
/// [java.security.cert.Certificate]s.
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface CertificatePath {

  /// @return an [immutable][java.util.Collections#unmodifiableList(List)] [List] of `Certificate`s.
  List<Certificate> getCertificates();
}
