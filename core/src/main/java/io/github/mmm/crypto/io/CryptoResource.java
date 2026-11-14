package io.github.mmm.crypto.io;

import java.io.InputStream;
import java.io.OutputStream;

/// Interface for a resource such as a [java.io.File].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface CryptoResource {

  /// @return the URI of this resource.
  String getUri();

  /// @return `true` if this resource already exists, `false` otherwise.
  boolean exists();

  /// @return a new [InputStream] to read this resource.
  /// @throws IllegalStateException if this resource does not [exist][#exists()].
  InputStream openInputStream();

  /// @return a new [OutputStream] to write to this resource. If the resource already [exists][#exists()] the
  ///         data written to the [OutputStream] will overwrite all existing data. Otherwise (if not yet
  ///         [exists][#exists()]) it will be created.
  OutputStream openOutputStream();

}
