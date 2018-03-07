package net.sf.mmm.security.api.io;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Interface for a resource such as a {@link java.io.File}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityDataResource {

  /**
   * @return the URI of this resource.
   */
  String getUri();

  /**
   * @return {@code true} if this resource already exists, {@code false} otherwise.
   */
  boolean exists();

  /**
   * @return a new {@link InputStream} to read this resource.
   * @throws IllegalStateException if this resource does not {@link #exists() exist}.
   */
  InputStream openInputStream();

  /**
   * @return a new {@link OutputStream} to write to this resource. If the resource already {@link #exists() exists} the
   *         data written to the {@link OutputStream} will overwrite all existing data. Otherwise (if not yet
   *         {@link #exists() exists}) it will be created.
   */
  OutputStream openOutputStream();

}
