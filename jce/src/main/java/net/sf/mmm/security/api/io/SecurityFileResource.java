package net.sf.mmm.security.api.io;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;

/**
 * Implementation of {@link SecurityDataResource} for a {@link File}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityFileResource implements SecurityDataResource {

  private final File file;

  /**
   * The constructor.
   *
   * @param file the {@link File} pointing to the data resource.
   */
  public SecurityFileResource(File file) {

    super();
    this.file = file;
    verifyNotDirectory();
  }

  /**
   * @return the wrapped {@link File}.
   */
  public File getFile() {

    return this.file;
  }

  @Override
  public boolean exists() {

    return this.file.exists() && !this.file.isDirectory();
  }

  private void ensureExists() {

    if (!this.file.exists()) {
      try {
        this.file.getParentFile().mkdirs();
        Files.createFile(this.file.toPath());
      } catch (Exception e) {
        throw new IllegalStateException("File " + this.file.getPath() + " could not be created!", e);
      }
    }
    verifyNotDirectory();
  }

  private void verifyNotDirectory() {

    if (this.file.isDirectory()) {
      throw new IllegalStateException("Resource is a directory: " + this.file.getPath());
    }
  }

  @Override
  public String getUri() {

    return this.file.toString();
  }

  @Override
  public InputStream openInputStream() {

    try {
      return new FileInputStream(this.file);
    } catch (FileNotFoundException e) {
      throw new IllegalStateException("File " + this.file.getPath() + " does not exist!", e);
    }
  }

  @Override
  public OutputStream openOutputStream() {

    ensureExists();
    try {
      return new FileOutputStream(this.file);
    } catch (FileNotFoundException e) {
      throw new IllegalStateException("File " + this.file.getPath() + " does not exist!", e);
    }
  }

}
