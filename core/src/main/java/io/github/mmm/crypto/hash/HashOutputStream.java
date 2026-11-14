package io.github.mmm.crypto.hash;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;

import io.github.mmm.crypto.io.OutputStreamWrapper;

/// An [OutputStream] that writes to a [MessageDigest]. Unlike [java.security.DigestOutputStream] it
/// does not wrap an [OutputStream] to write through.
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class HashOutputStream extends OutputStreamWrapper {

  private final HashCreator hashGenerator;

  /// The constructor.
  ///
  /// @param hashGenerator the [HashCreator].
  public HashOutputStream(HashCreator hashGenerator) {
    this(hashGenerator, null);
  }

  /// The constructor.
  ///
  /// @param hashGenerator the [HashCreator].
  /// @param delegate the [delegate][#getDelegate()]. May be `null`.
  public HashOutputStream(HashCreator hashGenerator, OutputStream delegate) {

    super(delegate);
    this.hashGenerator = hashGenerator;
  }

  @Override
  public void write(byte[] b, int off, int len) throws IOException {

    super.write(b, off, len);
    this.hashGenerator.update(b, off, len);
  }

  @Override
  public void write(int b) throws IOException {

    super.write(b);
    this.hashGenerator.update(new byte[] { (byte) b });
  }

}
