package net.sf.mmm.security.api.key.symmetric;

import net.sf.mmm.security.api.AbstractSecurityFactory;
import net.sf.mmm.security.api.key.SecurityKeyFactory;

/**
 * Interface for a {@link AbstractSecurityFactory factory} to {@link #newKeyCreator() create} instances of
 * {@link SecuritySymmetricKeyCreator} for symmetric cryptographic keys.<br>
 * An instance of {@link SecuritySymmetricKeyFactory} therefore represents a configuration with specific
 * {@link java.security.Key} {@link java.security.Key#getAlgorithm() algorithm} and {@link java.security.Key#getFormat()
 * format}(s).
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecuritySymmetricKeyFactory extends SecurityKeyFactory, SecuritySymmetricKeyConstants {

  /** {@link #getType() Type} of this factory. */
  String TYPE = "SymmetricKeyFactory";

  @Override
  SecuritySymmetricKeyCreator newKeyCreator();

  @Override
  default String getType() {

    return TYPE;
  }

}
