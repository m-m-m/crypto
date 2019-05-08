package net.sf.mmm.security.api.hash;

/**
 * The implementation of {@link SecurityHashFactory} that combines multiple {@link SecurityHashFactory} instances by
 * sequentially applying the hashes.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityHashFactoryCombined implements SecurityHashFactory {

  private final SecurityHashFactory[] factories;

  /**
   * The constructor.
   *
   * @param factories the {@link SecurityHashFactory} instances to combine.
   */
  public SecurityHashFactoryCombined(SecurityHashFactory[] factories) {

    super();
    this.factories = factories;
  }

  @Override
  public SecurityHashCreator newHashCreator() {

    SecurityHashCreator[] generators = new SecurityHashCreator[this.factories.length];
    for (int i = 0; i < this.factories.length; i++) {
      generators[i] = this.factories[i].newHashCreator();
    }
    return new SecurityHashCreatorImplCombine(generators);
  }

  @Override
  public String toString() {

    StringBuilder buffer = new StringBuilder();
    for (SecurityHashFactory factory : this.factories) {
      if (buffer.length() > 0) {
        buffer.append('+');
      }
      buffer.append(factory);
    }
    return buffer.toString();
  }

}
