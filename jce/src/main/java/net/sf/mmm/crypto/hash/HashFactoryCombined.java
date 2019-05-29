package net.sf.mmm.crypto.hash;

/**
 * The implementation of {@link HashFactory} that combines multiple {@link HashFactory} instances by
 * sequentially applying the hashes.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class HashFactoryCombined implements HashFactory {

  private final HashFactory[] factories;

  /**
   * The constructor.
   *
   * @param factories the {@link HashFactory} instances to combine.
   */
  public HashFactoryCombined(HashFactory[] factories) {

    super();
    this.factories = factories;
  }

  @Override
  public HashCreator newHashCreator() {

    HashCreator[] generators = new HashCreator[this.factories.length];
    for (int i = 0; i < this.factories.length; i++) {
      generators[i] = this.factories[i].newHashCreator();
    }
    return new HashCreatorImplCombined(generators);
  }

  @Override
  public String toString() {

    StringBuilder buffer = new StringBuilder();
    for (HashFactory factory : this.factories) {
      if (buffer.length() > 0) {
        buffer.append('+');
      }
      buffer.append(factory);
    }
    return buffer.toString();
  }

}
