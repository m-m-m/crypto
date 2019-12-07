/*
 * Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/**
 * Provides fundamental APIs and helper classes.
 */
module io.github.mmm.crypto.bc {

  requires transitive io.github.mmm.crypto;

  requires transitive org.bouncycastle.provider;

  requires org.bouncycastle.pkix;

  exports io.github.mmm.crypto.asymmetric.access.ec.bc;

  exports io.github.mmm.crypto.asymmetric.key.ec.bc;

  exports io.github.mmm.crypto.asymmetric.sign.ec.bc;

  exports io.github.mmm.crypto.hash.ripemd;

}
