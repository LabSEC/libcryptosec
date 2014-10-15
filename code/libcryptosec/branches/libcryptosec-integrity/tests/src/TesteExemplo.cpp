#include <libcryptosec/ByteArray.h>
#include "gtest.h"

TEST(ByteArray, TesteErrado) {
  EXPECT_EQ("teste1", ByteArray("teste").toString());
}

TEST(ByteArray, TesteCorreto) {
  EXPECT_EQ("teste", ByteArray("teste").toString());
}
