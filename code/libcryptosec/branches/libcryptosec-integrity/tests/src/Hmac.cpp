#include <libcryptosec/Hmac.h>
#include "gtest.h"
#include <vector.h>


TEST(GeracaoHmac, Sha256) {
	Hmac hmac;
	ByteArray b = ByteArray("senha");
	hmac.init(b, MessageDigest::SHA256);


  EXPECT_EQ("1616DF6E386C2660916BE7A4370951276B5229F26249C2D758643C58E6E6576E", hmac.doFinal("testeLABSEC").toHex());
}

TEST(GeracaoHmac, Sha1) {
	Hmac hmac;
	ByteArray b = ByteArray("senha");
	hmac.init(b, MessageDigest::SHA1);


  EXPECT_EQ("7211244CBA131C2DF0483EBF695FC705B1FCE084", hmac.doFinal("testeLABSEC").toHex());
}

TEST(GeracaoHmac, MD5) {
	Hmac hmac;
	ByteArray b = ByteArray("senha");
	hmac.init(b, MessageDigest::MD5);


  EXPECT_EQ("5D7F177BCA3E523BC711BFEFB65C9A1E", hmac.doFinal("testeLABSEC").toHex());
}

TEST(GeracaoHmac, Vector) {
	std::vector<ByteArray> myvector;
	Hmac hmac;
	myvector.push_back(ByteArray("testeLABSEC"));
	myvector.push_back(ByteArray("testeLABSEC2"));
	ByteArray b("senha");
	hmac.init(b, MessageDigest::SHA256);
	hmac.update(myvector);
	EXPECT_EQ("6684102EEF0D13117BAD70ED4F453427CE83B09E6CC77D92FD96BA655662E70E", hmac.doFinal().toHex());
}

TEST(HmacVazio, ByteArrayVazio) {
	Hmac hmac;
	ByteArray b;
	b.setDataPointer(0, 0);
	hmac.init(b, MessageDigest::SHA256);

  EXPECT_NO_THROW({ hmac.doFinal("testeLABSEC");});
}

TEST(HmacVazio, ValorVazio) {
	Hmac hmac;
	ByteArray b = ByteArray("senha");
	hmac.init(b, MessageDigest::SHA256);

  EXPECT_EQ("21B6D3C999CA4FFE07EA590B8C60932FEB576329B556957E1061DA9B0FF889AC", hmac.doFinal("").toHex());
}

TEST(GeracaoHmacInconsistente, NoInitDoFinal) {
	Hmac hmac;
	ByteArray b = ByteArray("senha");

  EXPECT_THROW(hmac.doFinal(""), InvalidStateException);
}

TEST(GeracaoHmacInconsistente, NoInitUpdate) {
	Hmac hmac;
	ByteArray b = ByteArray("senha");

  EXPECT_THROW(hmac.update(""), InvalidStateException);
}

TEST(GeracaoHmacInconsistente, DuploDoFinal) {
	Hmac hmac;
	ByteArray b = ByteArray("senha");
	hmac.init(b, MessageDigest::SHA256);
	hmac.doFinal("");
  EXPECT_THROW(hmac.doFinal(""), InvalidStateException);
}

TEST(GeracaoHmacInconsistente, DuploInit) {
	Hmac hmac;
	ByteArray b = ByteArray("senha");
	hmac.init(b, MessageDigest::SHA1);
	hmac.init(b, MessageDigest::SHA256);

	EXPECT_EQ("1616DF6E386C2660916BE7A4370951276B5229F26249C2D758643C58E6E6576E", hmac.doFinal("testeLABSEC").toHex());
}



/*TEST(Hmac, EngineVazia) {
	Hmac hmac;
	ByteArray b = ByteArray("senha");
	hmac.init(b, MessageDigest::SHA256, NULL);

	EXPECT_EQ("1616DF6E386C2660916BE7A4370951276B5229F26249C2D758643C58E6E6576E", hmac.doFinal("testeLABSEC").toHex());
}*/
