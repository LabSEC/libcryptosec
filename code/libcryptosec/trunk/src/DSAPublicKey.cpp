#include <libcryptosec/DSAPublicKey.h>

DSAPublicKey::DSAPublicKey(EVP_PKEY *key)
		throw (AsymmetricKeyException) : PublicKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::DSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAPublicKey::DSAPublicKey");
	}
}

DSAPublicKey::DSAPublicKey(ByteArray &derEncoded)
		throw (EncodeException, AsymmetricKeyException) : PublicKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm;
	algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::DSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAPublicKey::DSAPublicKey");
	}
}

DSAPublicKey::DSAPublicKey(std::string &pemEncoded)
		throw (EncodeException, AsymmetricKeyException) : PublicKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm;
	algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::DSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "DSAPublicKey::DSAPublicKey");
	}
}

DSAPublicKey::~DSAPublicKey()
{
}
