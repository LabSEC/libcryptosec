#include <libcryptosec/RSAPublicKey.h>

RSAPublicKey::RSAPublicKey(EVP_PKEY *key)
		throw (AsymmetricKeyException) : PublicKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPublicKey::RSAPublicKey");
	}
}

RSAPublicKey::RSAPublicKey(ByteArray &derEncoded)
		throw (EncodeException, AsymmetricKeyException) : PublicKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPublicKey::RSAPublicKey");
	}
}

RSAPublicKey::RSAPublicKey(std::string &pemEncoded)
		throw (EncodeException, AsymmetricKeyException)	 : PublicKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm;
	algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::RSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "RSAPublicKey::RSAPublicKey");
	}
}

RSAPublicKey::~RSAPublicKey()
{
}
