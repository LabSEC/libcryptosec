#include <libcryptosec/ECDSAPublicKey.h>

ECDSAPublicKey::ECDSAPublicKey(EVP_PKEY *key)
		throw (AsymmetricKeyException) : PublicKey(key)
{
	AsymmetricKey::Algorithm algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::ECDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPublicKey::ECDSAPublicKey");
	}
}

ECDSAPublicKey::ECDSAPublicKey(ByteArray &derEncoded)
		throw (EncodeException, AsymmetricKeyException) : PublicKey(derEncoded)
{
	AsymmetricKey::Algorithm algorithm;
	algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::ECDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPublicKey::ECDSAPublicKey");
	}
}

ECDSAPublicKey::ECDSAPublicKey(std::string &pemEncoded)
		throw (EncodeException, AsymmetricKeyException) : PublicKey(pemEncoded)
{
	AsymmetricKey::Algorithm algorithm;
	algorithm = this->getAlgorithm();
	if (algorithm != AsymmetricKey::ECDSA)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "ECDSAPublicKey::ECDSAPublicKey");
	}
}

ECDSAPublicKey::~ECDSAPublicKey()
{
}
