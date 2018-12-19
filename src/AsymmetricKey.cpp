#include <libcryptosec/AsymmetricKey.h>

AsymmetricKey::AsymmetricKey(EVP_PKEY *key)
		throw (AsymmetricKeyException)
{
}

AsymmetricKey::~AsymmetricKey()
{
	EVP_PKEY_free(key);
}

AsymmetricKey::Algorithm AsymmetricKey::getAlgorithm()
		throw (AsymmetricKeyException)
{
	int nid25519 = OBJ_sn2nid("ED25519");
	int nid448 = OBJ_sn2nid("ED448");
	int nid521 = OBJ_sn2nid("ED521");
	int pkeyType = 0;

	AsymmetricKey::Algorithm type;
	pkeyType = EVP_PKEY_type(this->key->type);
	switch (pkeyType)
	{
		case EVP_PKEY_RSA: /* TODO: confirmar porque tem estes dois tipos */
		case EVP_PKEY_RSA2:
			type = AsymmetricKey::RSA;
			break;
		case EVP_PKEY_DSA: /* TODO: confirmar porque tem estes quatro tipos. São mesmo diferentes ??? */
		case EVP_PKEY_DSA1:
		case EVP_PKEY_DSA2:
		case EVP_PKEY_DSA3:
		case EVP_PKEY_DSA4:
			type = AsymmetricKey::DSA;
			break;
		case EVP_PKEY_EC:
			type = AsymmetricKey::ECDSA;
			break;
//		case EVP_PKEY_DH:
//			type = AsymmetricKey::DH;
//			break;
//		case EVP_PKEY_EC:
//			type = AsymmetricKey::EC;
//			break;
		default:
			if (pkeyType != 0 && (pkeyType == nid25519 || pkeyType == nid448 || pkeyType == nid521)) {
				type = AsymmetricKey::EdDSA;
				break;
			}
			throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "There is no support for this type: " + std::string(OBJ_nid2sn(this->key->type)), "AsymmetricKey::getAlgorithm");
	}
	return type;
}

int AsymmetricKey::getSize() throw (AsymmetricKeyException)
{
	int ret;
	if (this->key == NULL)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::SET_NO_VALUE, "AsymmetricKey::getSize");
	}
	/* TODO: this function will br right only for RSA, DSA and EC. The others algorithms (DH) must be used 
	 * individual functions */
	ret = EVP_PKEY_size(this->key);
	if (ret == 0)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR, "AsymmetricKey::getSize");
	}
	return ret;
}

int AsymmetricKey::getSizeBits() throw (AsymmetricKeyException)
{
	int ret;
	if (this->key == NULL)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::SET_NO_VALUE, "AsymmetricKey::getSizeBits");
	}
	/* TODO: this function will br right only for RSA, DSA and EC. The others algorithms (DH) must be used 
	 * individual functions */
	ret = EVP_PKEY_bits(this->key);
	if (ret == 0)
	{
		throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE, "There is no support for this type: " + std::string(OBJ_nid2sn(this->key->type)), "AsymmetricKey::getSizeBits");
	}
	return ret;
}

EVP_PKEY* AsymmetricKey::getEvpPkey()
{
	return this->key;
}

//void AsymmetricKey::setEvpPkey(EVP_PKEY *key)
//{
//	if (this->key)
//	{
//		EVP_PKEY_free(key);
//	}
//	this->key = key;
//}
