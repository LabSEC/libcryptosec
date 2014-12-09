#include <libcryptosec/NamedECDSAKeyPair.h>

NamedECDSAKeyPair::NamedECDSAKeyPair(AsymmetricKey::Curve curve, bool named)
		throw (AsymmetricKeyException) {
	EC_KEY *eckey;
	this->key = NULL;
	this->engine = NULL;
	eckey = NULL;
	eckey = EC_KEY_new_by_curve_name(curve);
	if (named)
		EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
	EC_KEY_generate_key(eckey);
	if (!eckey) {
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"NamedECDSAKeyPair::NamedECDSAKeyPair");
	}
	this->key = EVP_PKEY_new();
	EVP_PKEY_assign_EC_KEY(this->key, eckey);
	if (!this->key) {
		throw AsymmetricKeyException(AsymmetricKeyException::INTERNAL_ERROR,
				"NamedECDSAKeyPair::NamedECDSAKeyPair");
	}
}

NamedECDSAKeyPair::~NamedECDSAKeyPair() {
	if (this->key) {
		EVP_PKEY_free(this->key);
		this->key = NULL;
	}
	if (this->engine) {
		ENGINE_free(this->engine);
		this->engine = NULL;
	}
}

PublicKey* NamedECDSAKeyPair::getPublicKey() throw (AsymmetricKeyException,
		EncodeException) {
	PublicKey *ret;
	std::string keyTemp;
	keyTemp = this->getPublicKeyPemEncoded();
	ret = new ECDSAPublicKey(keyTemp);
	return ret;
}

PrivateKey* NamedECDSAKeyPair::getPrivateKey() throw (AsymmetricKeyException) {
	PrivateKey *ret;
	EVP_PKEY *pkey;
	ret = NULL;
	if (engine) {
		pkey = ENGINE_load_private_key(this->engine, this->keyId.c_str(), NULL,
				NULL);
		if (!pkey) {
			throw AsymmetricKeyException(
					AsymmetricKeyException::UNAVAILABLE_KEY,
					"KeyId: " + this->keyId, "NamedECDSAKeyPair::getPrivateKey");
		}
		try {
			ret = new PrivateKey(pkey);
		} catch (...) {
			EVP_PKEY_free(pkey);
			throw;
		}
	} else {
		ret = new ECDSAPrivateKey(this->key);
		if (ret == NULL) {
			throw AsymmetricKeyException(AsymmetricKeyException::INVALID_TYPE,
					"NamedECDSAKeyPair::getPrivateKey");
		}
		CRYPTO_add(&this->key->references, 1, CRYPTO_LOCK_EVP_PKEY);
	}
	return ret;
}

AsymmetricKey::Algorithm NamedECDSAKeyPair::getAlgorithm()
		throw (AsymmetricKeyException) {
	return AsymmetricKey::NAMED_ECDSA;
}


