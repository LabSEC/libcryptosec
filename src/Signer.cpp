#include <libcryptosec/Signer.h>

ByteArray Signer::sign(PrivateKey &key, ByteArray &hash, MessageDigest::Algorithm algorithm)
		throw (SignerException)
{
	ByteArray ret;
	int rc, hashAlgorithmId;
	unsigned int signedSize, keySize;
	AsymmetricKey::Algorithm alg;
	const EVP_MD *hashAlgorithm;
	hashAlgorithm = MessageDigest::getMessageDigest(algorithm);
	hashAlgorithmId = EVP_MD_nid(hashAlgorithm);
	alg = key.getAlgorithm();
	keySize = key.getSize();
	ret = ByteArray(keySize);
	switch (alg)
	{
		case AsymmetricKey::RSA:
			rc = RSA_sign(hashAlgorithmId, hash.getDataPointer(), hash.size(), ret.getDataPointer(), &signedSize, (key.getEvpPkey())->pkey.rsa);
			break;
		case AsymmetricKey::DSA:
			rc = DSA_sign(hashAlgorithmId, hash.getDataPointer(), hash.size(), ret.getDataPointer(), &signedSize, (key.getEvpPkey())->pkey.dsa);
			break;
		case AsymmetricKey::ECDSA:
			rc = ECDSA_sign(hashAlgorithmId, hash.getDataPointer(), hash.size(), ret.getDataPointer(), &signedSize, (key.getEvpPkey())->pkey.ec);
			break;
		case AsymmetricKey::EdDSA:
			// TODO: add support?
			throw SignerException(SignerException::UNSUPPORTED_ASYMMETRIC_KEY_TYPE, "Signer::sign");
			break;
		default:
			throw SignerException(SignerException::UNSUPPORTED_ASYMMETRIC_KEY_TYPE, "Signer::sign");
	}
	//Uma assinatura DSA pode ser menor que o tamanho da chave
	if (rc == 0 || ((alg == AsymmetricKey::RSA) && (signedSize != keySize)))
	{
		throw SignerException(SignerException::SIGNING_DATA, "Signer::sign");
	}
	return ret;
}

bool Signer::verify(PublicKey &key, ByteArray &signature, ByteArray &hash, MessageDigest::Algorithm algorithm)
		throw (SignerException)
{
	int rc, hashAlgorithmId;
	AsymmetricKey::Algorithm alg;
	const EVP_MD *hashAlgorithm;
	hashAlgorithm = MessageDigest::getMessageDigest(algorithm);
	hashAlgorithmId = EVP_MD_nid(hashAlgorithm);
	alg = key.getAlgorithm();
	switch (alg)
	{
		case AsymmetricKey::RSA:
			rc = RSA_verify(hashAlgorithmId, hash.getDataPointer(), hash.size(), signature.getDataPointer(), signature.size(), (key.getEvpPkey())->pkey.rsa);
			break;
		case AsymmetricKey::DSA:
			rc = DSA_verify(hashAlgorithmId, hash.getDataPointer(), hash.size(), signature.getDataPointer(), signature.size(), (key.getEvpPkey())->pkey.dsa);
			break;
		case AsymmetricKey::ECDSA:
			rc = ECDSA_verify(hashAlgorithmId, hash.getDataPointer(), hash.size(), signature.getDataPointer(), signature.size(), (key.getEvpPkey())->pkey.ec);
			break;
		case AsymmetricKey::EdDSA:
			// TODO: add support
			throw SignerException(SignerException::UNSUPPORTED_ASYMMETRIC_KEY_TYPE, "Signer::verify");
			break;
		default:
			throw SignerException(SignerException::UNSUPPORTED_ASYMMETRIC_KEY_TYPE, "Signer::verify");
	}
	if (rc < 0)
	{
		throw SignerException(SignerException::VERIFYING_DATA, "Signer::verify");
	}
	return (rc)?true:false;
}
