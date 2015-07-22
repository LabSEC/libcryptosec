#include <libcryptosec/NetscapeSPKI.h>

NetscapeSPKI::NetscapeSPKI(NETSCAPE_SPKI *netscapeSPKI) throw (NetscapeSPKIException)
{
	this->netscapeSPKI = NULL;
	if (!netscapeSPKI)
	{
		throw NetscapeSPKIException(NetscapeSPKIException::INVALID_SPKI, "NetscapeSPKI::NetscapeSPKI");
	}
	this->netscapeSPKI = netscapeSPKI;
}

NetscapeSPKI::NetscapeSPKI(std::string netscapeSPKIBase64) throw (EncodeException)
{
	this->netscapeSPKI = NETSCAPE_SPKI_b64_decode(netscapeSPKIBase64.c_str(), netscapeSPKIBase64.size());
	if (!this->netscapeSPKI)
	{
		throw EncodeException(EncodeException::BASE64_DECODE, "NetscapeSPKI::NetscapeSPKI");
	}
}

NetscapeSPKI::~NetscapeSPKI()
{
	if (this->netscapeSPKI)
	{
		NETSCAPE_SPKI_free(this->netscapeSPKI);
		this->netscapeSPKI = NULL;
	}
}

std::string NetscapeSPKI::getBase64Encoded() throw (EncodeException)
{
	char *base64Encoded;
	std::string ret;
	base64Encoded = NETSCAPE_SPKI_b64_encode(this->netscapeSPKI);
	if (!base64Encoded)
	{
		throw EncodeException(EncodeException::BASE64_ENCODE, "NetscapeSPKI::getBase64Encoded");
	}
	ret = base64Encoded;
	free(base64Encoded);
	return ret;
}

PublicKey* NetscapeSPKI::getPublicKey()
		throw (AsymmetricKeyException, NetscapeSPKIException)
{
	EVP_PKEY *pubKey;
	PublicKey *ret;
	pubKey = NETSCAPE_SPKI_get_pubkey(this->netscapeSPKI);
	if (!pubKey)
	{
		throw NetscapeSPKIException(NetscapeSPKIException::SET_NO_VALUE, "NetscapeSPKIException::getPublicKey");
	}
	try
	{
		ret = new PublicKey(pubKey);
	}
	catch (...)
	{
		EVP_PKEY_free(pubKey);
		throw;
	}
	return ret;
}

std::string NetscapeSPKI::getChallenge()
{
	std::string ret;
	char *data;
	if (this->netscapeSPKI->spkac->challenge->length > 0)
	{
		/* pedir ao jeandré se é feito uma cópia do conteudo ao atribuir direto ao std::string */
		data = (char *)ASN1_STRING_data(this->netscapeSPKI->spkac->challenge);
		ret = data;
	}
	else
	{
		ret = "";
	}
	return ret;
}

bool NetscapeSPKI::verify() throw (AsymmetricKeyException, NetscapeSPKIException)
{
	PublicKey *pubKey;
	int rc;
	pubKey = this->getPublicKey();
	rc = NETSCAPE_SPKI_verify(this->netscapeSPKI, pubKey->getEvpPkey());
	delete pubKey;
	return (rc?true:false);
}

bool NetscapeSPKI::verify(PublicKey &publicKey)
{
	int rc;
	rc = NETSCAPE_SPKI_verify(this->netscapeSPKI, publicKey.getEvpPkey());
	return (rc?true:false);
}

bool NetscapeSPKI::isSigned()
{
	return ASN1_STRING_data(this->netscapeSPKI->signature) != NULL;
}
