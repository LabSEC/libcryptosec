#include <libcryptosec/NetscapeSPKIBuilder.h>

NetscapeSPKIBuilder::NetscapeSPKIBuilder()
{
	this->netscapeSPKI = NETSCAPE_SPKI_new();
}

NetscapeSPKIBuilder::NetscapeSPKIBuilder(std::string netscapeSPKIBase64) throw (EncodeException)
{
	this->netscapeSPKI = NETSCAPE_SPKI_b64_decode(netscapeSPKIBase64.c_str(), netscapeSPKIBase64.size());
	if (!this->netscapeSPKI)
	{
		throw EncodeException(EncodeException::BASE64_DECODE, "NetscapeSPKIBuilder::NetscapeSPKIBuilder");
	}
}

NetscapeSPKIBuilder::~NetscapeSPKIBuilder()
{
	if (this->netscapeSPKI)
	{
		NETSCAPE_SPKI_free(this->netscapeSPKI);
		this->netscapeSPKI = NULL;
	}
}

std::string NetscapeSPKIBuilder::getBase64Encoded() throw (EncodeException)
{
	char *base64Encoded;
	std::string ret;
	base64Encoded = NETSCAPE_SPKI_b64_encode(this->netscapeSPKI);
	if (!base64Encoded)
	{
		throw EncodeException(EncodeException::BASE64_ENCODE, "NetscapeSPKIBuilder::getBase64Encoded");
	}
	ret = base64Encoded;
	free(base64Encoded);
	return ret;
}

void NetscapeSPKIBuilder::setPublicKey(PublicKey &publicKey)
{
	NETSCAPE_SPKI_set_pubkey(this->netscapeSPKI, publicKey.getEvpPkey());
}

PublicKey* NetscapeSPKIBuilder::getPublicKey()
			throw (AsymmetricKeyException, NetscapeSPKIException)
{
	EVP_PKEY *pubKey;
	PublicKey *ret;
	pubKey = NETSCAPE_SPKI_get_pubkey(this->netscapeSPKI);
	if (!pubKey)
	{
		throw NetscapeSPKIException(NetscapeSPKIException::SET_NO_VALUE, "NetscapeSPKIBuilder::getPublicKey");
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

void NetscapeSPKIBuilder::setChallenge(std::string challenge)
{
	ASN1_IA5STRING_free(this->netscapeSPKI->spkac->challenge);
	this->netscapeSPKI->spkac->challenge = ASN1_IA5STRING_new();
	ASN1_STRING_set(this->netscapeSPKI->spkac->challenge, challenge.c_str(), challenge.size());
}

std::string NetscapeSPKIBuilder::getChallenge()
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

NetscapeSPKI* NetscapeSPKIBuilder::sign(PrivateKey &privateKey, MessageDigest::Algorithm messageDigest)
		throw (NetscapeSPKIException)
{
	int rc;
	NetscapeSPKI *ret;

        // TODO: We force Identity message digest for EdDSA to avoid changing callers which always pass digests.
        EVP_PKEY* pkey = privateKey.getEvpPkey();
        int pkeyType = EVP_PKEY_type(pkey->type);
        int nid25519 = OBJ_sn2nid("ED25519");
        int nid521 = OBJ_sn2nid("ED521");
        int nid448 = OBJ_sn2nid("ED448");
        if (pkeyType == nid25519 || pkeyType == nid521 || pkeyType == nid448) {
		messageDigest = MessageDigest::Identity;
        }

	rc = NETSCAPE_SPKI_sign(this->netscapeSPKI, privateKey.getEvpPkey(), MessageDigest::getMessageDigest(messageDigest));
	if (!rc)
	{
		throw NetscapeSPKIException(NetscapeSPKIException::SIGNING_SPKI, "NetscapeSPKIBuilder::sign");
	}
	ret = new NetscapeSPKI(this->netscapeSPKI);
	this->netscapeSPKI = NETSCAPE_SPKI_new();
	return ret;
}
