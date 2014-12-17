#include <libcryptosec/SmartcardSlot.h>

SmartcardSlot::SmartcardSlot(PKCS11_SLOT *slot)
{
	this->slot = slot;
}

SmartcardSlot::~SmartcardSlot()
{
}

std::string SmartcardSlot::getSerial()
{
	std::string ret;
	ret = this->slot[0].token->serialnr;
	return ret;
}

std::string SmartcardSlot::getLabel()
{
	std::string ret;
	ret = this->slot[0].token->label;
	return ret;
}

std::vector<SmartcardCertificate *> SmartcardSlot::getCertificates()
		throw (SmartcardModuleException)
{
	PKCS11_CERT *certs;
	unsigned int i, j, ncerts;
	char *bufferId;
	std::string id, label, serial;
	int rc, k, emptySlots;
	std::vector<SmartcardCertificate *> ret;
	std::vector<SmartcardCertificate *>::iterator iter;
	emptySlots = 0;
	SmartcardCertificate *cert;

	rc = PKCS11_enumerate_certs(this->slot[0].token, &certs, &ncerts);
	if (rc < 0){
		for (iter=ret.begin();iter!=ret.end();iter++)
		{
			ret.erase(iter);
			delete *iter;
		}
		throw SmartcardModuleException(SmartcardModuleException::ENUMERATING_CERTIFICATES, "SmartcardSlot::getCertificates", true);
	}
	for (j=0;j<ncerts;j++)
	{
		bufferId = (char *)calloc((certs[j].id_len * 2) + 1, sizeof(char));
		for (k=0;k<certs[j].id_len;k++)
		{
			sprintf(&(bufferId[k*2]), "%02X", certs[i].id[k]);
		}
		id.append(bufferId);
		free(bufferId);
		label = certs[j].label;
		serial = this->slot[0].token->serialnr;
		cert = new SmartcardCertificate(id, label, serial, X509_dup(certs[j].x509));
		ret.push_back(cert);
	}
	return ret;
}

ByteArray SmartcardSlot::decrypt(std::string &keyId, std::string &pin, ByteArray &data)
		throw (SmartcardModuleException)
{
	int rc, found = 0, nret, keySize, j, errorCode;
	PKCS11_KEY *keys;
	ByteArray ret;
    unsigned int nKeys, i;
    std::string idTmp;
    char *bufferId;
    ERR_clear_error();
    if (pin.size() < 4 || pin.size() > 8)
    {
    	throw SmartcardModuleException(SmartcardModuleException::INVALID_PIN, "SmartcardSlot::decrypt", true);
    }
	rc = PKCS11_login(this->slot, 0, pin.c_str());
	if (rc != 0)
    {
    	errorCode = ERR_GET_REASON(ERR_get_error());
    	if (errorCode == SmartcardModuleException::BLOCKED_PIN)
    	{
    		throw SmartcardModuleException(SmartcardModuleException::BLOCKED_PIN, "SmartcardSlot::decrypt", true);
    	}
    	else if (errorCode == SmartcardModuleException::INVALID_PIN)
    	{
    		throw SmartcardModuleException(SmartcardModuleException::INVALID_PIN, "SmartcardSlot::decrypt", true);
    	}
    	else
    	{
    		throw SmartcardModuleException(SmartcardModuleException::UNKNOWN, "SmartcardSlot::decrypt", true);
    	}
    }
	rc = PKCS11_enumerate_keys(this->slot[0].token, &keys, &nKeys);
	if (rc != 0 || nKeys == 0)
	{
		PKCS11_logout(this->slot);
		throw SmartcardModuleException(SmartcardModuleException::ENUMERATING_PRIVATE_KEYS, "SmartcardSlot::decrypt", true);
	}
	found = -1;
	for (i=0;(i<nKeys)&&(found==-1);i++)
	{
		bufferId = (char *)calloc((keys[i].id_len * 2) + 1, sizeof(char));
		for (j=0;j<keys[i].id_len;j++)
		{
			sprintf(&(bufferId[j*2]), "%02X", keys[i].id[j]);
		}
		idTmp = bufferId;
		free(bufferId);
        if (keyId == idTmp)
        {
            found = i;
            keySize = PKCS11_get_key_size(&keys[i]);
        }
    }
	if (found < 0)
	{
		PKCS11_logout(this->slot);
		//TODO: apagar todas as chaves encontradas, não tem na libp11
		throw SmartcardModuleException(SmartcardModuleException::ID_NOT_FOUND, "SmartcardSlot::decrypt", true);
	}
	ret = ByteArray(keySize);
    nret = PKCS11_private_decrypt(data.size(), data.getDataPointer(), ret.getDataPointer(), &keys[found], RSA_PKCS1_PADDING);
    PKCS11_logout(this->slot);
    if (nret <= 0)
    {
		throw SmartcardModuleException(SmartcardModuleException::DECRYPTING_DATA, "SmartcardSlot::decrypt", true);
    }
    ret = ByteArray(ret.getDataPointer(), nret);
    return ret;
}
