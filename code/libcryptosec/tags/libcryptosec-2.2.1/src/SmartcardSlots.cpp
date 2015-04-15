#include <libcryptosec/SmartcardSlots.h>

SmartcardSlots::SmartcardSlots(PKCS11_CTX *ctx, PKCS11_SLOT *scSlots, unsigned int nslots)
{
	this->ctx = ctx;
	this->scSlots = scSlots;
	this->nslots = nslots;
}

SmartcardSlots::~SmartcardSlots()
{
	PKCS11_release_all_slots(this->ctx, this->scSlots, this->nslots);
}

SmartcardSlot* SmartcardSlots::getSmartcardSlot(std::string serial, std::string id)
	throw (SmartcardModuleException)
{
	PKCS11_CERT *certs;
	unsigned int i, j, ncerts;
	char *bufferId;
	std::string idTmp, serialTmp;
	int rc, k;
	unsigned int emptySlots;
	SmartcardSlot *ret;
	emptySlots = 0;

	for (i=0;i<this->nslots;i++)
	{
		if (this->scSlots[i].token)
		{
			serialTmp = this->scSlots[i].token->serialnr;
			if (serialTmp == serial)
			{
				rc = PKCS11_enumerate_certs(this->scSlots[i].token, &certs, &ncerts);
				if (rc < 0){
					throw SmartcardModuleException(SmartcardModuleException::ENUMERATING_CERTIFICATES, "SmartcardSlots::getSmartcardSlot", true);
				}
				for (j=0;j<ncerts;j++)
				{
					idTmp = "";
					bufferId = (char *)calloc((certs[j].id_len * 2) + 1, sizeof(char));
					for (k=0;k<certs[j].id_len;k++)
					{
						sprintf(&(bufferId[k*2]), "%02X", certs[j].id[k]);
					}
					idTmp = (bufferId);
					free(bufferId);
					if (idTmp == id)
					{
						ret = new SmartcardSlot(&this->scSlots[i]);
						return ret;
					}
				}
			}
		}
		else
		{
			emptySlots++;
		}
	}
	if (emptySlots == this->nslots)
	{
		throw SmartcardModuleException(SmartcardModuleException::SMARTCARD_NOT_AVAILABLE, "SmartcardSlots::getSmartcardSlot", true);
	}
	else
	{
		throw SmartcardModuleException(SmartcardModuleException::ID_NOT_FOUND, "SmartcardSlots::getSmartcardSlot", true);
	}
}

std::vector<SmartcardCertificate *> SmartcardSlots::getCertificates()
		throw (SmartcardModuleException)
{
	PKCS11_CERT *certs;
	unsigned int i, j, ncerts;
	char *bufferId;
	std::string id, label, serial;
	int rc, k;
	unsigned int emptySlots;
	std::vector<SmartcardCertificate *> ret;
	std::vector<SmartcardCertificate *>::iterator iter;
	emptySlots = 0;
	SmartcardCertificate *cert;
	for (i=0;i<this->nslots;i++)
	{
		if (this->scSlots[i].token)
		{

//			printf("initialized: %02X\n", this->scSlots[i].token->initialized);
//			printf("loginRequired: %02X\n", this->scSlots[i].token->loginRequired);
//			printf("readOnly: %02X\n", this->scSlots[i].token->readOnly);
//			printf("secureLogin: %02X\n", this->scSlots[i].token->secureLogin);
//			printf("userPinSet: %02X\n", this->scSlots[i].token->userPinSet);

			if (this->scSlots[i].token->loginRequired)
			{
				rc = PKCS11_enumerate_certs(this->scSlots[i].token, &certs, &ncerts);
				if (rc < 0){
					for (iter=ret.begin();iter!=ret.end();iter++)
					{
						ret.erase(iter);
						delete *iter;
					}
					throw SmartcardModuleException(SmartcardModuleException::ENUMERATING_CERTIFICATES, "SmartcardSlots::getCertificates", true);
				}
				for (j=0;j<ncerts;j++)
				{
					if (certs[j].id_len == 1 && !certs[j].id[0])
					{
						/* CA certificate */
					}
					else
					{
						bufferId = (char *)calloc((certs[j].id_len * 2) + 1, sizeof(char));
						for (k=0;k<certs[j].id_len;k++)
						{
							sprintf(&(bufferId[k*2]), "%02X", certs[j].id[k]);
						}
						id = bufferId;
	//					printf("CERTS ACHADOS: %s\n", bufferId);
						free(bufferId);
						label = certs[j].label;
						serial = this->scSlots[i].token->serialnr;
						cert = new SmartcardCertificate(id, label, serial, X509_dup(certs[j].x509));
						ret.push_back(cert);
					}
				}
			}
		}
		else
		{
			emptySlots++;
		}
	}
	if (emptySlots == this->nslots)
	{
		throw SmartcardModuleException(SmartcardModuleException::SMARTCARD_NOT_AVAILABLE, "SmartcardSlots::getCertificates", true);
	}
	return ret;
}

unsigned int SmartcardSlots::getSlotsCount()
{
	return this->nslots;
}
