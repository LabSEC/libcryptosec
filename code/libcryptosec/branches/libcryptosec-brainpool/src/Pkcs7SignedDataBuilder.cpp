#include <libcryptosec/Pkcs7SignedDataBuilder.h>

Pkcs7SignedDataBuilder::Pkcs7SignedDataBuilder(MessageDigest::Algorithm mesDigAlgorithm,
			Certificate &cert, PrivateKey &privKey, bool attached)
		throw (Pkcs7Exception)
{
	int rc;
	PKCS7_SIGNER_INFO *si;
	PKCS7_set_type(this->pkcs7, NID_pkcs7_signed);
	PKCS7_content_new(this->pkcs7, NID_pkcs7_data);
	if (!attached)
	{
		PKCS7_set_detached(this->pkcs7, 1);
	}
	si = PKCS7_add_signature(this->pkcs7, cert.getX509(), privKey.getEvpPkey(), MessageDigest::getMessageDigest(mesDigAlgorithm));
	if (!si)
	{
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		throw Pkcs7Exception(Pkcs7Exception::ADDING_SIGNER, "Pkcs7SignedDataBuilder::Pkcs7SignedDataBuilder", true);
	}
	rc = PKCS7_add_certificate(this->pkcs7, cert.getX509());
	if (!rc)
	{
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		throw Pkcs7Exception(Pkcs7Exception::ADDING_CERTIFICATE, "Pkcs7SignedDataBuilder::Pkcs7SignedDataBuilder", true);
	}
	this->state = Pkcs7Builder::INIT;
}

Pkcs7SignedDataBuilder::~Pkcs7SignedDataBuilder()
{
}

void Pkcs7SignedDataBuilder::init(MessageDigest::Algorithm mesDigAlgorithm, Certificate &cert,
			PrivateKey &privKey, bool attached)
	throw (Pkcs7Exception)
{
	int rc;
	if (this->state != Pkcs7Builder::NO_INIT)
	{
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		if (this->state == Pkcs7Builder::UPDATE)
		{
			BIO_free(this->p7bio);
			this->p7bio = NULL;
		}
	}
	this->pkcs7 = PKCS7_new();
	PKCS7_set_type(this->pkcs7, NID_pkcs7_signed);
	if (!attached)
	{
		PKCS7_set_detached(this->pkcs7, 1);
	}
	if (!PKCS7_add_signature(this->pkcs7, cert.getX509(), privKey.getEvpPkey(), MessageDigest::getMessageDigest(mesDigAlgorithm)))
	{
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		throw Pkcs7Exception(Pkcs7Exception::ADDING_SIGNER, "Pkcs7SignedDataBuilder::Pkcs7SignedDataBuilder", true);
	}
	rc = PKCS7_add_certificate(this->pkcs7, cert.getX509());
	if (!rc)//inversor adicionado (martin 28/11/07)
	{
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		throw Pkcs7Exception(Pkcs7Exception::ADDING_CERTIFICATE, "Pkcs7SignedDataBuilder::Pkcs7SignedDataBuilder", true);
	}
	this->state = Pkcs7Builder::INIT;
}

void Pkcs7SignedDataBuilder::addSigner(MessageDigest::Algorithm mesDigAlgorithm, Certificate &cert, PrivateKey &privKey)
		throw (Pkcs7Exception, InvalidStateException)
{
	int rc;
	if (this->state != Pkcs7Builder::INIT)
	{
		throw InvalidStateException("Pkcs7SignedDataBuilder::addSigner");
	}
	if (!PKCS7_add_signature(this->pkcs7, cert.getX509(), privKey.getEvpPkey(), MessageDigest::getMessageDigest(mesDigAlgorithm)))
	{
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		throw Pkcs7Exception(Pkcs7Exception::ADDING_SIGNER, "Pkcs7SignedDataBuilder::addSigner", true);
	}
	rc = PKCS7_add_certificate(this->pkcs7, cert.getX509());
	if (!rc)//inversor adicionado (martin 28/11/07)
	{
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		throw Pkcs7Exception(Pkcs7Exception::ADDING_CERTIFICATE, "Pkcs7SignedDataBuilder::addSigner", true);
	}
}

void Pkcs7SignedDataBuilder::addCertificate(Certificate &cert) throw (Pkcs7Exception, InvalidStateException)
{
	int rc;
	if (this->state != Pkcs7Builder::INIT && this->state != Pkcs7Builder::UPDATE)
	{
		throw InvalidStateException("Pkcs7SignedDataBuilder::addCertificate");
	}

	rc = PKCS7_add_certificate(this->pkcs7, cert.getX509());
	if (!rc)
	{
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		throw Pkcs7Exception(Pkcs7Exception::ADDING_CERTIFICATE, "Pkcs7SignedDataBuilder::addCertificate", true);
	}
}

void Pkcs7SignedDataBuilder::addCrl(CertificateRevocationList &crl) throw (Pkcs7Exception, InvalidStateException)
{
	int rc;
	if (this->state != Pkcs7Builder::INIT && this->state != Pkcs7Builder::UPDATE)
	{
		throw InvalidStateException("Pkcs7SignedDataBuilder::addCrl");
	}

	rc = PKCS7_add_crl(this->pkcs7, crl.getX509Crl());
	if (!rc)
	{
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		throw Pkcs7Exception(Pkcs7Exception::ADDING_CERTIFICATE, "Pkcs7SignedDataBuilder::addCrl", true);
	}	
}

Pkcs7SignedData* Pkcs7SignedDataBuilder::doFinal()
		throw (InvalidStateException, Pkcs7Exception)
{
	int rc;
	Pkcs7SignedData *ret;
	if (this->state != Pkcs7Builder::UPDATE)
	{
		throw InvalidStateException("Pkcs7SignedDataBuilder::dofinal");
	}
	rc = BIO_flush(this->p7bio);
	if (!rc)
	{
        BIO_free(this->p7bio);
		this->p7bio = NULL;
        this->state = Pkcs7Builder::NO_INIT;
        throw Pkcs7Exception(Pkcs7Exception::INTERNAL_ERROR, "Pkcs7SignedDataBuilder::dofinal", true);
	}
	rc = PKCS7_dataFinal(this->pkcs7, this->p7bio);
	if (!rc)
	{
		BIO_free(this->p7bio);
		this->p7bio = NULL;
		PKCS7_free(this->pkcs7);
		this->pkcs7 = NULL;
		this->state = Pkcs7Builder::NO_INIT;
		throw Pkcs7Exception(Pkcs7Exception::INTERNAL_ERROR, "Pkcs7SignedDataBuilder::dofinal", true);
	}
	
	this->state = Pkcs7Builder::NO_INIT;
	BIO_free(this->p7bio);
	this->p7bio = NULL;
	ret = new Pkcs7SignedData(this->pkcs7);
	this->pkcs7 = NULL;
	return ret;
}

Pkcs7SignedData* Pkcs7SignedDataBuilder::doFinal(std::string &data)
		throw (InvalidStateException, Pkcs7Exception)
{
	this->update(data);
	return this->doFinal();
}

Pkcs7SignedData* Pkcs7SignedDataBuilder::doFinal(ByteArray &data)
		throw (InvalidStateException, Pkcs7Exception)
{
	this->update(data);
	return this->doFinal();
}
