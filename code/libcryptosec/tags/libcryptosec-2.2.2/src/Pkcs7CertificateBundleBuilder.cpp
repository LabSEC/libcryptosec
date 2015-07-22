#include <libcryptosec/Pkcs7CertificateBundleBuilder.h>

Pkcs7CertificateBundleBuilder::Pkcs7CertificateBundleBuilder()
{
	this->state = Pkcs7Builder::INIT;
	PKCS7_set_type(this->pkcs7, NID_pkcs7_signed);
	PKCS7_content_new(this->pkcs7, NID_pkcs7_data);
	this->certs = sk_X509_new_null();
}

Pkcs7CertificateBundleBuilder::~Pkcs7CertificateBundleBuilder()
{

}

void Pkcs7CertificateBundleBuilder::init()
{
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
	this->state = Pkcs7Builder::INIT;
	PKCS7_set_type(this->pkcs7, NID_pkcs7_signed);
	PKCS7_content_new(this->pkcs7, NID_pkcs7_data);
	this->certs = sk_X509_new_null();

}

void Pkcs7CertificateBundleBuilder::addCertificate(Certificate &cert)
					throw (Pkcs7Exception, InvalidStateException)
{
	int rc;
	if (this->state != Pkcs7Builder::INIT && this->state != Pkcs7Builder::UPDATE)
	{
		throw InvalidStateException("Pkcs7CertificateBundleBuilder::addCertificate");
	}
	rc = sk_X509_push(this->certs, cert.getX509());
	if(rc == 0)
	{
		throw Pkcs7Exception("Pkcs7CertificateBundleBuilder::addCertificate");
	}
}

Pkcs7CertificateBundle* Pkcs7CertificateBundleBuilder::doFinal()
					throw (InvalidStateException, Pkcs7Exception)
{
	Pkcs7CertificateBundle *ret;

	if (this->state != Pkcs7Builder::INIT && this->state != Pkcs7Builder::UPDATE)
	{
		throw InvalidStateException("Pkcs7CertificateBundleBuilder::dofinal");
	}

	this->pkcs7 = PKCS7_sign(NULL, NULL, this->certs, this->p7bio, 0);
	this->state = Pkcs7Builder::NO_INIT;

	if (this->pkcs7 == NULL)
	{
		throw Pkcs7Exception(Pkcs7Exception::INVALID_PKCS7, "Pkcs7CertificateBundleBuilder::dofinal");
	}
	ret = new Pkcs7CertificateBundle(pkcs7);

	BIO_free(this->p7bio);
	this->p7bio = NULL;
	this->pkcs7 = NULL;

	return ret;
}
