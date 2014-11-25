#include <libcryptosec/Pkcs7CertificateBundle.h>

Pkcs7CertificateBundle::Pkcs7CertificateBundle(PKCS7 *pkcs7) throw (Pkcs7Exception) : Pkcs7(pkcs7)
{
	if (OBJ_obj2nid(this->pkcs7->type) != NID_pkcs7_signed)
	{
		throw Pkcs7Exception(Pkcs7Exception::INVALID_TYPE, "Pkcs7CertificateBundle::Pkcs7CertificateBundle");
	}
}

Pkcs7CertificateBundle::~Pkcs7CertificateBundle()
{
	if (this->pkcs7)
	{
		PKCS7_free(this->pkcs7);
	}
}

void Pkcs7CertificateBundle::extract(std::ostream *out) throw (Pkcs7Exception)
{
	BIO *p7bio;
	p7bio = PKCS7_dataInit(this->pkcs7, NULL);
	if (!p7bio)
	{
		throw Pkcs7Exception(Pkcs7Exception::INTERNAL_ERROR, "Pkcs7CertificateBundle::extract");
	}
	int size, maxSize, finalSize;
	maxSize = 1024;
	size = maxSize;
	finalSize = 0;
	char buf[maxSize+1];
	while (size == maxSize)
	{
		size = BIO_read(p7bio, buf, maxSize);
		if (size == 0)
		{
			break;
		}
		out->write(buf, size);
	}
	BIO_free(p7bio);
}

std::vector<Certificate *> Pkcs7CertificateBundle::getCertificates()
{
	std::vector<Certificate *> ret;
	int i, num;
	X509 *oneCertificate;
	Certificate *certificate;
	num = sk_X509_num(this->pkcs7->d.sign->cert);
	for (i=0;i<num;i++)
	{
		oneCertificate = sk_X509_value(this->pkcs7->d.sign->cert, i);
		certificate = new Certificate(X509_dup(oneCertificate));
		ret.push_back(certificate);
	}
	return ret;
}

Pkcs7::Type Pkcs7CertificateBundle::getType()
{
	return this->CERTIFICATE_BUNDLE;
}
