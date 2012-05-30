#include <libcryptosec/Pkcs7EnvelopedData.h>

Pkcs7EnvelopedData::Pkcs7EnvelopedData(PKCS7 *pkcs7) throw (Pkcs7Exception) : Pkcs7(pkcs7)
{
	if (OBJ_obj2nid(this->pkcs7->type) != NID_pkcs7_enveloped)
	{
		throw Pkcs7Exception(Pkcs7Exception::INVALID_TYPE, "Pkcs7EnvelopedData::Pkcs7EnvelopedData");
	}
}

Pkcs7EnvelopedData::~Pkcs7EnvelopedData()
{
}

Pkcs7::Type Pkcs7EnvelopedData::getType()
{
	return Pkcs7::ENVELOPED;
}

//std::vector<Certificate *> Pkcs7EnvelopedData::getCertificates()
//{
//	std::vector<Certificate *> ret;
//	int i, num;
//	PKCS7_RECIP_INFO *recipInfo;
//	Certificate *certificate;
//	num = sk_PKCS7_RECIP_INFO_num(this->pkcs7->d.enveloped->recipientinfo);
//	for (i=0;i<num;i++)
//	{
//		recipInfo = sk_PKCS7_RECIP_INFO_value(this->pkcs7->d.enveloped->recipientinfo, i);
//		certificate = new Certificate(X509_dup(recipInfo->cert));
//		ret.push_back(certificate);
//	}
//	return ret;
//}

void Pkcs7EnvelopedData::decrypt(Certificate &certificate, PrivateKey &privateKey, std::ostream *out)
		throw (Pkcs7Exception)
{
	BIO *p7bio;
	int size, maxSize, finalSize;
	p7bio = PKCS7_dataDecode(this->pkcs7, privateKey.getEvpPkey(), NULL, certificate.getX509());
	if (!p7bio)
	{
		throw Pkcs7Exception(Pkcs7Exception::DECRYPTING, "Pkcs7EnvelopedData::decrypt");
	}
	maxSize = 4096;
	size = maxSize;
	finalSize = 0;
	char buf[maxSize+1];
	while (size == maxSize)
	{
		size = BIO_read(p7bio, buf, maxSize);
		if (size == 0){
			break;
		}
		out->write(buf, size);
	}
	BIO_free(p7bio);
}
