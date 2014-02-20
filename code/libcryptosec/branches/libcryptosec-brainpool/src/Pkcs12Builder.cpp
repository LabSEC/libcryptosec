#include <libcryptosec/Pkcs12Builder.h>

Pkcs12Builder::Pkcs12Builder()
{
	this->key = NULL;
	this->keyCert = NULL;
	this->friendlyName = string("");
}

Pkcs12Builder::~Pkcs12Builder()
{
}

void Pkcs12Builder::setKeyAndCertificate(PrivateKey* key, Certificate* cert, string friendlyName) throw()
{
	this->key = key;
	this->keyCert = cert;
	this->friendlyName = friendlyName;
}

void Pkcs12Builder::setAdditionalCerts(vector<Certificate*> certs) throw()
{
	this->certs = certs;
}

void Pkcs12Builder::addAdditionalCert(Certificate* cert) throw()
{
	this->certs.push_back(cert);
}

void Pkcs12Builder::clearAdditionalCerts() throw()
{
	this->certs.clear();
}

Pkcs12* Pkcs12Builder::doFinal(string password) const throw(Pkcs12Exception)
{
	PKCS12* tmp = NULL;
	STACK_OF(X509)* ca = NULL;
	char* cpass = NULL;
	char* cname = NULL;	
	
	int nid_key = 0;
	int nid_cert = 0;
	int iter = 0;
	int mac_iter = 0;
	int keytype = 0;

	//verifica se chave privada corresponde a chave publica
	if(!X509_check_private_key(this->keyCert->getX509(), this->key->getEvpPkey()))
	{
		throw Pkcs12Exception(Pkcs12Exception::KEY_AND_CERT_DO_NOT_MATCH, "Pkcs12Builder::doFinal");
	}
	
	//cria array de char para password
	cpass = new char[password.size() + 1];
	strcpy(cpass, password.c_str());
	
	//cria array de char para friendlyname
	if(friendlyName.compare("") != 0)
	{
		cname = new char[this->friendlyName.size() + 1];
		strcpy(cname, this->friendlyName.c_str());
	}
	
	//cria pilha de certificados
	ca = sk_X509_new_null();
	for(unsigned int i = 0 ; i < this->certs.size() ; i++)
	{
		sk_X509_push(ca, this->certs.at(i)->getX509());
	}
	
	//cria estruta PKCS12
	tmp =  PKCS12_create(cpass, cname, this->key->getEvpPkey(), this->keyCert->getX509(), ca,
	                                nid_key, nid_cert, iter, mac_iter, keytype);

	if(tmp == NULL)
	{
		delete cpass;
		delete cname;
		sk_X509_free(ca);
		
		throw Pkcs12Exception(Pkcs12Exception::UNKNOWN, "Pkcs12Builder::doFinal");
	}
	
	delete[] cpass;
	delete[] cname;
	sk_X509_free(ca);

	return new Pkcs12(tmp);
}
