#ifndef PKCS12BUILDER_H_
#define PKCS12BUILDER_H_

#include "PrivateKey.h"
#include <libcryptosec/certificate/Certificate.h>
#include "Pkcs12.h"
#include <libcryptosec/exception/Pkcs12Exception.h>

class Pkcs12Builder
{
public:
	Pkcs12Builder();
	virtual ~Pkcs12Builder();
	
	void setKeyAndCertificate(PrivateKey* key, Certificate* cert, string friendlyName = string("")) throw();
	void setAdditionalCerts(vector<Certificate*> certs) throw();
	void addAdditionalCert(Certificate* cert) throw();
	void clearAdditionalCerts() throw();
	Pkcs12* doFinal(string password = string("")) const throw(Pkcs12Exception);
	
protected:
	string friendlyName;
	PrivateKey* key;
	Certificate* keyCert;
	vector<Certificate*> certs;
};

#endif /*PKCS12BUILDER_H_*/
