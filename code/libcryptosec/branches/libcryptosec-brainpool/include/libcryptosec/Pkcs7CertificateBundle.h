#ifndef PKCS7CERTIFICATEBUNDLE_H_
#define PKCS7CERTIFICATEBUNDLE_H_

#include "Pkcs7.h"

#include <libcryptosec/exception/Pkcs7Exception.h>
#include <libcryptosec/certificate/Certificate.h>

class Pkcs7CertificateBundle : public Pkcs7
{
public:
	Pkcs7CertificateBundle(PKCS7 *pkcs7) throw (Pkcs7Exception);
	virtual ~Pkcs7CertificateBundle();

	/*
	 * Extrai o texto plano contido no pacote PKCS7
	 */
	void extract(std::ostream *out) throw (Pkcs7Exception);

	/**
	 * Retorna a lista de certificados contidas no pacote.
	 * @return a lista de certificados contidas no pacote.
	 **/
	std::vector<Certificate *> getCertificates();

	/**
	 * Implementa o método abstrato Pkcs7::getType(). Retorna Pkcs7::DATA
	 * @return o tipo de pacote PKCS7, no caso Pkcs7::DATA
	 **/
	virtual Pkcs7::Type getType();
};

#endif /* PKCS7CERTIFICATEBUNDLE_H_ */
