#ifndef PKCS7CERTIFICATEBUNDLEBUILDER_H_
#define PKCS7CERTIFICATEBUNDLEBUILDER_H_

#include <openssl/bio.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <string>
#include <vector>

#include "ByteArray.h"
#include "Pkcs7CertificateBundle.h"
#include "Pkcs7Builder.h"
#include <libcryptosec/exception/Pkcs7Exception.h>
#include <libcryptosec/exception/InvalidStateException.h>
#include <libcryptosec/certificate/Certificate.h>

/**
 * Implementa o padrão builder para criação de um pacote PKCS7 para disseminação
 * de certificados. De acordo com o openssl, para implementar essa
 * estrutura deve se usar o tipo PKCS7 signed sem incluir signatários. Também serve para
 * guardar apenas dados em texto plano no formato PKCS7
 * @ingroup PKCS7
 **/

class Pkcs7CertificateBundleBuilder : public Pkcs7Builder
{
public:
	/*
	 * Construtor padrão, inicializa os atributos essenciais para
	 * a criação do pacote de disseminação.
	 */
	Pkcs7CertificateBundleBuilder();
	virtual ~Pkcs7CertificateBundleBuilder();

	/*
	 * Reinicializa os atributos essenciais para
	 * a criação do pacote de disseminação.
	 */
	void init();

	/*
	 * Adiciona um certificado na pilha.
	 */
	void addCertificate(Certificate &cert)
					throw (Pkcs7Exception, InvalidStateException);

	/*
	 * Gera o pacote PKCS7 final
	 */
	Pkcs7CertificateBundle* doFinal()
					throw (InvalidStateException, Pkcs7Exception);

private:
	/*
	 * Pilha de certificados a serem adicionados ao pacote PKCS7
	 */
	STACK_OF(X509) *certs;
};

#endif /* PKCS7CERTIFICATEBUNDLEBUILDER_H_ */
