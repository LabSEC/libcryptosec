#ifndef PKCS12_H_
#define PKCS12_H_

#include <openssl/pkcs12.h>

#include "ByteArray.h"
#include "RSAPublicKey.h"
#include "DSAPublicKey.h"
#include "ECDSAPublicKey.h"
#include "EdDSAPublicKey.h"
#include "RSAPrivateKey.h"
#include "DSAPrivateKey.h"
#include "ECDSAPrivateKey.h"
#include "EdDSAPrivateKey.h"

#include <libcryptosec/certificate/Certificate.h>
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/Pkcs12Exception.h>

class Pkcs12
{
public:
	Pkcs12(PKCS12* p12);
	virtual ~Pkcs12();
	
	/**
	 * @return o conteudo em codificacao DER do pacote Pkcs12
	 * */
	ByteArray getDerEncoded() const throw(EncodeException);
	
	/**
	 * Retorna uma copia da chave privada encapsulada pelo objeto Pkcs12
	 * @param password passphrase do pacote Pkcs12
	 * */
	PrivateKey* getPrivKey(string password) throw(Pkcs12Exception);
	
	/**
	 * Retorna uma copia do certificado encapsulados pelo objeto Pkcs12
	 * @param password passphrase do pacote Pkcs12
	 * */
	Certificate* getCertificate(string password) throw(Pkcs12Exception);
	
	/**
	 * Retorna uma copia dos certificados adicionais encapsulados pelo objeto Pkcs12
	 * @param password passphrase do pacote Pkcs12
	 * */
	vector<Certificate*> getAdditionalCertificates(string password) throw(Pkcs12Exception);

protected:
	/**
	 * Popula os objetos internos da classe: privKey, cert e ca.
	 * @param password passphrase do pacote Pkcs12
	 * */
	void parse(string password) throw(Pkcs12Exception);
	
protected:
	PrivateKey* privKey;
	Certificate* cert;
	vector<Certificate*> ca;
	PKCS12* pkcs12;
};

#endif /*PKCS12_H_*/
