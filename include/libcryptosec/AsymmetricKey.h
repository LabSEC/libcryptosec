#ifndef ASYMMETRICKEY_H_
#define ASYMMETRICKEY_H_

/* openssl includes */
#include <openssl/bio.h>
#include <openssl/evp.h>

/* c++ library includes */
#include <string>

/* local includes */
#include "ByteArray.h"

/* exception icbludes */
#include <libcryptosec/exception/AsymmetricKeyException.h>


/**
 * @defgroup AsymmetricKeys Classes relacionadas ao uso de chaves assimétricas.
 **/

/**
 * Classe que representa uma chave assimétrica.
 * 
 * Esta classe é abstrata e implementa apenas os procedimentos comuns a todos os tipos 
 * de chaves assimétricas.
 * @see PrivateKey
 * @see PublicKey
 * @see RSAPrivateKey
 * @see RSAPublicKey
 * @see DSAPrivateKey
 * @see DSAPublicKey
 * @see KeyPair
 * @ingroup AsymmetricKeys
 */
class AsymmetricKey 
{

public:
	
	/**
	 * @enum Algorithm
	 **/
	/**
	 *  Algoritmos assimétricos suportados.
	 **/		 
	enum Algorithm 
	{
		RSA, /*!< A chave é do tipo RSA */
		DSA, /*!< A chave é do tipo DSA */
		ECDSA, /*!< A chave é do tipo ECDSA */
		EdDSA, /*!< A chave é do tipo EdDSA */
//		DH,
//		EC,
	};

	/**
	 * @enum Curve
	 **/
	/**
	 *  Curvas Elipticas suportadas (= NID)
	 **/
	enum Curve
	{
		X962_PRIME192V1 = 409,
		X962_PRIME192V2 = 410,
		X962_PRIME192V3 = 411,
		X962_PRIME239V1 = 412,
		X962_PRIME239V2 = 413,
		X962_PRIME239V3 = 414,
		X962_PRIME256V1 = 415,
		X962_C2PNB163V1 = 684,
		X962_C2PNB163V2 = 685,
		X962_C2PNB163V3 = 686,
		X962_C2PNB176V1 = 687,
		X962_C2TNB191V1 = 688,
		X962_C2TNB191V2 = 689,
		X962_C2TNB191V3 = 690,
		X962_C2PNB208W1 = 693,
		X962_C2TNB239V1 = 694,
		X962_C2TNB239V2 = 695,
		X962_C2TNB239V3 = 696,
		X962_C2PNB272W1 = 699,
		X962_C2PNB304W1 = 700,
		X962_C2TNB359V1 = 701,
		X962_C2PNB368W1 = 702,
		X962_C2TNB431R1 = 703,

		SECG_SECP160K1 = 708,
		SECG_SECP160R1 = 709,
		SECG_SECP160R2 = 710,
		SECG_SECP192K1 = 711,
		SECG_SECP224K1 = 712,
		SECG_SECP256K1 = 714,
		SECG_SECT163R1 = 722,
		SECG_SECT193R1 = 724,
		SECG_SECT193R2 = 725,
		SECG_SECT239K1 = 728,

		NISTSECG_SECP224R1 = 713,
		NISTSECG_SECP384R1 = 715,
		NISTSECG_SECP521R1 = 716,
		NISTSECG_SECT163K1 = 721,
		NISTSECG_SECT163R2 = 723,
		NISTSECG_SECT233K1 = 726,
		NISTSECG_SECT233R1 = 727,
		NISTSECG_SECT283K1 = 729,
		NISTSECG_SECT283R1 = 730,
		NISTSECG_SECT409K1 = 731,
		NISTSECG_SECT409R1 = 732,
		NISTSECG_SECT571K1 = 733,
		NISTSECG_SECT571R1 = 734,

		BRAINPOOL_P160R1 = 921,
		BRAINPOOL_P160T1 = 922,
		BRAINPOOL_P192R1 = 923,
		BRAINPOOL_P192T1 = 924,
		BRAINPOOL_P224R1 = 925,
		BRAINPOOL_P224T1 = 926,
		BRAINPOOL_P256R1 = 927,
		BRAINPOOL_P256T1 = 928,
		BRAINPOOL_P320R1 = 929,
		BRAINPOOL_P320T1 = 930,
		BRAINPOOL_P384R1 = 931,
		BRAINPOOL_P384T1 = 932,
		BRAINPOOL_P512R1 = 933,
		BRAINPOOL_P512T1 = 934,

		// Os NIDs são gerados pela engine, então usa valores "inválidos"
		ED25519 = 10001,
		ED448 = 10002,
		ED521 = 10003,
	};


	/**
	 * Construtor padrão recebendo um ponteiro para a estrutura OpenSSL EVP_PKEY.
	 * Esse construtor deve ser usando apenas internamente, para construir uma chave
	 * assimétrica nova deve ser utilizada a classe KeyPair.
	 * @param key ponteiro para a estrutura OpenSSL EVP_PKEY
	 * @throw AsymmetricKeyException caso a estrutura EVP_PKEY não seja uma estrutura
	 * OpenSSL válida ou ocorra algum problema na sua carga.
	 */
	AsymmetricKey(EVP_PKEY *key)
			throw (AsymmetricKeyException);
			
	/**
	 * Carrega uma chave assimétrica a partir da sua equivalente codificada em DER.
	 * Esse método é reimplementado pelas subclasses. 
	 * @param encoded a chave assimétrica no formato DER.
	 */
	AsymmetricKey(ByteArray &encoded);
	
	/**
	 * Carrega uma chave assimétrica a partir da sua equivalente codificada em PEM.
	 * Esse método é reimplementado pelas subclasses. 
	 * @param encoded a chave assimétrica no formato PEM.
	 */
	AsymmetricKey(std::string &encoded);
	
	/**
	 * Destrutor padrão. Limpa a estrutura interna EVP_PKEY
	 */
	virtual ~AsymmetricKey();

	/**
	 * Retorna uma representação da chave codificada em DER.
	 * Esse método é abstrato e implementado pelas subclasses. 
	 * @return chave assimétrica no formato DER.
	 */
	virtual ByteArray getDerEncoded() = 0;

	/**
	 * Retorna uma representação da chave codificada em PEM.
	 * Esse método é abstrato e implementado pelas subclasses. 
	 * @return chave assimétrica no formato PEM.
	 */
	virtual std::string getPemEncoded() = 0;
	
	/**
	 * Retorna o algoritmo assimétrico que deve ser usado com a chave atual.
	 * @return tipo do algoritmo simetrico para essa chave.
	 * @throw AsymmetricKeyException caso o tipo de chave não tenha sido reconhecido.
	 * @see AsymmetricKey::Algorithm
	 */
	AsymmetricKey::Algorithm getAlgorithm()
			throw (AsymmetricKeyException);
			
	/**
	 * Retorna o tamanho da chave em bytes.
	 * @return tamanho da chave em bytes.
	 * @throw AsymmetricKeyException se o tipo de chave não for suportado ou caso um
	 * erro tenha ocorrido ao tentar obter o tamanho da mesma.
	 */
	int getSize() throw (AsymmetricKeyException);
	
	/**
	 * Retorna o tamanho da chave em bits.
	 * @return tamanho da chave em bits.
	 * @throw AsymmetricKeyException se o tipo de chave não for suportado ou caso um
	 * erro tenha ocorrido ao tentar obter o tamanho da mesma.
	 */
	int getSizeBits() throw (AsymmetricKeyException);
	
	/**
	 * Uso interno. Retorna a estrutura OpenSSL interna.
	 * @return um ponteiro para a estrutura OpenSSL interna à classe AsymmetricKey.
	 */
	EVP_PKEY* getEvpPkey();
	
protected:

	/**
	 * Ponteiro para a estrutura interna OpenSSL EVP_PKEY.
	 */
	EVP_PKEY *key;
	
};

#endif /*ASYMMETRICKEY_H_*/
