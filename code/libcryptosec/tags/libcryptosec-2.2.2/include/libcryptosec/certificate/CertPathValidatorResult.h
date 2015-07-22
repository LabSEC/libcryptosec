#ifndef CERTPATHVALIDATORRESULT_H_
#define CERTPATHVALIDATORRESULT_H_


#include <openssl/x509_vfy.h>
#include <openssl/x509.h>
#include <string>
#include <sstream>
#include <vector>
#include "Certificate.h"
#include "ValidationFlags.h"

using namespace std;

/*
 * @ingroup Util
 * */

/*
 * @brief Encapsula informações sobre o resultado de uma validação de certificado X509. 
 * */
class CertPathValidatorResult
{

public:
	
	/**
	 * @enum ErrorCode
	 **/
	/**
	 * Possíveis erros de validação de certificado X509.
	 **/	
	enum ErrorCode
	{
		UNKNOWN,
		
		OK = X509_V_OK,
		
		UNABLE_TO_GET_ISSUER_CERT =  X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
		
		UNABLE_TO_GET_CRL = X509_V_ERR_UNABLE_TO_GET_CRL,
		
		UNABLE_TO_DECRYPT_CERT_SIGNATURE = X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE,		
		
		UNABLE_TO_DECRYPT_CRL_SIGNATURE = X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE,
	
		UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY = X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY, 
		
		CERT_SIGNATURE_FAILURE = X509_V_ERR_CERT_SIGNATURE_FAILURE,
		
		CRL_SIGNATURE_FAILURE = X509_V_ERR_CRL_SIGNATURE_FAILURE,
		
		CERT_NOT_YET_VALID = X509_V_ERR_CERT_NOT_YET_VALID,
		
		CRL_NOT_YET_VALID = X509_V_ERR_CRL_NOT_YET_VALID,
	
		CERT_HAS_EXPIRED = X509_V_ERR_CERT_HAS_EXPIRED,
		
		CRL_HAS_EXPIRED = X509_V_ERR_CRL_HAS_EXPIRED,
		
		ERROR_IN_CERT_NOT_BEFORE_FIELD = X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD,
		
		ERROR_IN_CERT_NOT_AFTER_FIELD = X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD,
		
		ERROR_IN_CRL_LAST_UPDATE_FIELD = X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD,
		
		ERROR_IN_CRL_NEXT_UPDATE_FIELD = X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD,
		
		OUT_OF_MEM = X509_V_ERR_OUT_OF_MEM,
		
		DEPTH_ZERO_SELF_SIGNED_CERT = X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
		
		SELF_SIGNED_CERT_IN_CHAIN = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
		
		UNABLE_TO_GET_ISSUER_CERT_LOCALLY = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
		
		UNABLE_TO_VERIFY_LEAF_SIGNATURE = X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
		
		CERT_CHAIN_TOO_LONG = X509_V_ERR_CERT_CHAIN_TOO_LONG,
		
		CERT_REVOKED = X509_V_ERR_CERT_REVOKED,
		
		INVALID_CA = X509_V_ERR_INVALID_CA,
		
		INVALID_NON_CA =X509_V_ERR_INVALID_NON_CA,
		
		PATH_LENGTH_EXCEEDED = X509_V_ERR_PATH_LENGTH_EXCEEDED,
		
		PROXY_PATH_LENGTH_EXCEEDED = X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED, 
		
		PROXY_CERTIFICATES_NOT_ALLOWED = X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED,
		
		INVALID_PURPOSE = X509_V_ERR_INVALID_PURPOSE,
		
		CERT_UNTRUSTED = X509_V_ERR_CERT_UNTRUSTED,
		
		CERT_REJECTED = X509_V_ERR_CERT_REJECTED,
		
		APPLICATION_VERIFICATION = X509_V_ERR_APPLICATION_VERIFICATION,
		
		SUBJECT_ISSUER_MISMATCH = X509_V_ERR_SUBJECT_ISSUER_MISMATCH,
		
		AKID_SKID_MISMATCH = X509_V_ERR_AKID_SKID_MISMATCH,
		
		AKID_ISSUER_SERIAL_MISMATCH = X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH,
		
		KEYUSAGE_NO_CERTSIGN = X509_V_ERR_KEYUSAGE_NO_CERTSIGN,
		
		UNABLE_TO_GET_CRL_ISSUER = X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER,
		
		UNHANDLED_CRITICAL_EXTENSION = X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION,
		
		KEYUSAGE_NO_CRL_SIGN = X509_V_ERR_KEYUSAGE_NO_CRL_SIGN,
		
		KEYUSAGE_NO_DIGITAL_SIGNATURE = X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE,
		
		UNHANDLED_CRITICAL_CRL_EXTENSION = X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION,
		
		NO_EXPLICIT_POLICY = X509_V_ERR_NO_EXPLICIT_POLICY
		
	};
	
public:
	
	/*
	 * Construtor padrão.
	 * */
	CertPathValidatorResult() : invalidCert(NULL), depth(0), errorCode(UNKNOWN), details(""), validationFlags(vector<ValidationFlags>())
	{
	}
	
	/*
	 * Construtor de cópia.
	 * @param cve referência para o objeto CertPathValidatorResult a ser copiado.
	 * */
	CertPathValidatorResult(const CertPathValidatorResult& cve) 
		: invalidCert(new Certificate(cve.getInvalidCertificate())), 
		depth(cve.getDepth()), errorCode(cve.getErrorCode()), details(cve.getDetails())
	{
	}
	
	/*
	 * Destrutor.
	 * */
	virtual ~CertPathValidatorResult()
	{
		delete this->invalidCert;
	}
	
	
	/*
	 * Define erro de validação
	 * @param error enum ErrorCode.
	 * */
	virtual void setErrorCode(ErrorCode error)
	{
		this->errorCode = error;
	}
	
	/*
	 * Define string de detalhes.
	 * @param details string de detalhes.
	 * */
	virtual void setDetails(string details)
	{
		this->details = details;
	}
	
	/*
	 * Retorna erro de validação.
	 * @return enum ErrorCode.
	 * */
	virtual ErrorCode getErrorType() const
	{
		return this->errorCode;
	}
	
	/*
	 * Retorna detalhes da validação.
	 * @return string.
	 * */
	virtual string getDetails()const
	{
		return this->details;
	}
	
	/*
	 * Traduz erro de validação para a string correspondente.
	 * @return string correspondente ao erro de validação.
	 * */
	virtual string getMessage() const
	{
		return (CertPathValidatorResult::errorCode2Message(this->errorCode));
	}

	/*
	 * Retorna mensagem detalhada sobre a validação de um certificado.
	 * @return string contendo mensagem detalhada sobre a validação de um certificado.
	 * */
	virtual std::string toString() const
	{
		char buf[256];
		stringstream s;
		string ret;
		
		s << this->depth;
		X509_NAME_oneline(X509_get_subject_name(this->invalidCert->getX509()), buf, sizeof(buf));
		
		ret = "Invalid certificate: " + string(buf) + "\n";		
		ret = ret + "Depth: " + s.str() + "\n"; 
		ret = ret + "Error: " + this->getMessage();

		return ret;
	}
	    
	/*
	 * Retorna código de erro da validação de certificado.
	 * @return ErroCode correspondente ao erro de validação.
	 * 
	 *  **/
	virtual ErrorCode getErrorCode() const
	{
	   	return this->errorCode;
	}

	/*
	 * Traduz erro de validação para a string correspondente.
	 * @return string correspondente ao erro de validação.
	 * */
	static string errorCode2Message(ErrorCode errorCode)
	{
    	string ret;
    	switch (errorCode)
    	{
    		case OK:
    			ret = "ok";
    			break;    		
    		
			case UNABLE_TO_GET_ISSUER_CERT:
				ret = "unable to get issuer certificate";
				break;
			case UNABLE_TO_GET_CRL:
				ret = "unable to get certificate CRL";
				break;
			case UNABLE_TO_DECRYPT_CERT_SIGNATURE:
				ret = "unable to decrypt certificate's signature";
				break;
			case UNABLE_TO_DECRYPT_CRL_SIGNATURE:
				ret = "unable to decrypt CRL's signature";
				break;
			case UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
				ret = "unable to decode issuer public key";
				break;
			case CERT_SIGNATURE_FAILURE:
				ret = "certificate signature failure";
				break;
			case CRL_SIGNATURE_FAILURE:
				ret = "CRL signature failure";
				break;
			case CERT_NOT_YET_VALID:
				ret = "certificate is not yet valid";
				break;
			case CRL_NOT_YET_VALID:
				ret = "CRL is not yet valid";
				break;
			case CERT_HAS_EXPIRED:
				ret = "certificate has expired";
				break;
			case CRL_HAS_EXPIRED:
				ret = "CRL has expired";
				break;
			case ERROR_IN_CERT_NOT_BEFORE_FIELD:
				ret = "format error in certificate's notBefore field";
				break;
			case ERROR_IN_CERT_NOT_AFTER_FIELD:
				ret = "format error in certificate's notAfter field";
				break;
			case ERROR_IN_CRL_LAST_UPDATE_FIELD:
				ret = "format error in CRL's lastUpdate field";
				break;
			case ERROR_IN_CRL_NEXT_UPDATE_FIELD:
				ret = "format error in CRL's nextUpdate field";
				break;
			case OUT_OF_MEM:
				ret = "out of memory";
				break;
			case DEPTH_ZERO_SELF_SIGNED_CERT:
				ret = "self signed certificate";
				break;
			case SELF_SIGNED_CERT_IN_CHAIN:
				ret = "self signed certificate in certificate chain";
				break;
			case UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
				ret = "unable to get local issuer certificate";
				break;
			case UNABLE_TO_VERIFY_LEAF_SIGNATURE:
				ret = "unable to verify the first certificate";
				break;
			case CERT_CHAIN_TOO_LONG:
				ret = "certificate chain too long";
				break;
			case CERT_REVOKED:
				ret = "certificate revoked";
				break;
			case INVALID_CA:
				ret =  "invalid CA certificate";
				break;
			case INVALID_NON_CA:
				ret =  "invalid non-CA certificate has CA markings";
				break;
			case PATH_LENGTH_EXCEEDED:
				ret =  "path length constraint exceeded";
				break;
			case PROXY_PATH_LENGTH_EXCEEDED:
				ret = "proxy path length constraint exceeded";
				break;
			case PROXY_CERTIFICATES_NOT_ALLOWED:
				ret = "proxy cerificates not allowed, please set the appropriate flag";
				break;
			case INVALID_PURPOSE:
				ret =  "unsupported certificate purpose";
				break;
			case CERT_UNTRUSTED:
				ret =  "certificate not trusted";
				break;
			case CERT_REJECTED:
				ret =  "certificate rejected";
				break;
			case APPLICATION_VERIFICATION:
				ret = "application verification failure";
				break;
			case SUBJECT_ISSUER_MISMATCH:
				ret = "subject issuer mismatch";
				break;
			case AKID_SKID_MISMATCH:
				ret = "authority and subject key identifier mismatch";
				break;
			case AKID_ISSUER_SERIAL_MISMATCH:
				ret = "authority and issuer serial number mismatch";
				break;
			case KEYUSAGE_NO_CERTSIGN:
				ret = "key usage does not include certificate signing";
				break;
			case UNABLE_TO_GET_CRL_ISSUER:
				ret = "unable to get CRL issuer certificate";
				break;
			case UNHANDLED_CRITICAL_EXTENSION:
				ret = "unhandled critical extension";
				break;
			case KEYUSAGE_NO_CRL_SIGN:
				ret = "key usage does not include CRL signing";
				break;
			case KEYUSAGE_NO_DIGITAL_SIGNATURE:
				ret = "key usage does not include digital signature";
				break;
			case UNHANDLED_CRITICAL_CRL_EXTENSION:
				ret = "unhandled critical CRL extension";
				break;
			case NO_EXPLICIT_POLICY:
				ret = "no explicit policy";
				break;
			default:
				ret = "unknown error";
    	}
    	return ret;
	}
	
	/*
	 * Define o certificado submetido a validação.
	 * @param cert ponteiro para o objeto Certificate. 
	 * */
	virtual void setInvalidCertificate(Certificate *cert)
	{
		X509 *newCert = X509_dup(cert->getX509());
		this->invalidCert = new Certificate(newCert);
	}
	
	/*
	 * Retorna o certificado submetido a validação.
	 * @return referência para o certificado submetido a validação.
	 * */
	virtual Certificate &getInvalidCertificate() const
	{
		return *this->invalidCert;
	}
	    
	/*
	* Retorna profundidade em que ocorreu erro de validação.
	* @return inteiro correspondente à profundidade em que ocorreu erro de validação.
	*/
	virtual int getDepth() const
	{
		return this->depth;
	}
	
	/*
	 * Define profundidade em que ocorreu erro de validação.
	 * @param depth inteiro correspondente à profundidade em que ocorreu erro de validação. 
	 * */
	virtual void setDepth(int depth)
	{
		this->depth = depth;
	}
	
	/*
	 * Adiciona uma opção de validação.
	 * @param flag item enum ValidationFlag.
	 * */
	virtual void setValidationFlag(ValidationFlags flag)
	{
		this->validationFlags.push_back(flag);
	}
	
	/*
	 * Define opções de validação.
	 * @param vetor com as opções de validação. Se o método for chamado sem parâmetro, as opções são resetadas.
	 * */
	virtual void setValidationFlag(vector<ValidationFlags> flags = vector<ValidationFlags>())
	{
		this->validationFlags = flags;
	}
	
	/*
	 * Retorna as opções de validação definidas.
	 * @return vetor de ValidationFlags.
	 * */
	virtual vector<ValidationFlags> getValidationFlags()
	{
		//codigo antigo, utilizando this->validationFlags com um unsigned int
/*		vector<ValidationFlags> flags;
		
		if(!(this->validationFlags & X509_V_FLAG_CRL_CHECK))
			flags.push_back(CRL_CHECK);
		
		if(!(this->validationFlags & X509_V_FLAG_CRL_CHECK_ALL))
			flags.push_back(CRL_CHECK_ALL);			
			
		return flags;*/
		return this->validationFlags;
	}
	
	/*
	 * Mapeia as constantes de erro de validação do OpenSSL para a enum ErrorCode.
	 * @param n constante de erro de validação do OpenSSL.
	 * @return enum ErrorCode correspondente.
	 * */
	static ErrorCode long2ErrorCode(long n)
	{
		ErrorCode ret;

    	switch (n)
    	{
    		case X509_V_OK:
    			ret = OK;
    			break;
			case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
				ret = UNABLE_TO_GET_ISSUER_CERT;
				break;
			case X509_V_ERR_UNABLE_TO_GET_CRL:
				ret = UNABLE_TO_GET_CRL;
				break;
			case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
				ret = UNABLE_TO_DECRYPT_CERT_SIGNATURE;
				break;
			case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
				ret = UNABLE_TO_DECRYPT_CRL_SIGNATURE;
				break;
			case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
				ret = UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
				break;
			case X509_V_ERR_CERT_SIGNATURE_FAILURE:
				ret = CERT_SIGNATURE_FAILURE;
				break;
			case X509_V_ERR_CRL_SIGNATURE_FAILURE:
				ret = CRL_SIGNATURE_FAILURE;
				break;
			case X509_V_ERR_CERT_NOT_YET_VALID:
				ret = CERT_NOT_YET_VALID;
				break;
			case X509_V_ERR_CRL_NOT_YET_VALID:
				ret = CRL_NOT_YET_VALID;
				break;
			case X509_V_ERR_CERT_HAS_EXPIRED:
				ret = CERT_HAS_EXPIRED;
				break;
			case X509_V_ERR_CRL_HAS_EXPIRED:
				ret = CRL_HAS_EXPIRED;
				break;
			case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
				ret = ERROR_IN_CERT_NOT_BEFORE_FIELD;
				break;
			case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
				ret = ERROR_IN_CERT_NOT_AFTER_FIELD;
				break;
			case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
				ret = ERROR_IN_CRL_LAST_UPDATE_FIELD;
				break;
			case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
				ret = ERROR_IN_CRL_NEXT_UPDATE_FIELD;
				break;
			case X509_V_ERR_OUT_OF_MEM:
				ret = OUT_OF_MEM;
				break;
			case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
				ret = DEPTH_ZERO_SELF_SIGNED_CERT;
				break;
			case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
				ret = SELF_SIGNED_CERT_IN_CHAIN;
				break;
			case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
				ret = UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
				break;
			case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
				ret = UNABLE_TO_VERIFY_LEAF_SIGNATURE;
				break;
			case X509_V_ERR_CERT_CHAIN_TOO_LONG:
				ret = CERT_CHAIN_TOO_LONG;
				break;
			case X509_V_ERR_CERT_REVOKED:
				ret = CERT_REVOKED;
				break;
			case X509_V_ERR_INVALID_CA:
				ret =  INVALID_CA;
				break;
			case X509_V_ERR_INVALID_NON_CA:
				ret =  INVALID_NON_CA;
				break;
			case X509_V_ERR_PATH_LENGTH_EXCEEDED:
				ret =  PATH_LENGTH_EXCEEDED;
				break;
			case X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED:
				ret = PROXY_PATH_LENGTH_EXCEEDED;
				break;
			case X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED:
				ret = PROXY_CERTIFICATES_NOT_ALLOWED;
				break;
			case X509_V_ERR_INVALID_PURPOSE:
				ret =  INVALID_PURPOSE;
				break;
			case X509_V_ERR_CERT_UNTRUSTED:
				ret =  CERT_UNTRUSTED;
				break;
			case X509_V_ERR_CERT_REJECTED:
				ret =  CERT_REJECTED;
				break;
			case X509_V_ERR_APPLICATION_VERIFICATION:
				ret = APPLICATION_VERIFICATION;
				break;
			case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
				ret = SUBJECT_ISSUER_MISMATCH;
				break;
			case X509_V_ERR_AKID_SKID_MISMATCH:
				ret = AKID_SKID_MISMATCH;
				break;
			case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
				ret = AKID_ISSUER_SERIAL_MISMATCH;
				break;
			case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
				ret = KEYUSAGE_NO_CERTSIGN;
				break;
			case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
				ret = UNABLE_TO_GET_CRL_ISSUER;
				break;
			case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
				ret = UNHANDLED_CRITICAL_EXTENSION;
				break;
			case X509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
				ret = KEYUSAGE_NO_CRL_SIGN;
				break;
			case X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE:
				ret = KEYUSAGE_NO_DIGITAL_SIGNATURE;
				break;
			case X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
				ret = UNHANDLED_CRITICAL_CRL_EXTENSION;
				break;
			case X509_V_ERR_NO_EXPLICIT_POLICY:
				ret = NO_EXPLICIT_POLICY;
				break;
			default:
				ret = UNKNOWN;
    	}		
		
		return ret;
	}
	
protected:
	/*
	 * Certificado submetido a validação.
	 * */
	Certificate *invalidCert;
	
	/*
	 * Profundidade em que ocorreu erro de validação.
	 * */
	int depth;
	
	/*
	 * Erro de validação.
	 * */
	ErrorCode errorCode;
	
	/*
	 * Detalhes da validação.
	 * */
	string details;
	
	/*
	 * Opções de validação.
	 * */
	vector<ValidationFlags> validationFlags;
};

#endif /*CERTPATHVALIDATORRESULT_H_*/
