#include <libcryptosec/OpenSSLErrorHandler.h>

BIO* OpenSSLErrorHandler::errorBio = BIO_new(BIO_s_mem());

//OpenSSLErrorHandler::OpenSSLErrorHandler()
//{
//}
//
//OpenSSLErrorHandler::~OpenSSLErrorHandler()
//{
//}

void OpenSSLErrorHandler::loadErrorsString(OpenSSLErrorHandler::ErrorsString errorsString)
{
	switch (errorsString)
	{
		case OpenSSLErrorHandler::ENCODE:
			ERR_load_BIO_strings();
			ERR_load_ASN1_strings();
			ERR_load_BUF_strings();
			break;
		case OpenSSLErrorHandler::ENGINE:
			ERR_load_ENGINE_strings();
			break;
		case OpenSSLErrorHandler::MESSAGE_DIGEST:
			ERR_load_EVP_strings();
			break;
		case OpenSSLErrorHandler::SYMMETRIC_CIPHER:
			ERR_load_EVP_strings();
			break;
		case OpenSSLErrorHandler::PKCS11_MODULE:
			ERR_load_PKCS11_strings();
			break;
		case OpenSSLErrorHandler::PKCS7:
			ERR_load_PKCS7_strings();
			break;
		case OpenSSLErrorHandler::RANDOM:
			ERR_load_RAND_strings();
			break;
		case OpenSSLErrorHandler::ASYMMETRIC_KEY:
			ERR_load_RSA_strings();
			ERR_load_EVP_strings();
			ERR_load_DH_strings();
			ERR_load_DSA_strings();
			ERR_load_BN_strings();
			break;
		case OpenSSLErrorHandler::CERTIFICATION:
			ERR_load_X509_strings();
			ERR_load_X509V3_strings();
			ERR_load_ASN1_strings();
			ERR_load_OBJ_strings();
			break;
	}
}

std::string OpenSSLErrorHandler::getErrors()
{
	unsigned char *errorData;
	std::string ret;
	int size;
	ByteArray temp;
	ERR_print_errors(errorBio);
	size = BIO_get_mem_data(errorBio, &errorData);
	if (size > 0)
	{
		temp = ByteArray(errorData, size);
		ret = temp.toString();
	}
	OpenSSLErrorHandler::clearErrors();
	return ret;
}

void OpenSSLErrorHandler::clearErrors()
{
	BIO_reset(errorBio);
	ERR_clear_error();
}
