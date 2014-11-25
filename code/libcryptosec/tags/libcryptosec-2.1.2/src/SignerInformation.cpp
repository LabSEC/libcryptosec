#include <libcryptosec/SignerInformation.h>

/*SignerInformation::SignerInformation()
{
}*/

SignerInformation::~SignerInformation()
{
	PKCS7_SIGNER_INFO_free(this->si);
}
