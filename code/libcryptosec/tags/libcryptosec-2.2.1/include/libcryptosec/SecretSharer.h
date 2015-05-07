#ifndef SECRETSHARER_H_
#define SECRETSHARER_H_

#include <vector>
#include <string>
#include <sstream>
#include <istream>

#include "ByteArray.h"
#include "Random.h"

#include <libcryptosec/exception/RandomException.h>
#include <libcryptosec/exception/SecretSharerException.h>

/**
 * Sharing and recovering secrets with only static functions.
 */
class SecretSharer {
public:
	/**
	 * share a secret in parts and threshold parts is necessary to recover
	 * @param data input of data, the secret
	 * @param parts number of parts that the secret will be shared
	 * @param threshold minimal number of parts to recover the secret
	 * @param secrets vector of ostream that will be wrote the pieces of the parts
	 * @throws InvalidNumberOfPartsException
	 * @throws InvalidNumberOfThresholdException
	 * @throws InvalidRandomDataSourceException
	 * @throws SecretSharerInternalErrorException
	 */
	static void split(std::istream *data, int parts, int threshold, std::vector<std::ostream*> *secrets)
		throw (SecretSharerException, RandomException);
	
	/**
	 * recover the secret from pieces
	 * @param secrets vector of input stream that will be read to recover the secret
	 * @param parts number of parts that the secret was split
	 * @param threshold value of threshold set on split
	 * @param secret output stream that will be wrote the secret
	 * @throws InvalidNumberOfPartsException
	 * @throws InvalidNumberOfThresholdException
	 * @throws SecretSharerInternalErrorException
	 */
	
	static void join(std::vector<std::istream* > *secrets, unsigned int parts, unsigned int threshold, std::ostream *secret)
		throw (SecretSharerException);
private:

	static unsigned char * int2char(unsigned int value);
	static unsigned int char2int(unsigned char *data);
	static char * bin2hex(unsigned char *data, int ndata);
	static unsigned char * hex2bin(char *data, unsigned int *length);
	static void setHeader(std::vector<std::ostream *>* secrets);
	static unsigned int * getHeader(std::vector<std::istream *>* secrets);
	static unsigned int * order_parts(unsigned int *seq, unsigned int parts, unsigned int threshold);

	static void rand_bytes(unsigned char *data, int num) throw (RandomException);
	static unsigned int eval (unsigned int * poly, unsigned int n, unsigned int x, unsigned int mod)
			throw (SecretSharerException);
	static void split_poly (std::istream *data, int parts, int threshold, std::vector<std::ostream *>* secrets)
			throw (RandomException, SecretSharerException);
	static unsigned int get_limited_16 (std::istream *data, unsigned int limit, struct splitContext * ctx)
			throw (RandomException);
	static void split_out (unsigned int d, std::vector<std::ostream *>* secrets, int parts, int threshold)
			throw (RandomException, SecretSharerException);
	static void split_xor (std::istream *data, int parts, std::vector<std::ostream *>* secrets)
			throw (RandomException);
	
	static void ExtBinEuclid(unsigned int * u, unsigned int * v, unsigned int * u1, unsigned int * u2, unsigned int * u3);
	static unsigned int invert(unsigned int n, unsigned int modulus)
			throw (SecretSharerException);
	
	static unsigned int interp (unsigned int i, unsigned int x [], unsigned int y [], unsigned int n, unsigned int mod)
			throw (SecretSharerException);
	static unsigned int get_assemble_16(std::vector<std::istream *>* secrets, unsigned int i, struct assembleContext * ctx, unsigned int limit);
	static unsigned int get_assemble (std::vector<std::istream *>* secrets, unsigned int *seq, unsigned int threshold, unsigned int x [], struct assembleContext * ctx)
			throw (SecretSharerException);
	static void assemble_poly(std::vector<std::istream *>* secrets, unsigned int *seq, unsigned int threshold, std::ostream *secret)
			throw (SecretSharerException);
	static void assemble_xor(std::vector<std::istream *>* secrets, unsigned int parts, std::ostream *secret);
};
#endif /*SECRETSHARER_H_*/
