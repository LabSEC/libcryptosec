#ifndef BASE64_H_
#define BASE64_H_

/* c++ library includes */
#include <string>

/* local includes */
#include "ByteArray.h"

/**
 * @ingroup Util
 */

/**
 * @brief class to perform base64 encode/decode. Implements only static functions.
 */

class Base64
{
public:
	/**
	 * encode data (readable/unreadable) to base64 format
	 * @data data to be encoded
	 * @return encoded data 
	 */
	static std::string encode(ByteArray &data);
	/**
	 * decode base64 format data to data (readable/unreadable)
	 * @data data to be decoded
	 * @return decoded data
	 */
	static ByteArray decode(std::string &data);
private:
	/**
	 * internal use. It Represents possible values to base64 format. 
	 */
	static const std::string base64Chars;
};

#endif /*BASE64_H_*/
