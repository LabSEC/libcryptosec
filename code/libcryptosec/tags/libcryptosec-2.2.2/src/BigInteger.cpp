#include <libcryptosec/BigInteger.h>

BigInteger::BigInteger() throw(BigIntegerException)
{
	if(!(this->bigInt = BN_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::BigInteger");
	}
	
	BigInteger::setValue(0);
}

BigInteger::BigInteger(BIGNUM const* bn) throw(BigIntegerException)
{
	if(!(this->bigInt = BN_dup(bn)))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::BigInteger");
	}
	
}

BigInteger::BigInteger(long val) throw(BigIntegerException)
{
	if(!(this->bigInt = BN_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::BigInteger");
	}
	
	BigInteger::setValue(val);
}

BigInteger::BigInteger(ASN1_INTEGER* val) throw(BigIntegerException)
{
	if(!(this->bigInt = BN_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::BigInteger");
	}
	
	if(!(ASN1_INTEGER_to_BN(val, this->bigInt)))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::BigInteger");
	}
}

BigInteger::BigInteger(ByteArray& b) throw(BigIntegerException)
{
	if(!(this->bigInt = BN_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::BigInteger");
	}
	
	if(!(BN_mpi2bn(b.getDataPointer(), b.size(), this->bigInt)))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::BigInteger");
	}
}

BigInteger::BigInteger(BigInteger const& b) throw(BigIntegerException)
{
	if(!(this->bigInt = BN_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::BigInteger");
	}
	
	*this = b;
}

BigInteger::BigInteger(std::string dec) throw(BigIntegerException)
{
	if(!(this->bigInt = BN_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::BigInteger");
	}
	
	BigInteger::setDecValue(dec);
}

BigInteger::~BigInteger()
{
	BN_clear_free(this->bigInt);
}

void BigInteger::setValue(const long val) throw(BigIntegerException)
{
	unsigned long copy;
	
	if(val < 0)
	{
		copy = static_cast<unsigned long>(-val);
	}
	else
	{
		copy = static_cast<unsigned long>(val);
	}
	
	if(!(BN_set_word(this->bigInt, copy)))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::BigInteger");
	}
	
	if(val < 0)
	{
		this->setNegative(true);
	}
}

void BigInteger::setNegative(const bool neg) throw()
{
	if(neg)
	{
		BN_set_negative(this->bigInt, 1);
	}
	else
	{
		BN_set_negative(this->bigInt, 0);
	}
}

double BigInteger::getValue() const throw(BigIntegerException)
{
	unsigned long tmp;
	double ret;
	
	tmp = BN_get_word(this->bigInt);
	
	if(tmp == BN_MASK2)
	{
		throw BigIntegerException(BigIntegerException::UNSIGNED_LONG_OVERFLOW, "BigInteger::getValue");
	}
	
	ret = static_cast<double>(tmp);
	
	if(this->isNegative())
	{
		ret = -ret;
	}
	
	return ret;
}

ASN1_INTEGER* BigInteger::getASN1Value() const throw(BigIntegerException) 
{
	ASN1_INTEGER* ret = NULL;
	
	if(!(ret = ASN1_INTEGER_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::getASN1Value");
	}
	
	if(!(BN_to_ASN1_INTEGER(this->bigInt, ret)))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::getASN1Value");
	}
	
	return ret;
}

ByteArray* BigInteger::getBinValue() const throw(BigIntegerException)
{
	unsigned char* data;
	int len;
	ByteArray* ret = new ByteArray();
	
	if(!ret)
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::getBinValue");
	}
	
	len = BN_bn2mpi(this->bigInt, NULL);
	data = new unsigned char[len];
	
	/* consegue-se dignosticar algo retorno de BN_bn2mpi? pelo que olhei no codigo ele nunca retorna algo <= 0*/
	BN_bn2mpi(this->bigInt, data);
	
	ret->setDataPointer(data, len);
	
	return ret;
}

BIGNUM const* BigInteger::getBIGNUM() const throw()
{
	return this->bigInt;
}

bool BigInteger::isNegative() const throw()
{
	bool ret = false;
	
	if(BN_is_negative(this->bigInt))
	{
		ret = true;
	}
	
	return ret;
}

string BigInteger::toHex() const throw()
{
	string ret;
	char* str; 
	
	str = BN_bn2hex(this->bigInt);
	ret = str; /*o conteudo do str eh copiado*/
	
	OPENSSL_free(str);
	return ret;
}

string BigInteger::toDec() const throw()
{
	string ret;
	char* str; 
	
	str = BN_bn2dec(this->bigInt);
	ret = str; /*o conteudo do str eh copiado*/
	
	OPENSSL_free(str);
	return ret;
}

void BigInteger::setRandValue(int numBits) throw(BigIntegerException)
{
	int top;
	int bottom;
	
	//semeia GNA
	srand(time(NULL));
	
	switch(rand() % 3)
	{
		case 0:
			top = -1;
			break;
		
		case 1:
			top = 0;
			break;
			
		case 2:
			top = 1;
			break;
	}
	
	switch (rand() % 2) {
		case 0:
			bottom = 0;
			break;
			
		case 1:
			bottom = 1;
			break;
	}
	
	if(!(BN_rand(this->bigInt, numBits, top, bottom)))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::setRandValue");
	}
	
}

int BigInteger::size() const throw()
{
	return BN_num_bits(this->bigInt);
}

void BigInteger::setHexValue(std::string hex) throw(BigIntegerException)
{
	if(!(BN_hex2bn(&this->bigInt, hex.c_str())))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::setHexValue");
	}
}

void BigInteger::setDecValue(std::string dec) throw(BigIntegerException)
{
	if(!(BN_dec2bn(&this->bigInt, dec.c_str())))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::setDecValue");
	}
}

BigInteger& BigInteger::add(BigInteger const& a) throw(BigIntegerException)
{
	if(!(BN_add(this->bigInt, this->bigInt, a.getBIGNUM())))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::add");
	}
	return *this;
}

BigInteger& BigInteger::add(long const a) throw(BigIntegerException)
{
	BigInteger b(a);
	
	return this->add(b);
}

BigInteger& BigInteger::sub(BigInteger const& a) throw(BigIntegerException)
{
	if(!(BN_sub(this->bigInt, this->bigInt, a.getBIGNUM())))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::add");
	}
	return *this;
}

BigInteger& BigInteger::sub(long const a) throw(BigIntegerException)
{
	BigInteger tmp(a);
	return this->sub(tmp);
}

BigInteger& BigInteger::mul(BigInteger const& a) throw(BigIntegerException)
{
	BN_CTX* ctx = NULL;
	BIGNUM* r = NULL;
	
	if(!(r = BN_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::mul");
	}
	
	if(!(ctx = BN_CTX_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::mul");
	}
	
	if(!BN_mul(r, this->bigInt, a.getBIGNUM(), ctx))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::mul");
	}
	
	if(BN_copy(this->bigInt, r) == NULL)
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::mul");
	}
	
	BN_free(r);
	BN_CTX_free(ctx);
	return (*this);
}

BigInteger& BigInteger::mul(long const a) throw(BigIntegerException)
{
	BigInteger tmp(a);
	return this->mul(tmp);
}

BigInteger BigInteger::operator*(BigInteger const& a) const throw(BigIntegerException)
{
	BigInteger tmp(*this);
	return tmp.mul(a);
}

BigInteger BigInteger::operator*(long const c) const throw(BigIntegerException)
{
	BigInteger tmp1(*this);
	BigInteger tmp2(c);
	return tmp1.mul(tmp2);
}

BigInteger& BigInteger::div(BigInteger const& a) throw(BigIntegerException)
{
	BN_CTX* ctx = NULL;
	BIGNUM* dv = NULL;
	BIGNUM* rem = NULL;
	
	if(a == 0)
	{
		throw BigIntegerException(BigIntegerException::DIVISION_BY_ZERO, "BigInteger::div");
	}
	
	if(!(dv = BN_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::div");
	}
	
	if(!(rem = BN_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::div");
	}
	
	if(!(ctx = BN_CTX_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::div");
	}
	
	if(!BN_div(dv, rem, this->bigInt, a.getBIGNUM(), ctx))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::div");
	}
	
	if(BN_copy(this->bigInt, dv) == NULL)
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::div");
	}
	
	BN_free(dv);
	BN_free(rem);
	BN_CTX_free(ctx);
	return (*this);
}

BigInteger& BigInteger::div(long const a) throw(BigIntegerException)
{
	BigInteger tmp(a);
	return this->div(tmp);
}

BigInteger BigInteger::operator/(BigInteger const& a) const throw(BigIntegerException)
{
	BigInteger tmp(*this);
	return tmp.div(a);
}

BigInteger BigInteger::operator/(long const c) const throw(BigIntegerException)
{
	BigInteger a(*this);
	BigInteger b(c);
	
	return a.div(b);
}

BigInteger& BigInteger::mod(BigInteger const& a) throw(BigIntegerException)
{
	BN_CTX* ctx = NULL;
	BIGNUM* rem = NULL;
	
	if(a == 0)
	{
		throw BigIntegerException(BigIntegerException::DIVISION_BY_ZERO, "BigInteger::mod");
	}
	
	if(!(rem = BN_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::mod");
	}
	
	if(!(ctx = BN_CTX_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::mod");
	}
	
	if(!BN_mod(rem, this->bigInt, a.getBIGNUM(), ctx))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::mod");
	}
	
	if(BN_copy(this->bigInt, rem) == NULL)
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::mod");
	}
	
	BN_free(rem);
	BN_CTX_free(ctx);
	return (*this);
}

BigInteger& BigInteger::mod(long const a) throw(BigIntegerException)
{
	BigInteger tmp(a);
	return this->mod(tmp);
}

BigInteger BigInteger::operator%(BigInteger const& a) const throw(BigIntegerException)
{
	BigInteger tmp(*this);
	return tmp.mod(a);
}

BigInteger BigInteger::operator%(long const c) const throw(BigIntegerException)
{
	BigInteger tmp(*this);
	return tmp.mod(c);
}

int BigInteger::compare(BigInteger const& a) const throw()
{
	return BN_cmp(this->getBIGNUM(), a.getBIGNUM());
}

BigInteger BigInteger::operator+(BigInteger const& c) const throw(BigIntegerException)
{
	BigInteger ret;
	ret.add(*this);
	return ret.add(c);
}

BigInteger BigInteger::operator+(long const c) const throw(BigIntegerException)
{
	BigInteger ret;
	ret.add(*this);
	return ret.add(c);
}

BigInteger& BigInteger::operator+=(BigInteger const& c) throw(BigIntegerException)
{
	return this->add(c);
}

BigInteger& BigInteger::operator+=(long const c) throw(BigIntegerException)
{
	BigInteger tmp(c);
	return this->add(tmp);
}

BigInteger BigInteger::operator-(BigInteger const& c) const throw(BigIntegerException)
{
	BigInteger ret;
	ret.add(*this);
	return ret.sub(c);
}

BigInteger BigInteger::operator-(long const c) const throw(BigIntegerException)
{
	BigInteger ret;
	ret.add(*this);
	return ret.sub(c);
}

BigInteger& BigInteger::operator=(BigInteger const& c) throw(BigIntegerException)
{
	if(!(BN_copy(this->bigInt, c.getBIGNUM())))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::operator=");
	}
	
	return *this;
}

BigInteger& BigInteger::operator=(long const c) throw(BigIntegerException)
{
	this->setValue(c);	
	return *this;
}

bool BigInteger::operator==(BigInteger const& c) const throw()
{
	return this->compare(c) == 0;
}

bool BigInteger::operator==(long const c) const throw(BigIntegerException)
{
	BigInteger tmp(c);
	return this->compare(tmp) == 0;
}

bool BigInteger::operator!=(BigInteger const& c) const throw()
{
	return this->compare(c) != 0;
}

bool BigInteger::operator!=(long const c) const throw(BigIntegerException)
{
	BigInteger tmp(c);
	return this->compare(tmp) != 0;
}

bool BigInteger::operator>(BigInteger const& c) const throw()
{
	return this->compare(c) == 1;
}

bool BigInteger::operator>(long const c) const throw(BigIntegerException)
{
	BigInteger tmp(c);
	return this->compare(tmp) == 1;
}

bool BigInteger::operator>=(BigInteger const& c) const throw()
{
	return (this->compare(c) >= 0);
}

bool BigInteger::operator>=(long const c) const throw(BigIntegerException)
{
	BigInteger tmp(c);
	return (*this >= tmp);
}

bool BigInteger::operator<(BigInteger const& c) const throw()
{
	return this->compare(c) == -1;
}

bool BigInteger::operator<(long const c) const throw(BigIntegerException)
{
	BigInteger tmp(c);
	return this->compare(tmp) == -1;
}

bool BigInteger::operator<=(BigInteger const& c) const throw()
{
	return (this->compare(c) <= 0);
}

bool BigInteger::operator<=(long const c) const throw(BigIntegerException)
{
	BigInteger tmp(c);
	return (*this <= tmp);
}

bool BigInteger::operator!() const throw()
{
	return ((*this) == 0);
}

bool BigInteger::operator||(BigInteger const& c) const throw()
{
	bool a = !((*this) == 0);
	bool b = !(c == 0);
	
	return a || b;
}

bool BigInteger::operator||(long const c) const throw(BigIntegerException)
{
	bool a = !((*this) == 0);
	bool b = c != 0;
	
	return a || b;
}

bool BigInteger::operator&&(BigInteger const& c) const throw()
{
	bool a = !((*this) == 0);
	bool b = !(c == 0);
	
	return a && b;
}

bool BigInteger::operator&&(long const c) const throw(BigIntegerException)
{
	bool a = !((*this) == 0);
	bool b = c != 0;
	
	return a && b;
}

BigInteger operator+(long const c, BigInteger const& d) throw(BigIntegerException)
{
	return d + c;
}

BigInteger operator-(long const c, BigInteger const& d) throw(BigIntegerException)
{
	BigInteger tmp(c);
	return tmp - d;
}
