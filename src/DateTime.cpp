#include <libcryptosec/DateTime.h>

//pegar hora local
DateTime::DateTime() throw(BigIntegerException)
{
	this->setDateTime(0);	
}

DateTime::DateTime(time_t dateTime) throw(BigIntegerException)
{
	this->setDateTime(dateTime);
}

DateTime::DateTime(BigInteger const& dateTime) throw(BigIntegerException)
{
	this->setDateTime(dateTime);
}

DateTime::DateTime(ASN1_TIME *asn1Time) throw(BigIntegerException)
{
/*	tm dateTimeTm;
	std::string dateTimeWr;
	int size, i;
	unsigned char *dateTimeBin;
	char temp[5];
	if (!asn1Time)
	{
		this->dateTime = 0;
	}
	else
	{
		dateTimeBin = ASN1_STRING_data(asn1Time);
		size = ASN1_STRING_length(asn1Time);
		if (!(dateTimeBin) || ((size != 13) && (size != 15)))
		{
	//		throw CertificationException(CertificationException::SET_NO_VALUE, "DateTime::DateTime");
			this->dateTime = 0;
		}
		else
		{
			for (i=0;i<size;i++)
			{
				dateTimeWr[i] = dateTimeBin[i];
			}
		    if (size == 13)
		    {
		    	temp[0] = dateTimeWr[10];
		    	temp[1] = dateTimeWr[11];
		    	temp[2] = '\0';
				dateTimeTm.tm_sec = atoi(temp);
				temp[0] = dateTimeWr[8];
		    	temp[1] = dateTimeWr[9];
		    	temp[2] = '\0';
				dateTimeTm.tm_min = atoi(temp);
				temp[0] = dateTimeWr[6];
		    	temp[1] = dateTimeWr[7];
		    	temp[2] = '\0';
				dateTimeTm.tm_hour = atoi(temp);
				temp[0] = dateTimeWr[4];
		    	temp[1] = dateTimeWr[5];
		    	temp[2] = '\0';
				dateTimeTm.tm_mday = atoi(temp);
				temp[0] = dateTimeWr[2];
		    	temp[1] = dateTimeWr[3];
		    	temp[2] = '\0';
				dateTimeTm.tm_mon = atoi(temp) - 1;
				dateTimeTm.tm_isdst = -1;
				temp[0] = dateTimeWr[0];
		    	temp[1] = dateTimeWr[1];
		    	temp[2] = '\0';
				dateTimeTm.tm_year = atoi(temp);
				if (dateTimeTm.tm_year < 50)
				{
					dateTimeTm.tm_year += 100;
				}
		    }
		    else
		    {
		    	temp[0] = dateTimeWr[12];
		    	temp[1] = dateTimeWr[13];
		    	temp[2] = '\0';
				dateTimeTm.tm_sec = atoi(temp);
				temp[0] = dateTimeWr[10];
		    	temp[1] = dateTimeWr[11];
		    	temp[2] = '\0';
				dateTimeTm.tm_min = atoi(temp);
				temp[0] = dateTimeWr[8];
		    	temp[1] = dateTimeWr[9];
		    	temp[2] = '\0';
				dateTimeTm.tm_hour = atoi(temp);
				temp[0] = dateTimeWr[6];
		    	temp[1] = dateTimeWr[7];
		    	temp[2] = '\0';
				dateTimeTm.tm_mday = atoi(temp);
				temp[0] = dateTimeWr[4];
		    	temp[1] = dateTimeWr[5];
		    	temp[2] = '\0';
				dateTimeTm.tm_mon = atoi(temp) - 1;
				dateTimeTm.tm_isdst = -1;
				temp[0] = dateTimeWr[0];
		    	temp[1] = dateTimeWr[1];
		    	temp[2] = dateTimeWr[2];
		    	temp[3] = dateTimeWr[3];
		    	temp[4] = '\0';
				dateTimeTm.tm_year = atoi(temp) - 1900;
			}
			this->dateTime = timegm(&dateTimeTm);
		}
	}*/
	
	string str(reinterpret_cast<char*>(asn1Time->data), asn1Time->length);
	this->setDateTime(this->date2epoch(str));
}

DateTime::DateTime(std::string s) throw(BigIntegerException)
{
	this->setDateTime(DateTime::date2epoch(s));
}

DateTime::~DateTime()
{
}

void DateTime::setDateTime(time_t dateTime) throw(BigIntegerException)
{
	this->seconds = dateTime;
}

void DateTime::setDateTime(BigInteger const& b) throw(BigIntegerException)
{
	this->seconds = b;
}

time_t DateTime::getDateTime() const throw(BigIntegerException)
{
/*	struct tm stm;
	std::istringstream stream; 
	std::string aString;
	
	aString = std::string(reinterpret_cast<char*>(this->dateTime->data), this->dateTime->length);
	
	//year
	stream.str(aString.substr(0,2));
	stream >> stm.tm_year;
	
	//month
	stream.str(aString.substr(aString.size() - 11,2));
	stream >> stm.tm_mon;
	stm.tm_mon = stm.tm_mon + 2000 - 1900;
	
	//day
	stream.str(aString.substr(aString.size() - 9,2));
	stream >> stm.tm_mday;
	
	//hour
	stream.str(aString.substr(aString.size() - 7,2));
	stream >> stm.tm_hour;
	
	//min
	stream.str(aString.substr(aString.size() - 5,2));
	stream >> stm.tm_min;
	
	//sec
	stream.str(aString.substr(aString.size() - 3,2));
	stream >> stm.tm_dec;
	
	return mktime(&stm);*/
	
	return static_cast<time_t>(this->seconds.getValue());
}

std::string DateTime::getXmlEncoded(std::string tab) const throw(BigIntegerException)
{	
	ASN1_TIME* gt;
	string str;
	
	gt = this->getAsn1Time();
	str = string(reinterpret_cast<char*>(gt->data), gt->length);
	
	str = tab + str; 
	
	return str;	
}

ASN1_TIME* DateTime::getAsn1Time() const throw(BigIntegerException)
{
	BigInteger limit("2524608000");// segundos para 01/01/2050 00:00:00 Zulu
	ASN1_TIME* ret = NULL;
	
	if(this->seconds < limit)
	{
		ret = this->getUTCTime();
	}
	else
	{
		ret = this->getGeneralizedTime();
	}
	
	return ret;
}

ASN1_TIME* DateTime::getGeneralizedTime() const throw(BigIntegerException)
{
	ASN1_TIME *ret;
	DateVal date;
	stringstream stream;
	string gt;
	
	date = DateTime::getDate(this->seconds);
	
	stream.setf(ios_base::right);
	stream.fill('0');
	
	stream.width(4); //no maximo 4 digitos para ano
	stream << date.year;
	
	stream.width(2);
	stream << (date.mon + 1);	
	stream.width(2);
	stream << date.dayOfMonth;
	stream.width(2);
	stream << date.hour;
	stream.width(2);
	stream << date.min;
	stream.width(2);
	stream << date.sec;
	stream.width(1);
	stream << "Z";

	gt = stream.str();
	
	ret = ASN1_GENERALIZEDTIME_new();
	
	//pode retornar 1 no caso de falha de alocacao de memoria
	ASN1_STRING_set(ret, gt.c_str(), gt.size());

	return ret;
}

ASN1_TIME* DateTime::getUTCTime() const throw(BigIntegerException)
{
	ASN1_TIME *ret;
	DateVal date;
	stringstream stream;
	string tmp;
	string utc;
	
	date = DateTime::getDate(this->seconds);
	
	stream.setf(ios_base::right);
	stream.fill('0');
	
	stream.width(2); //define um tamanho minimo de 2 chars
	stream << date.year;
	stream >> tmp;
	
	//pega apenas os dois numeros mais a direita
	if(tmp.size() > 2)
	{
		tmp = tmp.substr(tmp.size() - 2);
	}
	stream.clear();
	stream.str("");
	
	stream << tmp;
	stream.width(2);
	stream << (date.mon + 1);	
	stream.width(2);
	stream << date.dayOfMonth;
	stream.width(2);
	stream << date.hour;
	stream.width(2);
	stream << date.min;
	stream.width(2);
	stream << date.sec;
	stream.width(1);
	stream << "Z";

	utc = stream.str();
	
	ret = M_ASN1_UTCTIME_new();
	
	//pode retornar 1 no caso de falha de alocacao de memoria
	ASN1_STRING_set(ret, utc.c_str(), utc.size());

	return ret;
}

std::string DateTime::getISODate() const throw(BigIntegerException)
{
	DateVal date;
	stringstream stream;
	
	date = DateTime::getDate(this->seconds);
	
	stream.setf(ios_base::right);
	stream.fill('0');
	
	stream.width(4); //no maximo 4 digitos para ano
	stream << date.year;
	
	stream.width(1);
	stream << "-"; //delimitador
	
	stream.width(2);
	stream << (date.mon + 1);	

	stream.width(1);
	stream << "-"; //delimitador
	
	stream.width(2);
	stream << date.dayOfMonth;
	
	stream.width(1);
	stream << "T"; //delimitador
	
	stream.width(2);
	stream << date.hour;
	
	stream.width(1);
	stream << ":"; //delimitador
	
	stream.width(2);
	stream << date.min;

	stream.width(1);
	stream << ":"; //delimitador
	
	stream.width(2);
	stream << date.sec;
	
	return stream.str();
}

DateTime& DateTime::operator =(const DateTime& aDate) throw(BigIntegerException)
{
	this->setDateTime(aDate.getSeconds());
	return(*this);	
}

BigInteger const& DateTime::getSeconds() const throw()
{
	return this->seconds;
}

void DateTime::addSeconds(long b) throw(BigIntegerException)
{
	this->seconds.add(b);
}

void DateTime::addMinutes(long b) throw(BigIntegerException)
{
	BigInteger tmp(b);
	tmp.mul(60);
	this->seconds.add(tmp);
}

void DateTime::addHours(long b) throw(BigIntegerException)
{
	BigInteger tmp(b);
	tmp.mul(60);
	tmp.mul(60);
	this->seconds.add(tmp);
}

void DateTime::addDays(long b) throw(BigIntegerException)
{
	BigInteger tmp(b);
	tmp.mul(60);
	tmp.mul(60);
	tmp.mul(24);
	this->seconds.add(tmp);
}

void DateTime::addYears(long b) throw(BigIntegerException)
{
	BigInteger tmp(b);
	tmp.mul(60);
	tmp.mul(60);
	tmp.mul(24);
	tmp.mul(365);
	this->seconds.add(tmp);
}

//versao antiga, sem suporte a biginteger
/*time_t DateTime::date2epoch(int year, int month, int day, int hour, int min, int sec, int offset_timezone) const
{
	time_t ret = 0;
	int daysOfMonths[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
	
	int leapDays = (year - 1 - 1970)/4;
	int dyears = (year - 1970) * 365;
	int dmonth = 0;
	
	for(int i = 0; i < month ; i++)
	{
		dmonth +=  daysOfMonths[i];
	}
	
	if(isLeapYear(year) && month > 1)
	{
		dmonth++;
	}
	
	ret = (leapDays + dyears + dmonth)*24*60*60 + hour*60*60 + min*60 + sec - offset_timezone*60*60; 
	
	ret += (day - 1)*24*60*60;
		
	return ret;
}*/

//versao antiga, sem suporte a biginteger
/*DateTime::dateVal DateTime::getDate() const
{
	int daysOfMonths[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
	DateTime::dateVal ret;
	int yearsSinceEpoch = 0;
	int year = 0;
	int leapDays = 0;
	int month = 1;
	int daysSinceEpoch = 0;
	int minLeft = 0;
	
	//ret.tm_isdst = 0;
	ret.mon = 0;
	
	//anos desde 1970
	yearsSinceEpoch = this->seconds / (365 * 24 * 60 * 60);
	//year = 1970 + yearsSinceEpoch;
	//ret.tm_year = 70 + yearsSinceEpoch; //year - 1900
	ret.year = 1970 + yearsSinceEpoch;
	
	//leapdays devido a anos bissextos
	leapDays = yearsSinceEpoch / 4;
	
	//dias desde 1970
	daysSinceEpoch = this->seconds / (24*60*60);
	
	//subtract leap days
	daysSinceEpoch-= leapDays;
	
	//dayofyear
	ret.dayOfYear = daysSinceEpoch % 365;
	
	//verifica se eh ano bissexto
	if(isLeapYear(ret.year))
	{
		daysOfMonths[1]++;
	}
	
	//dayOfMonth = ret.tm_yday;
	ret.dayOfMonth = ret.dayOfYear;
	
	for(int i = 0 ; i < 12 ; i++)
	{
		ret.dayOfMonth-= daysOfMonths[i];
		
		if(ret.dayOfMonth > 0)
		{
			month++;
			ret.mon++;
		}
		else
		{
			ret.dayOfMonth+= daysOfMonths[i] + 1; //1 - 31
			break;
		}
	}
	
	ret.sec = this->seconds - ((daysSinceEpoch + leapDays) * 24 * 60 * 60);	
	
	ret.hour = ret.sec / (60*60);
		
	minLeft = ret.sec - (ret.hour * 60 * 60);
	
	ret.min = minLeft / 60;
	
	ret.sec = minLeft - (ret.min * 60);
		
	ret.dayOfWeek = this->getDayOfWeek(ret.year, ret.mon, ret.dayOfMonth);
	
	return ret;
}*/

bool DateTime::operator==(const DateTime& other) const throw()
{
	return (this->getSeconds() == other.getSeconds());
}

bool DateTime::operator==(time_t other) const throw(BigIntegerException)
{
	return (this->getSeconds() == other);
}

bool DateTime::operator<(const DateTime& other) const throw()
{
	return (this->getSeconds() < other.getSeconds());
}

bool DateTime::operator<(time_t other) const throw(BigIntegerException)
{
	return (this->getSeconds() < other);
}

bool DateTime::operator>(const DateTime& other) const throw()
{
	return (this->getSeconds() > other.getSeconds());
}

bool DateTime::operator>(time_t other) const throw(BigIntegerException)
{
	return (this->getSeconds() > other);
}
