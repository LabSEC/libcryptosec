#ifndef DATETIME_H_
#define DATETIME_H_

#include <openssl/asn1.h>

#include <time.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cmath>

#include "BigInteger.h"
#include <libcryptosec/exception/CertificationException.h>



/**
 * @ingroup Util
 */

/**
 * @brief Implementa a representação da data.
 * É utilizada em certificados, LCRs.
 * Utiliza o formato epoch (time_t) para representar datas internamente. 
  */
class DateTime
{
public:
	
	/**
	 * @struct DateVal
	 * Contem dados sobre uma data. Equivalente ao struct tm (time.h)
	 */
	struct DateVal
	{
		  int sec;					/* Seconds.	[0-60] (1 leap second) */
		  int min;					/* Minutes.	[0-59] */
		  int hour;					/* Hours.	[0-23] */
		  int dayOfMonth;			/* Day.		[1-31] */
		  int mon;					/* Month.	[0-11] */
		  int year;					/* Year 		   */
		  int dayOfWeek;			/* Day of week.	[0-6] */
		  int dayOfYear;			/* Days of year.[0-365]	*/	
	};
	
	/**
	 * Construtor padrão.
	 * Cria um objeto DateTime com data 0 (00:00:00 UTC, 1 de Janeiro de 1970).
	 */
	DateTime() throw(BigIntegerException);
	
	/**
	 * Construtor.
	 * Cria um objeto DateTime com uma data específica.
	 * @param dateTime data específica em segundos.
	 * obs: linux: time_t = __SLONGWORD_TYPE = long int = long.
	 */
	DateTime(time_t dateTime) throw(BigIntegerException);
	
	/**
	 * Construtor.
	 * Cria um objeto DateTime com uma data específica.
	 * @param dateTime data específica em segundos.
	 */
	DateTime(BigInteger const& dateTime) throw(BigIntegerException);
	
	/**
	 * Contrutor.
	 * Cria um objeto DateTime com uma data específica.
	 * @param asn1Time data específica. 
	 */	
	DateTime(ASN1_TIME *asn1Time) throw(BigIntegerException);

	/**
	 * Contrutor.
	 * Cria um objeto DateTime com uma data específica.
	 * @param utc string no formato UTCTime(YYMMDDHHMMSSZ) ou GeneralizedTime (YYYYMMDDHHMMSSZ).
	 * Notar que ambos estão no fuso Zulu (GMT+0). 
	 */	
	DateTime(std::string utc) throw(BigIntegerException);
	
	/**
	 * Destrutor.
	 */
	virtual ~DateTime();
	
	/** 
	 * Obtem representação da data em formato Xml
	 * @return data em formato Xml
	 */	
	std::string getXmlEncoded(std::string tab = "") const throw(BigIntegerException);

	/**
	 * Define a data do objeto DateTime.
	 * @param dateTime data específica em segundos.
	 */
	void setDateTime(time_t dateTime) throw(BigIntegerException);

	/**
	 * Define a data do objeto DateTime.
	 * @param dateTime data específica em segundos.
	 */
	void setDateTime(BigInteger const& dateTime) throw(BigIntegerException);
	
	/**
	 * Obtem data em segundos.
	 * @return data em segundos. 
	 */
	time_t getDateTime() const throw(BigIntegerException);
	
	/**
	 * Obtem data em segundos.
	 * @return data em segundos. 
	 */
	BigInteger const& getSeconds() const throw();
	
	/**
	 * Obtem data em formato ASN1.
	 * @return objeto ASN1_TIME no formato UTCTime se ano inferior a 2050, GeneralizedTime caso contrario.
	 */
	ASN1_TIME* getAsn1Time() const throw(BigIntegerException);
	
	/**
	* Obtem data em formato ASN1.
	* @return objeto ASN1_TIME no formato GeneralizedTime (YYYYMMDDHHMMSSZ).
	*/
	ASN1_TIME* getGeneralizedTime() const throw(BigIntegerException);
	
	/**
	* Obtem data em formato ASN1.
	* @return objeto ASN1_TIME no formato UTCTime (YYMMDDHHMMSSZ).
	*/
	ASN1_TIME* getUTCTime() const throw(BigIntegerException);
			
	/**
	 * Obtem data em formato ISO8601.
	 * @return string no formato YYYY-MM-DDTHH:MM:SS (no GMT).
	 */
	std::string getISODate() const throw(BigIntegerException);
	
	/**
	 * Operador de atribuição.
	 * @param value referência para objeto DateTime.
	 */
	DateTime& operator =(const DateTime& value) throw(BigIntegerException);
	
	/**
	 * Transforma do formato em segundos (epoch) para ano, mês, dia, hora, minuto e segundo.
	 * @param epoch referência para segundos.
	 * @return estrutura com ano, mês, dia, hora, minuto e segundo.
	 * */
	static DateTime::DateVal getDate(BigInteger const& epoch) throw(BigIntegerException)
	{
		const long SECS_DAY = 86400L;
		DateTime::DateVal ret;							
		BigInteger yearsSinceEpoch(0L);
		BigInteger leapDays(0L);
		BigInteger daysSinceEpoch(0L);		
		BigInteger tmp;			
		BigInteger hours(epoch);
		BigInteger days(epoch);
		int dayOfYear;
		int sizeOfMonth;
		
		hours.mod(SECS_DAY);
		days.div(SECS_DAY);
		
		tmp = hours % 60;
		ret.sec = static_cast<int>(tmp.getValue());
					
		tmp = (hours % 3600).div(60);
		ret.min = static_cast<int>(tmp.getValue());
		
		hours.div(3600);
		ret.hour = static_cast<int>(hours.getValue());
		
		ret.year = 1970;
		//remover
		//int anos = 0;
		//BigInteger sum(0L);
		//cout << "days inicial " <<days.toDec() << endl;
		//
		while(days >= DateTime::getYearSize(ret.year))
		{
			days.sub(DateTime::getYearSize(ret.year));
			ret.year++;
			
			//remover
			//anos++;
			//sum.add(DateTime::getYearSize(ret.year));
		}
		//cout << "sum "<< sum.toDec() << endl;
		//cout << "days restantes " << days.toDec() << endl;
		//cout << "anos" << anos << endl;
		
		ret.dayOfYear = static_cast<int>(days.getValue());
		dayOfYear = ret.dayOfYear;
		
		ret.mon = 0;
		sizeOfMonth = DateTime::getMonthSize(ret.mon, ret.year);
		while(dayOfYear >= sizeOfMonth)
		{
			dayOfYear-= sizeOfMonth;
			ret.mon++;
			sizeOfMonth = DateTime::getMonthSize(ret.mon, ret.year);
		}
		ret.dayOfMonth = dayOfYear + 1;
		
		ret.dayOfWeek = DateTime::getDayOfWeek(ret.year, ret.mon, ret.dayOfMonth);
		
		return ret;
	}
/*	{
		int daysOfMonths[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
		DateTime::DateVal ret;				
		int month = 1;
		int minLeft = 0;
		BigInteger yearsSinceEpoch(0L);
		BigInteger leapDays(0L);
		BigInteger daysSinceEpoch(0L);		
		BigInteger tmp;
		int mod;
		
		ret.mon = 0;
		
		//anos desde 1970
		//yearsSinceEpoch = epoch / (365 * 24 * 60 * 60);

		//ret.year = static_cast<int>((1970 + yearsSinceEpoch).getValue());
		
		//leapdays decorrentes a anos bissextos
		yearsSinceEpoch = epoch / (365 * 24 * 60 * 60);
		leapDays = yearsSinceEpoch / 4;				
		
		
		 * A divisao (ano-1970)/4 mostra quantos anos bissextos existem. Esse numero é fracionário
		 * que e deve ser interpretado da seguinte forma: fracao >= 5 -> arredonda pra cima, caso contrário
		 * arredonda pra baixo.
		 *  
		 * Porém a parte fracionária é truncada na divisão entre inteiros. Assim usa-se módulo da seguinte forma:
		 * 
		 * (ano-1970)mod 4 = 0/1 => corresponde a .0 e .25 => Nao faz nada.
		 * (ano-1970)mod 4 = 2 => ano é bissexto. Verificar se o mês > fevereiro
		 * (ano-1970)mod 4 = 3 => corresponde a .75 => Incrementa
		 * 
		mod = static_cast<int>((yearsSinceEpoch % 4).getValue());
		//cout << yearsSinceEpoch.toDec() << endl;	
		switch(mod)
		{
			case 3:
				leapDays.add(1);
				break;
				
			case 2:
				daysOfMonths[1]++;
				break;
				
			default :
				break;
		}

		//yearsSinceEpoch descontando-se os leapdays
		yearsSinceEpoch = (epoch - (leapDays * 24 * 60 *60)) / (365 * 24 * 60 * 60);
		ret.year = static_cast<int>((1970 + yearsSinceEpoch).getValue());
		
		//dias desde 1970
		daysSinceEpoch = epoch / (24*60*60);
		
		//cout << daysSinceEpoch.toDec() << endl;
		//cout << leapDays.toDec() << endl;
		
		//subtract leap days
		daysSinceEpoch = daysSinceEpoch - leapDays;
		
		//dayofyear
		ret.dayOfYear = static_cast<int>((daysSinceEpoch % 365).getValue());
		
		//verifica se eh ano bissexto
		if(DateTime::isLeapYear(ret.year))
		{
			daysOfMonths[1]++;
		}
		
		//dayOfMonth = ret.tm_yday;
		ret.dayOfMonth = ret.dayOfYear + 1; //dayOfYear [0-365], dayOfMonth [1-31]
		
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
				ret.dayOfMonth+= daysOfMonths[i];
				break;
			}
		}
		
		tmp = epoch - ((daysSinceEpoch + leapDays) * 24 * 60 * 60);
		ret.sec = static_cast<int>(tmp.getValue());	
		
		ret.hour = ret.sec / (60*60);
			
		minLeft = ret.sec - (ret.hour * 60 * 60);
		
		ret.min = minLeft / 60;
		
		ret.sec = minLeft - (ret.min * 60);
			
		ret.dayOfWeek = DateTime::getDayOfWeek(ret.year, ret.mon, ret.dayOfMonth);
		
		return ret;
	}*/
	
	/**
	 * Adiciona segundos.
	 * @param quantidade de segundos.
	 * */	
	void addSeconds(long b) throw(BigIntegerException);
	
	/**
	 * Adiciona minutos.
	 * @param quantidade de minutos.
	 * */
	void addMinutes(long b) throw(BigIntegerException);
	
	/**
	 * Adiciona horas.
	 * @param quantidade de horas.
	 * */	
	void addHours(long b) throw(BigIntegerException);
	
	/**
	 * Adiciona dias.
	 * @param quantidade de dias.
	 * */	
	void addDays(long b) throw(BigIntegerException);

	/**
	 * Adiciona anos.
	 * @param quantidade de anos.
	 * */	
	void addYears(long b) throw(BigIntegerException);
	
	/**
	 * Transforma de formato UTCTime(YYMMDDHHMMSSZ) ou GeneralizedTime (YYYYMMDDHHMMSSZ) para epoch(segundos).
	 * @param aString string no formato 'YYMMDDHHMMSSZ' ou 'YYYYMMDDHHMMSSZ'.
	 * return segundos.
	 * */
	static BigInteger date2epoch(string aString) throw(BigIntegerException)
	{
		int year;
		int month; //[0-11]
		int day; //[1-31]
		int hour; //[0-23]
		int min; //[0-59]
		int sec; //[0-59]  + leap second?	
		bool utc = false;
		istringstream stream;
		int gtoffset = 0; //deslocamento adicionar para substring se for generalizedtime
		
		utc = aString.size() == 13;
		
		//year
		if(utc)
		{
			stream.str(aString.substr(0,2));
			stream >> year;
			
			if(year >= 50)
			{
				year+= 1900;
			}
			else
			{
				year+= 2000;
			}			
		}
		else //gt
		{
			stream.str(aString.substr(0,4));
			stream >> year;
			gtoffset = 2;
		}
		
		//month
		stream.clear();
		stream.str(aString.substr(2 + gtoffset,2));
		stream >> month;
		month--;
			
		//day
		stream.clear();
		stream.str(aString.substr(4 + gtoffset,2));
		stream >> day;
		
		//hour
		stream.clear();
		stream.str(aString.substr(6 + gtoffset,2));
		stream >> hour;
		
		//min
		stream.clear();
		stream.str(aString.substr(8 + gtoffset,2));
		stream >> min;
		
		//sec
		stream.clear();
		stream.str(aString.substr(10 + gtoffset,2));
		stream >> sec;

		return date2epoch(year, month, day, hour, min, sec);
	}
	
	/**
	 * Transforma do formato ano, mês [0-11], dia [1-31], hora [0-23], minuto [0-59] e segundo [0-59] (Zulu/GMT+0) para epoch.
	 * @return segundos.
	 * */	
	static BigInteger date2epoch(int year, int month, int day, int hour, int min, int sec) throw(BigIntegerException)
	{
		BigInteger ret(0L);
		
		for(int i = 1970; i < year; i++)
		{
			ret.add(DateTime::getYearSize(i));
		}
		
		for(int i = 0 ; i < month ; i ++)
		{
			ret.add(DateTime::getMonthSize(i, year));
		}
		
		ret.add(day - 1);	
		ret.mul(24);
		ret.add(hour);
		ret.mul(60);
		ret.add(min);
		ret.mul(60);
		ret.add(sec);
			
		return ret;
	}
	
	/***
	 * Retorna o dia da semana dados ano, mês [0-11] e dia [1-31].
	 * @return dia da semana: 0 para Domingo, 6 para Sábado.
	 * obs: code adapted from http://www.sislands.com/coin70/week3/dayofwk.htm
	 * */
	static int getDayOfWeek(int year, int month, int day) throw()
	{
		month++; //para adaptar ao algoritmo
		
		int a = (14 - month) / 12;
		int y = year - a;
		int m = month + 12 * a - 2;    
		return (day + y + (y / 4) - (y / 100) + (y / 400) + ((31 * m) / 12))  % 7;		
	}
	
	/*	static int getDayOfWeek(int year, int month, int day) throw()
	{
		int doomsDays[] = {3, 28, 7, 4, 9, 6, 11, 8, 5, 10, 7, 12};
		int doomsDay;
		int ret = 0;
		int dayOfWeek;
		
		dayOfWeek = DateTime::getDoomsday(year);
		
		doomsDay = doomsDays[month];
		
		if(isLeapYear(year) & ( (month == 0) || (month == 1)) ) //jan and feb
		{
			doomsDay++;
		}
		
		if(day < doomsDay)
		{
			ret = (dayOfWeek - (doomsDay - day)) % 7; 
		}
		else if(day > doomsDay)
		{
			ret = (dayOfWeek + (day - doomsDay)) % 7;
		}
		else
		{
			ret = dayOfWeek;
		}
			
		if(ret < 0)
		{
			ret += 7;
		}
		
		return ret;
	}*/
	
	/**
	 * Retorna dia da semana de referência (doomsday) para um ano específico.
	 * @param year ano.
	 * @return dia da semana: 0 para Domingo, 6 para Sábado.
	 * */
	/*inline static int getDoomsday(int year) throw()  //YYYY
	{
		return (2 + year + (year/4) - (year/100) + (year/400)) % 7;
	}*/
	
	/**
	 * Verifica se um ano é bissexto.
	 * @param y ano.
	 * @return true se é bissexto, false caso contrário.
	 * */
	inline static bool isLeapYear(int y) throw()
	{
		return (y>0) && !(y%4) && ( (y%100) || !(y%400) );
	}

	/**
	 * Retorna quantidade de dias de um ano
	 * @param year ano desejado.
	 * @return número de dias.
	 * */
	inline static int getYearSize(int year)
	{
		int ret = 365;
		
		if(DateTime::isLeapYear(year))
		{
			ret = 366;
		}
		
		return ret;
	}
	
	/**
	 * Retorna quantidade de dias de um ano
	 * @param month mês [0-11]
	 * @param year ano desejado.
	 * @return número de dias.
	 * */
	inline static int getMonthSize(int month, int year)
	{
		int daysOfMonths[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
		
		int ret = daysOfMonths[month];
		
		if( (DateTime::isLeapYear(year)) && (month == 1) )
		{
			ret++;
		}
		
		return ret;
	}	
	
	bool operator==(const DateTime& other) const throw();
	bool operator==(time_t other) const throw(BigIntegerException);

	bool operator<(const DateTime& other) const throw();
	bool operator<(time_t other) const throw(BigIntegerException);

	bool operator>(const DateTime& other) const throw();
	bool operator>(time_t other) const throw(BigIntegerException);

		
protected:
	/*
	 * Segundos desde  00:00:00 on January 1, 1970, Coordinated Universal Time (UTC).
	 * */
	BigInteger seconds;
};

#endif /*DATETIME_H_*/
