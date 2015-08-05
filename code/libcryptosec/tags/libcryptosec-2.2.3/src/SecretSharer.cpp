/* Copyright (C) 2000, 2001 Stefan Karrmann <S.Karrmann@gmx.net>
 * All rights reserved.
 *
 * $Id: algo.c,v 1.2 2001/01/06 22:23:13 sk Exp $
 *
 * Splits a secret into parts.
 * Or assembles the parts to get the secret.
 *
 * This file is part of sharesecret.
 */

#include <libcryptosec/SecretSharer.h>

/* global */

# ifdef DEBUG
#  define VDL(arguments) (MYVDL arguments)
#  include <stdio.h>		/* fprintf */
#  define MYVDL(arguments...) (fprintf (stderr,##arguments))
# else /* DEBUG */
#  define VDL(arguments) /* empty */
# endif /* ifdef DEBUG */

/* invert */
#define isEven(x) (((x) & 0x01) == 0)
#define isOdd(x)  ((x) & 0x01)
#define swap(x, y) (x ^= y, y ^= x, x ^= y)

void SecretSharer::ExtBinEuclid(unsigned int * u, unsigned int * v, unsigned int * u1, unsigned int * u2, unsigned int * u3){
	/* warning: swap u and v if u < v */
	unsigned int k, t1, t2, t3;
	
	if (*u < *v)
		swap (*u, *v);
	for (k = 0; isEven (*u) && isEven (*v); ++k){
		*u >>= 1; *v >>= 1;
	}
	*u1 = 1; *u2 =  0; *u3 = *u; t1 = *v; t2 = *u - 1; t3 = *v;
	do{
		do{
			if (isEven (*u3)){
				if (isOdd (*u1) || isOdd(*u2)){
					*u1 += *v; *u2 += *u;
				}
				*u1 >>= 1; *u2 >>= 1; *u3 >>= 1;
			}
			if (isEven (t3) || *u3 < t3){
				swap (*u1, t1); swap (*u2, t2); swap (*u3, t3);
			}
		} while (isEven (*u3));	/* end of do loop */
		while (*u1 < t1 || *u2 < t2){
			*u1 += *v; *u2 += *u;
		}
		*u1 -= t1; *u2 -= t2; *u3 -=t3;
	} while (t3 != 0);		/* end of do loop */
	while (*u1 >= *v && *u2 >= *u){
		*u1 -= *v; *u2 -= *u;
	}
	*u1  <<= k; *u2 <<= k; *u3 <<= k;
}

unsigned int SecretSharer::invert(unsigned int n, unsigned int modulus) throw (SecretSharerException){
	unsigned int u, v, u1, u2, u3;

	if (!(0 < n && n < modulus)){
		throw SecretSharerException(SecretSharerException::INTERNAL_ERROR, "SecretSharer::invert");
	}
	u = modulus;
	v = n;
	
//	if (!(0 < u && 0 < v)){
//		return -1;
//	}
	
	SecretSharer::ExtBinEuclid(&u, &v, &u1, &u2, &u3);
	VDL(("%lu * %lu + (-%lu) * %lu = %lu = %lu, %lu\n", u, u1, v, u2, u3, (u * u1 - v * u2), (u - u2) % u));
	if (1 == u3)
	{
		return (u - u2);		/* really the inverse */
	}
	else
	{
		throw SecretSharerException(SecretSharerException::INTERNAL_ERROR, "SecretSharer::invert");
	}
}

#define PRIME (65521ul)
#define PARTS_LIMIT (PRIME)
#define THRESHOLD_LIMIT (PRIME - 1)

unsigned char * SecretSharer::int2char(unsigned int value){
	unsigned char *data;
	data = (unsigned char *)calloc(5, sizeof(unsigned char));
	data[0] = ((value & 0xFF000000) >> 24);
	data[1] = ((value & 0x00FF0000) >> 16);
	data[2] = ((value & 0x0000FF00) >> 8);
	data[3] =  (value & 0x000000FF);
	return data;
}

unsigned int SecretSharer::char2int(unsigned char *data){
	unsigned int rc = 0x00;
	rc ^= (data[0] << 24);
	rc ^= (data[1] << 16);
	rc ^= (data[2] << 8);
	rc ^= data[3];
	return rc;
}

char * SecretSharer::bin2hex(unsigned char *data, int ndata){
	char *ret;
	ret = (char *)calloc((ndata*2)+1, sizeof(char));
	int i;
	for (i=0;i<ndata;i++){
		sprintf(ret, "%s%02x", ret, data[i]);
	}
	return ret;
}

unsigned char * SecretSharer::hex2bin(char *data, unsigned int *length){
	char hex[3];
	int d = 0;
	int ndata = strlen(data);
	unsigned char *final;
	unsigned int j = 0;
	int i = 0;
	if (ndata%2)
		return NULL;
	final = (unsigned char *)calloc(ndata/2+1, sizeof(unsigned char));
	while((ndata) > 0){
		sprintf(hex, "%c%c", data[i], data[i+1]);
		hex[2] = '\0';
		sscanf(hex, "%x", &d);
		final[j] = (unsigned char) d;
		j++;
		i++;
		i++;
		ndata--;
		ndata--;
	}
	if (j != (strlen(data)/2)){
		return NULL;
	}
	(*length) = j;
	return final;
}

void SecretSharer::setHeader(std::vector<std::ostream *>* secrets){
	unsigned int i;
	unsigned char *char_i;
	char *char_hex;
	for (i=0;i<secrets->size();i++){
		char_i = SecretSharer::int2char(i);
		char_hex = SecretSharer::bin2hex(char_i, 4);
		secrets->at(i)->write(char_hex, 8);
		free(char_i);
		free(char_hex);
	}
}

unsigned int * SecretSharer::getHeader(std::vector<std::istream *>* secrets){
	unsigned int j, size_i, *rc;
	unsigned char *char_i;
	char *char_hex;
	char_hex = (char *)calloc(9, sizeof(char));
	rc = (unsigned int *)calloc(secrets->size() + 1, sizeof(unsigned int));
	for (j=0;j<secrets->size();j++){
		secrets->at(j)->readsome(char_hex, 8);
		if ((char_i = SecretSharer::hex2bin(char_hex, &size_i)) == NULL){
			free(char_hex);
			free(rc);
			return NULL;
		}
		rc[j] = SecretSharer::char2int(char_i);
		free(char_i);
//		free(char_hex);
	}
	return rc;
}

unsigned int * SecretSharer::order_parts(unsigned int *seq, unsigned int parts, unsigned int threshold){
	unsigned int *rc, i, j, k;
	rc = (unsigned int *)calloc(threshold, sizeof(unsigned int));
	k=0;
	i=0;
	while (i < parts && k != threshold){
		for (j=0;j<threshold;j++){
			if (seq[j] == i){
				rc[k] = j;
				k++;
			}
		}
		i++;
	}
	return rc;
}

/*
 * The purpose of the "magic" is to xor the incoming value with a
 * different number each time.  This is purely intended to deal with
 * the problem that values of d >= limit-1 must be stored as four
 * bytes rather than two.  I was worried that some file might have a
 * lot of 0xff's which would balloon in size.  So I wanted to xor with
 * a rather random number.  Then, I change the random number each time
 * in order to make it less likely that some other file would happen
 * to have a lot of ballooning values.  This way it would be very rare
 * that a file managed to track my magic number in such a way that
 * many d's were over the size threshold.
 *
 * (The "magic" is not intended to increase the security or the
 * cryptographic strength of the algorithm in any way; it is purely to
 * keep the size of the output files from being much bigger than the
 * input.)
 */

/* Two random values - see comment above to explain magic */
#define IMAGIC 0x8a31
#define DMAGIC 0x1347

/******************* Code related to splitting *********************/

//void SecretSharer::rand_bytes(unsigned char *data, int num)
//		throw (RandomException){
//	FILE *fp;
//	unsigned char buffer[num];
//	int rc = 0;
//	
//	if (!(fp = fopen("/dev/urandom", "rb"))){
//		throw RandomException("/dev/urandom");
//	}
//	rc = fread(buffer, 1, num, fp);
//	if (rc != num){
//		fclose(fp);
//		throw RandomException("not enought random data");
//	}
//	fclose(fp);
//	memcpy(data, buffer, num);
//}

void SecretSharer::rand_bytes(unsigned char *data, int num)
		throw (RandomException){
	ByteArray rand;
	rand = Random::bytes(num);
	memcpy(data, rand.getDataPointer(), num);
}

/*
 * Evaluate the given polynomial, n coefficients, at point x=i.
 * Do it mod the specified modulus.
 *
 * poly = Polynomial coefficients
 * n = # coefficients (order of polynomial + 1)
 * x = Point to evaluate it at
 * mod = Modulus for evaluation
 *
 * precondition: n > 0
 */
unsigned int SecretSharer::eval (unsigned int * poly, unsigned int n, unsigned int x, unsigned int mod)
		throw (SecretSharerException){
	unsigned int result;		/* Accumulated polynomial */
	unsigned int j;			/* index */
	if (!( n > 0)){			/* precondition */
		SecretSharerException(SecretSharerException::INTERNAL_ERROR, "SecretSharer::eval");
	}
	result = poly [n - 1];
	for (j = n - 1; j > 0; j--){
		result *= x;
		result += poly [j - 1];
		result %= mod;
	}
	return result;
}

struct splitContext{
	bool have_extra;
	unsigned int extra;
	bool oddflag;
	unsigned long int magic;
	int prng_file_desc;
};

/*
 * Return a 16-bit value from file f_in, but limit it to be less than limit.
 * Anything >= limit-1 gets returned as two consecutive values (on 2 calls).
 * Return limit on EOF, or (limit + 1) if the previous return value had been
 * padded because the file had an odd # bytes.
 */

unsigned int SecretSharer::get_limited_16 (std::istream *data, unsigned int limit, struct splitContext * ctx)
		throw (RandomException){
	unsigned char buffer[3];
	unsigned int d;
	int size;

	/* First check for leftover from last time */
	if (ctx->have_extra){
		ctx->have_extra = false;
		return ctx->extra;
	}
	/* Check if last return included a pad */
	if (ctx->oddflag)
		return limit + 1;
	/* Read data (bigendian), do the magic */
	if ((size = data->readsome((char *)&(buffer[0]), 1)) < 1){
		return limit;
	}
	if ((size = data->readsome((char *)&(buffer[1]), 1)) < 1){
		rand_bytes(&(buffer[1]), 1); // may throw a exception
		ctx->oddflag = true;
	}
	d = (buffer[0] << 8) + buffer[1];
	d ^= ctx->magic;
	ctx->magic = (ctx->magic + DMAGIC) & 0xffff;
	/* If over the limit, return limit-1 as a code for that, and remember
	to return the rest next time. */
	if (d >= (limit - 1)){
		ctx->have_extra = true;
		ctx->extra = d - (limit - 1);
		d = limit - 1;
	}
	return d;
}

/*
 * Given a 16-bit value d, less than mod, split it into files in parts such
 * that any k of them can reconstruct it.
 */

void SecretSharer::split_out (unsigned int d, std::vector<std::ostream *>* secrets, int parts, int threshold)
		throw (RandomException, SecretSharerException){
	int i, di;
	unsigned int * poly;
	unsigned char buffer;
	poly = (unsigned int *)calloc(threshold * sizeof (poly [0]), sizeof(unsigned int));
	poly[0] = d;
	try {
		SecretSharer::rand_bytes((unsigned char *)(poly+1), (sizeof (poly [0])) * (threshold - 1));
	}catch(...){
		free(poly);
		throw;
	}
	/* Normalize the coefficients. Best would be poly [i] < PRIME,
	   but this is good enough to avoid overflows. - sk */
	for (i=1;i<threshold;i++){
		poly [i] = poly [i] % PRIME;
	}
	for (i=0;i<parts;i++){
		try{
			di = SecretSharer::eval (poly, threshold, i + 1, PRIME);
		}catch(...){
			free(poly);
			throw;
		}
		buffer = (di >> 8) & 0xff;
		(secrets->at(i))->write((char *)&buffer, 1);
		buffer = di & 0xff;
		(secrets->at(i))->write((char *)&buffer, 1);
	}
	free(poly);
}

/*
 * Split the specified input file into nout output files, such that
 * any threshold of them are sufficient to reconstruct the input. mod is the
 * largest prime < 2^16.  This is the main routine for the polynomial
 * splitting case.
 *
 */

void SecretSharer::split_poly (std::istream *data, int parts, int threshold, std::vector<std::ostream *>* secrets)
		throw (RandomException, SecretSharerException){
	int d, i, j;
	struct splitContext sctx;
	unsigned char buffer [1];

//	I( threshold < THRESHOLD_LIMIT); /* I must evaluate the polynom at threshold+1. */

	sctx.magic = IMAGIC;
	sctx.have_extra = false;
	sctx.oddflag = false;

	/* Prefix each file with "x" coordinate, 2 byte.
	   Write it `high byte first' =? big endian?. */
	for (i=0;i<parts;i++){
		buffer[0] = (i + 1) >> 8;
		(secrets->at(i))->write((char *)buffer, 1);
		buffer[0] = (i + 1) & 0xff;
		(secrets->at(i))->write((char *)buffer, 1);
	}
	for (;;){
		d = SecretSharer::get_limited_16 (data, PRIME, &sctx);
		if (PRIME == d){
			break;
		}
		if (PRIME + 1 == d){
			/* Odd flag - pad output files with an arbitrary byte to remember. */
			buffer[0] = 0;
			for (j=0;j<parts;j++){
				(secrets->at(j))->write((char *)&(buffer[0]), 1);
			}
			break;
		}
		SecretSharer::split_out(d, secrets, parts, threshold);
	}
}

/*
 * Split the specified input file into nout output files, such that
 * only all of them are sufficient to reconstruct the input.
 * This is the main routine for the xor-splitting case.
 *
 */

void SecretSharer::split_xor (std::istream *data, int parts, std::vector<std::ostream *>* secrets)
		throw (RandomException){
	unsigned int i;
	int j;
	unsigned char ch;
	unsigned char *buffer, xored;
	buffer = (unsigned char *)calloc(sizeof (unsigned char) * parts + 1, sizeof(unsigned char));
	while ((i = data->readsome((char *)&ch, 1)) > 0){
		xored = ch;
		try{
			SecretSharer::rand_bytes(buffer, parts-1);
		}catch(...){
			free(buffer);
			throw;
		}
		for (j=0;j<parts-1;j++){
			xored ^= buffer[j];
			(secrets->at(j))->write((char *)&(buffer[j]), 1);
			
		}
		(secrets->at(parts-1))->write((char *)&(xored), 1);
	}
	free(buffer);
}

void SecretSharer::split(std::istream *data, int parts, int threshold, std::vector<std::ostream *>* secrets)
		throw (SecretSharerException, RandomException){
	int i;
	int size, maxSize, finalSize;
	if (parts < 1){
		throw SecretSharerException(SecretSharerException::INVALID_PARTS_VALUE, "SecretSharer::split");
	}else if (threshold < 1){
		throw SecretSharerException(SecretSharerException::INVALID_THRESHOLD_VALUE, "SecretSharer::split");
	}else if (parts < threshold){
		throw SecretSharerException(SecretSharerException::INVALID_THRESHOLD_VALUE, "SecretSharer::split");
	}else if ((unsigned int)threshold > secrets->size()){
		throw SecretSharerException(SecretSharerException::INVALID_PARTS_VALUE, "SecretSharer::split");
	}
	if (threshold == 1){
		maxSize = 1024;
		size = maxSize;
		finalSize = 0;
		char buf[maxSize+1];
		while (size != 0){
			size = data->readsome(buf, maxSize);
			if (size == 0){
				break;
			}
			for (i=0;i<parts;i++){
				(secrets->at(i))->write(buf, size);
			}
		}
	}else if (parts == threshold){
		SecretSharer::split_xor (data, parts, secrets);
	}else{
		SecretSharer::setHeader(secrets);
		SecretSharer::split_poly (data, parts, threshold, secrets);
	}
}

/*
 * Split the specified input file into nout output files, such that
 * any k of them are sufficient to reconstruct the input.  mod is the
 * largest prime < 2^16.  This is the main routine for the splitting case.
 *
 */
    
/******************* Code related to assembly *********************/


/*
 * Interpolate the polynomial specified at x and y coordinates
 * in the array of size n, at x=i.  Do it mod the specified modulus.
 * This uses the Aitken Neville Algorithmus (see any introduction to
 * numerical mathmatics) to calculate the polynomial alpha.
 *
 * init: alpha_j..j(x) = y[j]
 * recusion equation:
 * alpha_j..k(x) = 1/(x_k - x_j) *
 *               * ((x_k - x) * alpha_j..k-1(x) - (x_j - x) * alpha_j+1..k(x))
 *
 * This algorithm is from Knuth, The Art of Computer Programming, Vol. 2,
 * Seminumerical Algorithms, section 4.6.4, Evaluation of Polynomials,
 * equation 43 and 44, page 485 (bottom) in 1981 hardcover edition.
 * Knuth has his indices go from 0 to n; mine go from 0 to n-1, a slight
 * notational change.
 *
 * i = x coord of interpolated point
 * x[] = x coordinates of known points
 * y[] = y coordinates of known points
 * n = size of x, y, and alpha arrays
 * mod = modulus for reducing results
 */
unsigned int SecretSharer::interp (unsigned int i, unsigned int x [], unsigned int y [], unsigned int n, unsigned int mod)
		throw (SecretSharerException){
	unsigned int * alpha;
	int j, k;
	unsigned int prod, temp;

	alpha = (unsigned int *)calloc(n * sizeof (unsigned int) + 1, sizeof(unsigned int));
	for (j = 0; j < (int)n; ++j) {
		alpha [j] = y [j];
	}
	for (k = 1; k < (int)n; ++k){
		for (j = n - 1; j >= k; --j){
			if (alpha [j] > alpha[j - 1])
				alpha [j] = alpha [j] - alpha [j - 1];
			else
				alpha [j] = alpha [j] - alpha [j - 1] + mod;
			try{
				temp = invert (x [j] - x [j - k], mod);
			}catch (...){
				free(alpha);
				throw;
			}
			alpha [j] *= temp;
			alpha [j] = alpha [j] % mod;
		}
	}
	prod = alpha [n - 1];
	for (j = n - 2; j >= 0; --j){
		if (i < x [j])
			prod *= i - x [j] + mod;
		else
			prod *= i - x [j];
		prod += alpha [j];
		prod %= mod;
	}
	free(alpha);
	return prod;
}

struct assembleContext
{
  bool * notfirst;
  unsigned int * next;
  unsigned int * y;
  bool * oddflag;
};

/*
 * Return a 16-bit-value from the file, with a flag set if only the
 * high 8 bits of the reconstructed value will be valid.  This is known
 * because odd-size files are padded with an extra byte.  We have to stay
 * two bytes ahead to know this.
 * @return limit on EOF, limit + 1 Error.
 */
 
unsigned int SecretSharer::get_assemble_16(std::vector<std::istream *>* secrets, unsigned int i, struct assembleContext * ctx, unsigned int limit){
	unsigned char buffer[2];
	unsigned int d1;
	unsigned int * next_d1;
	bool * notfirst;
	unsigned int size;
	next_d1 = ctx->next;
	notfirst = ctx->notfirst;
	if (! notfirst [i]){
		/* Get ahead the first time */
		if ((size = (secrets->at(i))->readsome((char *)&(buffer[0]), 1)) < 1){
			return limit;
		}
		if ((size = (secrets->at(i))->readsome((char *)&(buffer[1]), 1)) < 1){
			return limit + 1;
		}
		next_d1 [i] = (buffer [0] << 8) + buffer [1];
		notfirst [i] = true;
	}
	d1 = next_d1 [i];
	
	if ((size = (secrets->at(i))->readsome((char *)&(buffer[0]), 1)) < 1){
		if (ctx->oddflag[i]){
			return limit;
		}else{
			next_d1[i] = limit;
		}
	}else{
		if ((size = (secrets->at(i))->readsome((char *)&(buffer[1]), 1)) < 1){
			ctx->oddflag [i] = true;
			next_d1 [i] = (buffer [0]) << 8;
		}else{
			next_d1 [i] = ((buffer [0]) << 8) + buffer [1];
		}
	}
	return d1;
}

/*
 * Get 16-bit values from each file, and interpolate them to get the value
 * at x=0.  That is how we do the assembly.  Set the odd flag of the ctx if
 * only the high 8 bits of this interpolated value are valid.
 */
/*
 * Returns mod on EOF, exits on error.
 */

unsigned int SecretSharer::get_assemble (std::vector<std::istream *>* secrets, unsigned int *seq, unsigned int threshold, unsigned int x [], struct assembleContext * ctx)
		throw (SecretSharerException){
	unsigned int result;
	int index;
	unsigned int i;
//  int number_of_parts = parts->number_of_buffers;
	unsigned int mod = PRIME;
	index = 0;
	for (i=0;i<threshold;i++){
		ctx->y [i] = SecretSharer::get_assemble_16(secrets, seq[i], ctx, mod);
		if (mod + 1 == ctx->y [i]){ /* Only error and EOFs checking. */
			SecretSharerException(SecretSharerException::INTERNAL_ERROR, "SecretSharer::get_assemble");
		}else if (i == 0 && mod == ctx->y [0]){
			/* First file ended. => All must end. Check it! */
			for (;i<threshold;i++){
				if (ctx->oddflag [0] != ctx->oddflag [i] || mod != get_assemble_16 (secrets, seq[i], ctx, mod)){
					SecretSharerException(SecretSharerException::INTERNAL_ERROR, "SecretSharer::get_assemble");
				}
			}
			/* Everything is ok and I am finished. */
			return mod;
		}else if (i != 0 && mod == ctx->y [i]){
			SecretSharerException(SecretSharerException::INTERNAL_ERROR, "SecretSharer::get_assemble");
		}
	}
	result = SecretSharer::interp (0, x, ctx->y, threshold, PRIME);
	return result;
}

/*
 * Given files in parts, assemble them to generate the
 * original file.  This is the main routine for the assembly case.
 */

void SecretSharer::assemble_poly(std::vector<std::istream *>* secrets, unsigned int *seq, unsigned int threshold, std::ostream *secret)
		throw (SecretSharerException){
	unsigned int magic = IMAGIC;
	unsigned int *x, d;
	unsigned int i, size;
	struct assembleContext ctx;
	unsigned char buffer[2], c1, c2;
	unsigned int mod = PRIME;

	x = (unsigned int *)calloc(sizeof (unsigned int) * threshold, sizeof(unsigned int));
	ctx.notfirst = (bool *)calloc (sizeof (bool)* threshold, sizeof(unsigned int));
	ctx.oddflag = (bool *)calloc (sizeof (bool) * threshold, sizeof(unsigned int));
	ctx.next = (unsigned int *)calloc (sizeof (unsigned int) * threshold, sizeof(unsigned int));
	ctx.y = (unsigned int *)calloc (sizeof (unsigned int) * threshold, sizeof(unsigned int));
	memset (ctx.notfirst, 0, sizeof (bool) * threshold);
	memset (ctx.oddflag, 0, sizeof (bool) * threshold);

	/* Read index number x from each file, two byte per. */
	for (i=0;i<threshold;i++){
		if ((size = (secrets->at(seq[i]))->readsome((char *)&(buffer[0]), 1)) < 1){
			free(ctx.y);
			free(ctx.next);
			free(ctx.notfirst);
			free(ctx.oddflag);
			free(x);
			SecretSharerException(SecretSharerException::INTERNAL_ERROR, "SecretSharer::assemble_poly");
		}
		if ((size = (secrets->at(seq[i]))->readsome((char *)&(buffer[1]), 1)) < 1){
			free(ctx.y);
			free(ctx.next);
			free(ctx.notfirst);
			free(ctx.oddflag);
			free(x);
			SecretSharerException(SecretSharerException::INTERNAL_ERROR, "SecretSharer::assemble_poly");
		}
		x[i] = ((buffer [0]) << 8) + buffer [1];
		if (0 == x [i] || PARTS_LIMIT <= x [i]) {
			free(ctx.y);
			free(ctx.next);
			free(ctx.notfirst);
			free(ctx.oddflag);
			free(x);
			SecretSharerException(SecretSharerException::INTERNAL_ERROR, "SecretSharer::assemble_poly");
		}
	}
	while (true){
		d = SecretSharer::get_assemble (secrets, seq, threshold, x, & ctx);
		if (d == mod)
			break;			/* f_in are of same (effective) length.
						   Exit the loop, since everythin is ok. */
		if (d == mod - 1){
			try{
				d = SecretSharer::get_assemble (secrets, seq, threshold, x, & ctx);
			}catch (...){
				free(ctx.y);
				free(ctx.next);
				free(ctx.notfirst);
				free(ctx.oddflag);
				free(x);
				throw;
			}
			if (mod == d){
				free(ctx.y);
				free(ctx.next);
				free(ctx.notfirst);
				free(ctx.oddflag);
				free(x);
				SecretSharerException(SecretSharerException::INTERNAL_ERROR, "SecretSharer::assemble_poly");
			}
			d += mod - 1;
		}
		d ^= magic;
		magic = (magic + DMAGIC) & 0xffff;

		c1 = (unsigned char)(d >> 8) & 0xff;
		c2 = (unsigned char)d & 0xff;
		
		secret->write((char *)&c1, 1);
		if (ctx.oddflag[0]){
			continue;
		}
		secret->write((char *)&c2, 1);
	}
	free(ctx.y);
	free(ctx.next);
	free(ctx.notfirst);
	free(ctx.oddflag);
	free(x);
}

/*
 * Given parts a set of files, assemble them to generate the
 * original file.  This is the main routine for the assembly case.
 */

void SecretSharer::assemble_xor(std::vector<std::istream *>* secrets, unsigned int parts, std::ostream *secret){
	unsigned int i, size;
	unsigned char ch, result;
	size = (secrets->at(0))->readsome((char *)&result, 1);
	while (size != 0){
		for (i=1;i<parts;i++){
			size = (secrets->at(i))->readsome((char *)&ch, 1);
			result ^= (ch & 0xff);
		}
		secret->write((char *)&result, 1);
		size = (secrets->at(0))->readsome((char *)&result, 1);
	}
}

/*
 * Given the data parts, assemble them to generate the
 * original secret.  This is the main routine for the assembly case.
 */
void SecretSharer::join(std::vector<std::istream *>* secrets, unsigned int parts, unsigned int threshold, std::ostream *secret)
		throw (SecretSharerException){
//	int i, j;
	int maxSize, size, finalSize;
	unsigned int *seq_orig, *seq;
	
	if (parts < 1){
		throw SecretSharerException(SecretSharerException::INVALID_PARTS_VALUE, "SecretSharer::join");
	}else if (threshold < 1){
		throw SecretSharerException(SecretSharerException::INVALID_THRESHOLD_VALUE, "SecretSharer::join");
	}else if (parts < threshold){
		throw SecretSharerException(SecretSharerException::INVALID_THRESHOLD_VALUE, "SecretSharer::join");
	}else if (secrets->size() < threshold){
		throw SecretSharerException(SecretSharerException::INVALID_PARTS_VALUE, "SecretSharer::join");
	}
	if (threshold == 1){
		maxSize = 1024;
		size = maxSize;
		finalSize = 0;
		char buf[maxSize+1];
		size = (secrets->at(0))->readsome(buf, maxSize);
		while (size != 0){
			secret->write(buf, size);
			size = (secrets->at(0))->readsome(buf, maxSize);
		}
	}else if (threshold == parts){
		SecretSharer::assemble_xor (secrets, parts, secret);
	}else{
		if ((seq_orig = SecretSharer::getHeader(secrets)) == NULL){
			SecretSharerException(SecretSharerException::INTERNAL_ERROR, "SecretSharer::join");
		}
		seq = SecretSharer::order_parts(seq_orig, parts, threshold);
		free(seq_orig);
		try{
			SecretSharer::assemble_poly (secrets, seq, threshold, secret);
		}catch (...){
			free(seq);
		}
	}
}

/*
 * Given parts a set of files, assemble them to generate the
 * original file.  This is the main routine for the file assembly case.
 */
