#include <libcryptosec/ec/Curve.h>

const std::string Curve::notSpecified = "Not Specified";

Curve::Curve() {
	//Nothing to do
	this->a = 0;
	this->b = 0;
	this->p = 0;
	this->x = 0;
	this->y = 0;
	this->order = 0;
	this->cofactor = 0;
}

Curve::Curve(ByteArray& encoded) {
	//TODO
	this->a = 0;
	this->b = 0;
	this->p = 0;
	this->x = 0;
	this->y = 0;
	this->order = 0;
	this->cofactor = 0;
}

Curve::Curve(std::string& encoded) {
	//TODO
	this->a = 0;
	this->b = 0;
	this->p = 0;
	this->x = 0;
	this->y = 0;
	this->order = 0;
	this->cofactor = 0;
}

Curve::~Curve() {
}

const BIGNUM* Curve::BN_a() const throw () {
	return this->a->getBIGNUM();
}

const BIGNUM* Curve::BN_b() const throw () {
	return this->b->getBIGNUM();
}

const BIGNUM* Curve::BN_p() const throw () {
	return this->p->getBIGNUM();
}

const BIGNUM* Curve::BN_x() const throw () {
	return this->x->getBIGNUM();
}

const BIGNUM* Curve::BN_y() const throw () {
	return this->y->getBIGNUM();
}

const BIGNUM* Curve::BN_order() const throw () {
	return this->order->getBIGNUM();
}

const BIGNUM* Curve::BN_cofactor() const throw () {
	return this->cofactor->getBIGNUM();
}
