#include <libcryptosec/ec/EllipticCurve.h>

const std::string EllipticCurve::notSpecified = "Not Specified";

EllipticCurve::EllipticCurve() {
	//Nothing to do
	this->a = 0;
	this->b = 0;
	this->p = 0;
	this->x = 0;
	this->y = 0;
	this->order = 0;
	this->cofactor = 0;
}

EllipticCurve::EllipticCurve(ByteArray& encoded) {
	//TODO
	this->a = 0;
	this->b = 0;
	this->p = 0;
	this->x = 0;
	this->y = 0;
	this->order = 0;
	this->cofactor = 0;
}

EllipticCurve::EllipticCurve(std::string& encoded) {
	//TODO
	this->a = 0;
	this->b = 0;
	this->p = 0;
	this->x = 0;
	this->y = 0;
	this->order = 0;
	this->cofactor = 0;
}

EllipticCurve::~EllipticCurve() {
}

const BIGNUM* EllipticCurve::BN_a() const throw () {
	return this->a->getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_b() const throw () {
	return this->b->getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_p() const throw () {
	return this->p->getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_x() const throw () {
	return this->x->getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_y() const throw () {
	return this->y->getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_order() const throw () {
	return this->order->getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_cofactor() const throw () {
	return this->cofactor->getBIGNUM();
}
