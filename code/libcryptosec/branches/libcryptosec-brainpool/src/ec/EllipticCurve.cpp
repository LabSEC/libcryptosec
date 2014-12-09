#include <libcryptosec/ec/EllipticCurve.h>

const std::string EllipticCurve::notSpecified = "Not Specified";

EllipticCurve::EllipticCurve() {
	//Nothing to do
}

EllipticCurve::EllipticCurve(ByteArray& encoded) {
	//TODO
}

EllipticCurve::EllipticCurve(std::string& encoded) {
	//TODO
}

EllipticCurve::~EllipticCurve() {
}

const BIGNUM* EllipticCurve::BN_a() const throw () {
	return this->a.getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_b() const throw () {
	return this->b.getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_p() const throw () {
	return this->p.getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_x() const throw () {
	return this->x.getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_y() const throw () {
	return this->y.getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_order() const throw () {
	return this->order.getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_cofactor() const throw () {
	return this->cofactor.getBIGNUM();
}

const BigInteger EllipticCurve::getA() const {
	return a;
}

void EllipticCurve::setA(const BigInteger a) {
	this->a = a;
}

const BigInteger EllipticCurve::getB() const {
	return b;
}

void EllipticCurve::setB(const BigInteger b) {
	this->b = b;
}

const BigInteger EllipticCurve::getCofactor() const {
	return cofactor;
}

void EllipticCurve::setCofactor(const BigInteger cofactor) {
	this->cofactor = cofactor;
}

const std::string EllipticCurve::getName() const {
	return name;
}

void EllipticCurve::setName(const std::string name) {
	this->name = name;
}

const std::string EllipticCurve::getOid() const {
	return oid;
}

void EllipticCurve::setOid(const std::string oid) {
	this->oid = oid;
}

const BigInteger EllipticCurve::getOrder() const {
	return order;
}

void EllipticCurve::setOrder(const BigInteger order) {
	this->order = order;
}

const BigInteger EllipticCurve::getP() const {
	return p;
}

void EllipticCurve::setP(const BigInteger p) {
	this->p = p;
}

const BigInteger EllipticCurve::getX() const {
	return x;
}

void EllipticCurve::setX(const BigInteger x) {
	this->x = x;
}

const BigInteger EllipticCurve::getY() const {
	return y;
}

void EllipticCurve::setY(const BigInteger y) {
	this->y = y;
}

void EllipticCurve::setA(const std::string hex) {
	this->a.setHexValue(hex);
}

void EllipticCurve::setB(const std::string hex) {
	this->b.setHexValue(hex);
}

void EllipticCurve::setCofactor(const std::string hex) {
	this->cofactor.setHexValue(hex);
}

void EllipticCurve::setOrder(const std::string hex) {
	this->order.setHexValue(hex);
}

void EllipticCurve::setP(const std::string hex) {
	this->p.setHexValue(hex);
}

void EllipticCurve::setX(const std::string hex) {
	this->x.setHexValue(hex);
}

void EllipticCurve::setY(const std::string hex) {
	this->y.setHexValue(hex);
}
