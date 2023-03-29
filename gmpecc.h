#ifndef GMPECC_H
#define GMPECC_H

#include <gmp.h>

// Curve structure as per https://github.com/AntonKueltz/fastecdsa/blob/7315fa30c3e533dd12ff7bf9161f96b93607ad85/fastecdsa/curve.py
struct Curve {
	char *name;
	mpz_t p;
	mpz_t a;
	mpz_t b;
	mpz_t q;
	mpz_t gx;
	mpz_t gy;
	unsigned char bytes[5];
};

struct Point {
	mpz_t x;
	mpz_t y;
	struct Curve curve;
};

struct Elliptic_Curve {
	mpz_t p;
	mpz_t n;
};


void Point_Doubling(struct Point *P, struct Point *R);
void Point_Addition(struct Point *P, struct Point *Q, struct Point *R);
void Scalar_Multiplication(struct Point P, struct Point *R, mpz_t m);
void Point_Negation(struct Point *A, struct Point *S);
void init_doublingG(struct Point *P);
void deallocate_doublingG();
struct Elliptic_Curve EC;
struct Point G;
struct Point DoublingG[256];


#endif
