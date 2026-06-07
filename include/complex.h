#ifndef _COMPLEX_H
#define _COMPLEX_H

/*
 * <complex.h> for IsaacCompiler / StackVM.
 *
 * The compiler implements the _Complex type and the __real__/__imag__,
 * __builtin_complex operators natively (see
 * StackVM/Documentation/Complex.html).  This header just provides the standard
 * names on top of those primitives.
 */

#define complex _Complex
#define _Complex_I (__builtin_complex(0.0, 1.0))
#define I _Complex_I

/* C11 exact-construction macro. */
#define CMPLX(x, y) (__builtin_complex((double)(x), (double)(y)))
#define CMPLXF(x, y) (__builtin_complex((float)(x), (float)(y)))
#define CMPLXL(x, y) (__builtin_complex((long double)(x), (long double)(y)))

/* Component access -- these expand to the compiler's lvalue operators. */
#define creal(z) (__real__ (z))
#define cimag(z) (__imag__ (z))
#define crealf(z) (__real__ (z))
#define cimagf(z) (__imag__ (z))
#define creall(z) (__real__ (z))
#define cimagl(z) (__imag__ (z))

/* Complex conjugate: negate the imaginary part. */
#define conj(z) (__builtin_complex(__real__ (z), -__imag__ (z)))
#define conjf(z) (__builtin_complex((float)__real__ (z), (float)-__imag__ (z)))
#define conjl(z) (__builtin_complex((long double)__real__ (z), \
                                    (long double)-__imag__ (z)))

#endif /* _COMPLEX_H */
