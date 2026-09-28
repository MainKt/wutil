PACKAGE=	tests

LDFLAGS+=	-L/usr/local/lib
CFLAGS+=	-I/usr/local/include

.if defined(MK_WUTIL_SAN)
CFLAGS+=	-fsanitize=address,undefined
LDFLAGS+=	-fsanitize=address,undefined
.endif

LIBATF_C?=	${LIBDESTDIR}${LIBDIR_BASE}/libprivateatf-c.a
LDADD_atf_c?=	-lprivateatf-c

.PATH:	${.CURDIR:H}

ATF_TESTS_C+=	array_test

ATF_TESTS_C+=	interface_test
SRCS.interface_test=	interface_test.c interface.c
LDADD.interface_test+=	-lifconfig

.include <bsd.test.mk>
