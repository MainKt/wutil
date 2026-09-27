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

ATF_TESTS_C+=	utils_test
SRCS.utils_test=	utils_test.c utils.c

ATF_TESTS_C+=	wifi_test
SRCS.wifi_test=	\
	wifi_test.c \
	wifi.c \
	wpa_ctrl.c \
	utils.c

ATF_TESTS_C+=	wpa_ctrl_test
SRCS.wpa_ctrl_test=	\
	wpa_ctrl_test.c \
	wpa_ctrl.c

ATF_TESTS_SH+=	wutil_test

.include <bsd.test.mk>
