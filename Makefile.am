#
# Makefile.am for checkpassword-pam
#

man_MANS = checkpassword-pam.8

bin_PROGRAMS = checkpassword-pam

checkpassword_pam_SOURCES = checkpassword-pam.c logging.h pam-support.h pam-support.c \
                            getopt.h getopt.c getopt1.c

EXTRA_DIST = $(man_MANS) interface.html

.PHONY: diff
diff:
	tar zxfv $(PACKAGE)-$(PREVIOUS_VERSION).tar.gz
	tar zxfv $(PACKAGE)-$(VERSION).tar.gz
	diff -ruN $(PACKAGE)-$(PREVIOUS_VERSION)/ $(PACKAGE)-$(VERSION)/ > \
		$(PACKAGE)-$(PREVIOUS_VERSION)-$(VERSION).diff; /bin/true
	gzip $(PACKAGE)-$(PREVIOUS_VERSION)-$(VERSION).diff
	rm -rf ./$(PACKAGE)-$(PREVIOUS_VERSION)/ $(PACKAGE)-$(VERSION)/

.PHONY: upload
upload:
	ncftpput upload.sourceforge.net /incoming \
		$(PACKAGE)-$(VERSION).tar.gz $(PACKAGE)-$(PREVIOUS_VERSION)-$(VERSION).diff.gz
