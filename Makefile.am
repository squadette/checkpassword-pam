#
# Makefile.am for checkpassword-pam
#

man_MANS = checkpassword-pam.8

bin_PROGRAMS = checkpassword-pam

checkpassword_pam_SOURCES = checkpassword-pam.c logging.h pam-support.h pam-support.c \
                            getopt.h getopt.c getopt1.c setenv.c ansidecl.h

EXTRA_DIST = $(man_MANS) interface.html \
             debian/changelog debian/control debian/copyright \
             debian/docs debian/*.files debian/*.manpages debian/rules

DIFF_FILENAME = $(PACKAGE)-$(PREVIOUS_VERSION)-$(VERSION).diff

.PHONY: diff
diff:
	tar zxfv $(PACKAGE)-$(PREVIOUS_VERSION).tar.gz
	tar zxfv $(PACKAGE)-$(VERSION).tar.gz
	diff -ruN $(PACKAGE)-$(PREVIOUS_VERSION)/ $(PACKAGE)-$(VERSION)/ > \
		$(DIFF_FILENAME).tmp; /bin/true
	diffstat $(DIFF_FILENAME).tmp > $(DIFF_FILENAME)
	cat $(DIFF_FILENAME).tmp >> $(DIFF_FILENAME)
	rm $(DIFF_FILENAME).tmp
	gzip $(PACKAGE)-$(PREVIOUS_VERSION)-$(VERSION).diff
	rm -rf ./$(PACKAGE)-$(PREVIOUS_VERSION)/ $(PACKAGE)-$(VERSION)/

.PHONY: upload
upload:
	ncftpput upload.sourceforge.net /incoming \
		$(PACKAGE)-$(VERSION).tar.gz $(PACKAGE)-$(PREVIOUS_VERSION)-$(VERSION).diff.gz

.PHONY: deb
deb: dist
	rm -rf tmp/
	mkdir tmp/
	tar zxfv $(PACKAGE)-$(VERSION).tar.gz -C tmp/
	cd tmp/$(PACKAGE)-$(VERSION); dpkg-buildpackage -rfakeroot -uc -us

.PHONY: clean-local
clean-local:
	rm -rf tmp/
