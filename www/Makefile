
.PHONY: html
html: checkpassword-pam.8.html

checkpassword-pam.8.html: ../checkpassword-pam.8
	man-to-html $< > $@

.PHONY: rsync
rsync: html
	rsync -trvz -e ssh --stats *.html ../README ../NEWS \
		tyranny@checkpasswd-pam.sf.net:/home/groups/c/ch/checkpasswd-pam/htdocs/

.PHONY: clean
clean:
	rm -f checkpassword-pam.8.html
