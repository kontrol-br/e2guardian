DISTCLEANFILES = Makefile.in 

E2DATADIR = $(E2CONFDIR)/lists

SUBDIRS = .

SAMPLELISTS = authexceptioniplist \
authexceptionsitelist \
authexceptionurllist \
bannedclientlist \
bannediplist \
browserregexplist \
embededreferersiteiplist \
embededreferersitelist \
embededrefererurllist \
exceptionclientlist \
exceptioniplist \
nologextensionlist \
nologregexpurllist \
nologsiteiplist \
nologsitelist \
nologurllist \
nomitmsiteiplist \
nomitmsitelist \
searchregexplist \
searchexceptionregexplist
 
EXTRA_DIST = 

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(E2DATADIR) && \\
	for l in $(SAMPLELISTS) ; do \\
		if test ! -f $(DESTDIR)$(E2DATADIR)/$$l ; then \\
			echo "$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l"; \\
			$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l; \\
		fi; \\
		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l.sample"; \\
		$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l.sample; \\
	done
uninstall-local:
	for l in $(SAMPLELISTS) ; do \
		rm -f $(DESTDIR)$(E2DATADIR)/$$l.sample ; \
	done
