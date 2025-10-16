DISTCLEANFILES = Makefile.in \
                 domainsnobypass \
                 urlnobypass

E2DATADIR = $(E2CONFDIR)/lists

SUBDIRS = oldphraselists phraselists . authplugins bannedrooms common example.group

if NEED_CSLISTS
SUBDIRS += contentscanners
endif
if NEED_DMLISTS
SUBDIRS += downloadmanagers
endif

WLISTS = README \
        domainsnobypass \
        ipnobypass \
        urlnobypass

EXTRA_DIST = domainsnobypass.in \
             ipnobypass \
             urlnobypass.in

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(E2DATADIR) && \
		for l in $(WLISTS) ; do \
			echo "$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l"; \
			$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l; \
	done && \
		for l in exceptionvirusextensionlist exceptionvirussiteiplist ; do \
			if test -f contentscanners/$$l ; then \
				echo "$(INSTALL_DATA) contentscanners/$$l $(DESTDIR)$(E2DATADIR)/$$l"; \
				$(INSTALL_DATA) contentscanners/$$l $(DESTDIR)$(E2DATADIR)/$$l; \
			fi; \
	done
uninstall-local:
	for l in $(WLISTS) ; do \
		rm -f $(DESTDIR)$(E2DATADIR)/$$l ; \
	done
	for l in exceptionvirusextensionlist exceptionvirussiteiplist ; do \
		rm -f $(DESTDIR)$(E2DATADIR)/$$l ; \
	done
