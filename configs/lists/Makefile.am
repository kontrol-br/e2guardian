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

SAMPLELISTS = domainsnobypass \
        ipnobypass \
        urlnobypass \
        newbannedphraselist \
        newexceptionphraselist \
        newweightedphraselist \
        filtergroupslist

EXTRA_DIST = domainsnobypass.in \
             ipnobypass \
             urlnobypass.in

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(E2DATADIR)
	for l in $(SAMPLELISTS) ; do \
		if test ! -f $(DESTDIR)$(E2DATADIR)/$$l ; then \
			echo "$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l"; \
			$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l; \
		fi; \
		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l.sample"; \
		$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l.sample; \
	done
uninstall-local:
	for l in $(SAMPLELISTS) ; do \
	rm -f $(DESTDIR)$(E2DATADIR)/$$l.sample ; \
	done
