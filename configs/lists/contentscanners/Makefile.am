DISTCLEANFILES = Makefile.in

E2DATADIR = $(E2CONFDIR)/lists/contentscanners

SUBDIRS = .

WLISTS = exceptionvirusmimetypelist exceptionvirusextensionlist \
         exceptionvirussitelist exceptionvirusurllist \
         exceptionvirussiteiplist

EXTRA_DIST = $(WLISTS)

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(E2DATADIR); \
        for l in $(WLISTS) ; do \
                if test ! -f $(DESTDIR)$(E2DATADIR)/$$l ; then \
			echo "$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l"; \
			$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l; \
		fi; \
		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l.sample"; \
		$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l.sample; \
	done
uninstall-local:
	for l in $(WLISTS) ; do \
		rm -f $(DESTDIR)$(E2DATADIR)/$$l.sample ; \
	done
