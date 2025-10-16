DISTCLEANFILES = Makefile.in

E2DATADIR = $(E2CONFDIR)/lists/authplugins

SUBDIRS = .

WLISTS = ipgroups portgroups filtergroupslist

EXTRA_DIST = $(WLISTS)

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(E2DATADIR); \\
	for l in $(WLISTS) ; do \
		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l.sample"; \
		$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l.sample; \
		if test ! -f $(DESTDIR)$(E2DATADIR)/$$l ; then \
			echo "$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l"; \
			$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l; \
		fi; \
	done


uninstall-local:
	for l in $(WLISTS) ; do \
		rm -f $(DESTDIR)$(E2DATADIR)/$$l.sample ; \
	done
