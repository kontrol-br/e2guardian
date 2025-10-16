DISTCLEANFILES = Makefile.in

SUBDIRS= languages . scripts

DATATOPDIR = $(datadir)/$(PACKAGE_NAME)

FLISTS = transparent1x1.gif e2guardian.pl blockedflash.swf

EXTRA_DIST = $(FLISTS)

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(DATATOPDIR); \\
	$(MKDIR_P) $(DESTDIR)$(E2LOGLOCATION); \\
	$(MKDIR_P) $(DESTDIR)$(E2PIDDIR); \\
	for l in $(FLISTS) ; do \
		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(DATATOPDIR)/$$l"; \
		$(INSTALL_DATA) $$l $(DESTDIR)$(DATATOPDIR)/$$l; \
	done

uninstall-local:
	for l in $(FLISTS) ; do \
		rm -f $(DESTDIR)$(DATATOPDIR)/$$l ; \
	done
