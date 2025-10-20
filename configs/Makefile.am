DISTCLEANFILES = Makefile.in \
e2guardian.conf \
e2guardianf1.conf \
examplef1.story

SUBDIRS = lists downloadmanagers authplugins .

if NEED_CSCONFIGS
SUBDIRS += contentscanners
endif

FLISTS = e2guardian.conf e2guardianf1.conf examplef1.story common.story \
        site.story preauth.story

AUTHPLUGIN_LISTS = lists/authplugins/ipgroups \
        lists/authplugins/portgroups \
        lists/authplugins/filtergroupslist

EXTRA_DIST = e2guardian.conf.in e2guardianf1.conf.in examplef1.story.in


install-data-local:
	$(MKDIR_P) $(DESTDIR)$(E2CONFDIR); \
	$(MKDIR_P) $(DESTDIR)$(E2CONFDIR)/lists; \
	$(MKDIR_P) $(DESTDIR)$(E2CONFDIR)/lists/authplugins; \
	for l in $(FLISTS) ; do \
	echo "$(INSTALL_DATA) $$l $(DESTDIR)$(E2CONFDIR)/$$l.sample"; \
	$(INSTALL_DATA) $$l $(DESTDIR)$(E2CONFDIR)/$$l.sample; \
	done

install-data-hook:
	for l in $(AUTHPLUGIN_LISTS) ; do \
	base=`basename $$l`; \
	src="$(srcdir)/$$l"; \
	echo "$(INSTALL_DATA) $$src $(DESTDIR)$(E2CONFDIR)/lists/authplugins/$$base.sample"; \
	$(INSTALL_DATA) $$src $(DESTDIR)$(E2CONFDIR)/lists/authplugins/$$base.sample; \
	if test ! -f $(DESTDIR)$(E2CONFDIR)/lists/authplugins/$$base ; then \
	echo "$(INSTALL_DATA) $$src $(DESTDIR)$(E2CONFDIR)/lists/authplugins/$$base"; \
	$(INSTALL_DATA) $$src $(DESTDIR)$(E2CONFDIR)/lists/authplugins/$$base; \
	fi; \
	done

uninstall-local:
	for l in $(FLISTS) ; do \
	rm -f $(DESTDIR)$(E2CONFDIR)/$$l.sample ; \
	done

