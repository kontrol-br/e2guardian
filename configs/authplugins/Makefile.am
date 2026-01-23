DISTCLEANFILES = Makefile.in

E2DATADIR = $(E2CONFDIR)/authplugins

SUBDIRS = .

FLISTS = ident.conf ip.conf \
	 port.conf pf-basic.conf  \
	 BearerBasic.conf \
	 proxy-basic.conf proxy-digest.conf \
	 proxy-header.conf proxy-ntlm.conf


if PRT_DNSAUTH
FLISTS += dnsauth.conf
endif


EXTRA_DIST = ident.conf ip.conf \
	     port.conf dnsauth.conf pf-basic.conf \
	     BearerBasic.conf proxy-basic.conf \
	     proxy-digest.conf proxy-header.conf \
	     proxy-ntlm.conf

SAMPLE_LISTS = proxy-basic.conf proxy-digest.conf \
	       proxy-header.conf proxy-ntlm.conf

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(E2DATADIR) && \
	for l in $(FLISTS) ; do \
		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l"; \
		$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l; \
	done
	for l in $(SAMPLE_LISTS) ; do \
		if test -f $(DESTDIR)$(E2DATADIR)/$$l ; then \
			echo "$(INSTALL_DATA) $(DESTDIR)$(E2DATADIR)/$$l $(DESTDIR)$(E2DATADIR)/$$l.sample"; \
			$(INSTALL_DATA) $(DESTDIR)$(E2DATADIR)/$$l $(DESTDIR)$(E2DATADIR)/$$l.sample; \
		fi; \
	done


uninstall-local:
	for l in $(FLISTS) ; do \
		rm -f $(DESTDIR)$(E2DATADIR)/$$l ; \
	done
