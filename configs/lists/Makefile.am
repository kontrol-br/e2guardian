DISTCLEANFILES = Makefile.in 

E2DATADIR = $(E2CONFDIR)/lists

SUBDIRS = oldphraselists phraselists . authplugins rooms bannedrooms common example.group

if NEED_CSLISTS
SUBDIRS += contentscanners
endif
if NEED_DMLISTS
SUBDIRS += downloadmanagers
endif

WLISTS = README

ROOT_SAMPLE_LISTS = addheaderregexplist \
	authexceptioniplist authexceptionsitelist authexceptionsiteiplist \
	authexceptionurllist bannedclientlist bannedextensionlist \
	bannediplist bannedmimetypelist bannedphraselist \
	bannedregexpheaderlist bannedregexpurllist \
	bannedregexpuseragentlist bannedsearchlist \
	bannedsearchoveridelist bannedsiteiplist bannedsitelist \
	bannedsslsiteiplist bannedsslsitelist bannedurllist \
	contentregexplist embededreferersiteiplist \
	embededreferersitelist embededrefererurllist \
	exceptionclientlist exceptionextensionlist exceptionfilesiteiplist \
	exceptionfilesitelist exceptionfileurllist exceptioniplist \
	exceptionmimetypelist exceptionphraselist exceptionregexpheaderlist \
	exceptionregexpurllist exceptionregexpuseragentlist exceptionsiteiplist \
	exceptionsitelist exceptionurllist filtergroupslist greysiteiplist \
	greysitelist greysslsiteiplist greysslsitelist greyurllist \
	headerregexplist localbannedsearchlist localbannedsiteiplist \
	localbannedsitelist localbannedsslsiteiplist localbannedsslsitelist \
	localbannedurllist localexceptionsiteiplist localexceptionsitelist \
	localexceptionurllist localgreysiteiplist localgreysitelist \
	localgreysslsiteiplist localgreysslsitelist localgreyurllist \
	logregexpurllist logsiteiplist logsitelist logurllist \
	newbannedphraselist newexceptionphraselist newweightedphraselist \
	nocheckcertsiteiplist nocheckcertsitelist refererexceptionsiteiplist \
	refererexceptionsitelist refererexceptionurllist searchregexplist \
	sslsiteregexplist urlredirectregexplist urlregexplist weightedphraselist
 
EXTRA_DIST = 

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(E2DATADIR) && \
		for l in $(WLISTS) ; do \
		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l"; \
		$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l; \
	done
	$(mkinstalldirs) $(DESTDIR)$(E2DATADIR) && \
	for l in $(ROOT_SAMPLE_LISTS) ; do \
		src_name=$$l; \
		case $$l in \
			newbannedphraselist) src_name=bannedphraselist ;; \
			newexceptionphraselist) src_name=exceptionphraselist ;; \
			newweightedphraselist) src_name=weightedphraselist ;; \
		esac; \
		src_path=; \
		for d in $(DESTDIR)$(E2CONFDIR)/lists/example.group \
		         $(DESTDIR)$(E2CONFDIR)/lists/common \
		         $(DESTDIR)$(E2CONFDIR)/lists/authplugins; do \
			if test -f $$d/$$src_name ; then \
				src_path=$$d/$$src_name; \
				break; \
			fi; \
		done; \
		if test -z "$$src_path" ; then \
			echo "Missing list $$src_name for root sample $$l"; \
			exit 1; \
		fi; \
		echo "$(INSTALL_DATA) $$src_path $(DESTDIR)$(E2DATADIR)/$$l.sample"; \
		$(INSTALL_DATA) $$src_path $(DESTDIR)$(E2DATADIR)/$$l.sample; \
	done


uninstall-local:
	for l in $(WLISTS) ; do \
		rm -f $(DESTDIR)$(E2DATADIR)/$$l ; \
	done
