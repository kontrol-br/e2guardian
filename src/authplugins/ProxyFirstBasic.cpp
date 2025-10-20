// ProxyFirstBasic auth plugin
//
// Plugin for use where e2g is behind squid and squid sends user in basic 
// format

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include "../Auth.hpp"
#include "../OptionContainer.hpp"
#include "../NaughtyFilter.hpp"
#include "../StoryBoard.hpp"

#include <syslog.h>
#include <iostream>

extern bool is_daemonised;
extern OptionContainer o;
extern thread_local std::string thread_id;

// DECLARATIONS

// class name is relevant!
class pf_basic_instance : public AuthPlugin
{
    public:
    pf_basic_instance(ConfigVar &definition)
        : AuthPlugin(definition)
    {
        needs_proxy_query = false;
        client_ip_based = false;
    };
    int identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user, auth_rec &authrec);
    int determineGroup(std::string &user, int &rfg, StoryBoard &story, NaughtyFilter &cm) override;
    int init(void *args);
};

// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

AuthPlugin *PF_basic_create(ConfigVar &definition)
{
    return new pf_basic_instance(definition);
}

// end of Class factory

// proxy auth header username extraction
int pf_basic_instance::identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user, auth_rec &authrec)
{
    // don't match for non-basic auth types
    String raw_type(h.getAuthType());
    // [PROXYBASIC_DEBUG] Informando inicio do processamento identify do proxy-basic.
    proxy_basic_debug_log("%sIniciando identify do proxy-basic: auth_type='%s' raw_auth='%s'", thread_id.c_str(),
                          raw_type.toCharArray(), h.getRawAuthData().c_str());

    String t(raw_type);
    t.toLower();
    if (t == "basic") {
        // extract username
        string = h.getAuthData();
        // [PROXYBASIC_DEBUG] Registrando credencial BASIC apos decodificacao.
        proxy_basic_debug_log("%sCredencial BASIC decodificada: '%s'", thread_id.c_str(), string.c_str());
        if (string.length() > 0) {
            string.resize(string.find_first_of(':'));
            authrec.user_name = string;
            authrec.user_source = "pf_basic";
            is_real_user = true;
            // [PROXYBASIC_DEBUG] Informando usuario obtido do cabecalho Proxy-Authorization.
            proxy_basic_debug_log("%sUsuario obtido do cabecalho Proxy-Authorization: '%s'", thread_id.c_str(), string.c_str());
            return E2AUTH_OK;
        }
    }

    // [PROXYBASIC_DEBUG] Indicando tentativa de extrair usuario do cabecalho X-Forwarded-For.
    proxy_basic_debug_log("%sTentando extrair usuario do cabecalho X-Forwarded-For", thread_id.c_str());
    std::string forwarded_user;
    if (extract_forwarded_user(h, forwarded_user)) {
        string = forwarded_user;
        authrec.user_name = string;
        authrec.user_source = "forwarded";
        is_real_user = true;
        // [PROXYBASIC_DEBUG] Informando usuario obtido do X-Forwarded-For.
        proxy_basic_debug_log("%sUsuario obtido do X-Forwarded-For: '%s'", thread_id.c_str(), string.c_str());
        return E2AUTH_OK;
    }

    // [PROXYBASIC_DEBUG] Registrando ausencia de credenciais validas apos todas as tentativas.
    proxy_basic_debug_log("%sNenhuma credencial valida encontrada para proxy-basic", thread_id.c_str());
    return E2AUTH_NOMATCH;
}

int pf_basic_instance::determineGroup(std::string &user, int &rfg, StoryBoard &story, NaughtyFilter &cm)
{
    if (user.length() < 1 || user == "-")
        return E2AUTH_NOMATCH;

    // [PROXYBASIC_DEBUG] Registrando usuario recebido para determinacao de grupo no plugin.
    proxy_basic_debug_log("%sdetermineGroup (proxy-basic) recebeu usuario '%s'", thread_id.c_str(), user.c_str());
    std::string normalised = normalise_auth_username(user);
    if (normalised.empty())
        return E2AUTH_NOMATCH;

    // [PROXYBASIC_DEBUG] Registrando resultado da normalizacao antes de converter para minusculas.
    proxy_basic_debug_log("%sUsuario apos normalizacao (antes do lower-case): '%s'", thread_id.c_str(), normalised.c_str());
    String lowered(normalised.c_str());
    lowered.toLower();
    user = lowered.toCharArray();

    // [PROXYBASIC_DEBUG] Informando usuario apos conversao para minusculas no determineGroup.
    proxy_basic_debug_log("%sUsuario apos conversao para minusculas no determineGroup do proxy-basic: '%s'",
                          thread_id.c_str(), user.c_str());

    cm.user = user;

    if (!story.runFunctEntry(story_entry, cm)) {
        int default_group = get_default(!cm.request_header->isProxyRequest);
        if (default_group > 0) {
            rfg = default_group - 1;
            cm.filtergroup = rfg;
            // [PROXYBASIC_DEBUG] Indicando aplicacao do grupo padrao devido a ausencia de correspondencia.
            proxy_basic_debug_log("%sUsuario nao localizado; aplicando grupo padrao %d no proxy-basic", thread_id.c_str(), rfg);
            if (cm.authrec != nullptr) {
                cm.authrec->group_source = cv["plugname"];
                cm.authrec->filter_group = rfg;
                if (cm.authrec->user_name.length() == 0)
                    cm.authrec->user_name = user;
            }
            return E2AUTH_OK;
        }
#ifdef E2DEBUG
        std::cerr << thread_id << "User not in filter groups list for: " << cv["plugname"].c_str() << std::endl;
#endif
        // [PROXYBASIC_DEBUG] Informando que o usuario nao foi encontrado nas listas do plugin.
        proxy_basic_debug_log("%sUsuario '%s' nao encontrado nas listas do proxy-basic", thread_id.c_str(), user.c_str());
        return E2AUTH_NOGROUP;
    }

    rfg = cm.filtergroup;
    // [PROXYBASIC_DEBUG] Registrando grupo atribuido ao usuario pelo proxy-basic.
    proxy_basic_debug_log("%sUsuario '%s' associado ao grupo %d pelo proxy-basic", thread_id.c_str(), user.c_str(), rfg);
    if (cm.authrec != nullptr) {
        cm.authrec->group_source = cv["plugname"];
        cm.authrec->filter_group = rfg;
        if (cm.authrec->user_name.length() == 0)
            cm.authrec->user_name = user;
        cm.authrec->is_authed = true;
    }

    return E2AUTH_OK;
}

int pf_basic_instance::init(void *args)
{
    OptionContainer::auth_entry sen;
    sen.entry_function = cv["story_function"];
    if (sen.entry_function.length() > 0) {
        sen.entry_id = ENT_STORYA_AUTH_PF_BASIC;
        story_entry = sen.entry_id;
        o.auth_entry_dq.push_back(sen);
        read_def_fg();
        return 0;
    } else {
        if (!is_daemonised)
            std::cerr << thread_id << "No story_function defined in proxy auth plugin config" << std::endl;
        syslog(LOG_ERR, "No story_function defined in proxy auth plugin config");
        return -1;
    }
}

