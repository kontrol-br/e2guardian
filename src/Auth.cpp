// AuthPlugin class - interface for plugins for retrieving client usernames
// and filter group membership

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "Auth.hpp"
#include "OptionContainer.hpp"
#include "LOptionContainer.hpp"

#include <iostream>
#include <syslog.h>
#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <sstream>
#include <arpa/inet.h>

// GLOBALS

extern OptionContainer o;
extern thread_local std::string thread_id;
extern bool is_daemonised;

extern authcreate_t proxycreate;
extern authcreate_t digestcreate;
extern authcreate_t identcreate;
extern authcreate_t ipcreate;
extern authcreate_t portcreate;
extern authcreate_t headercreate;
extern authcreate_t PF_basic_create;

#ifdef PRT_DNSAUTH
extern authcreate_t dnsauthcreate;
#endif

#ifdef ENABLE_NTLM
extern authcreate_t ntlmcreate;
#endif

namespace
{
std::string trim_copy(const std::string &value)
{
    auto begin = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) { return std::isspace(ch); });
    auto end = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) { return std::isspace(ch); }).base();
    if (begin >= end)
        return std::string();
    return std::string(begin, end);
}

bool is_likely_ip(const std::string &token)
{
    if (token.empty())
        return false;

    struct in_addr v4;
    if (inet_pton(AF_INET, token.c_str(), &v4) == 1)
        return true;

#ifdef AF_INET6
    struct in6_addr v6;
    if (inet_pton(AF_INET6, token.c_str(), &v6) == 1)
        return true;
#endif

    return false;
}
}

thread_local bool proxy_basic_debug_scope_flag = false;

void proxy_basic_debug_log(const char *fmt, ...)
{
    if (!proxy_basic_debug_scope_flag)
        return;

    std::string format = "[PROXYBASIC_DEBUG] ";
    format += fmt;

    va_list args;
    va_start(args, fmt);
    vsyslog(LOG_INFO, format.c_str(), args);
    va_end(args);
}

ProxyBasicDebugScope::ProxyBasicDebugScope(bool enable)
    : previous_(proxy_basic_debug_scope_flag)
{
    if (enable)
        proxy_basic_debug_scope_flag = true;
}

ProxyBasicDebugScope::~ProxyBasicDebugScope()
{
    proxy_basic_debug_scope_flag = previous_;
}

std::string normalise_auth_username(const std::string &raw)
{
    proxy_basic_debug_log("%sRecebido usuario bruto para normalizacao: '%s'", thread_id.c_str(), raw.c_str());

    std::string result = trim_copy(raw);
    if (result.empty())
        return result;

    size_t slash_pos = result.find_last_of("\\/");
    if (slash_pos != std::string::npos && slash_pos + 1 < result.size())
        result = result.substr(slash_pos + 1);

    size_t at_pos = result.find('@');
    if (at_pos != std::string::npos)
        result = result.substr(0, at_pos);

    // Remove surrounding quotes if present.
    if (result.size() > 1 && ((result.front() == '"' && result.back() == '"') || (result.front() == '\'' && result.back() == '\'')))
        result = result.substr(1, result.size() - 2);

    result = trim_copy(result);

    proxy_basic_debug_log("%sUsuario apos normalizacao sem alterar caixa: '%s'", thread_id.c_str(), result.c_str());

    return result;
}

bool extract_forwarded_user(HTTPHeader &h, std::string &username)
{
    std::string forwarded = h.getXForwardedForIP();
    proxy_basic_debug_log("%sCabecalho X-Forwarded-For bruto: '%s'", thread_id.c_str(), forwarded.c_str());

    if (forwarded.empty()) {
        proxy_basic_debug_log("%sCabecalho X-Forwarded-For ausente ou vazio", thread_id.c_str());
        return false;
    }

    std::stringstream stream(forwarded);
    std::string token;
    std::string candidate;
    while (std::getline(stream, token, ',')) {
        std::string trimmed = trim_copy(token);
        proxy_basic_debug_log("%sToken X-Forwarded-For analisado: '%s'", thread_id.c_str(), trimmed.c_str());
        if (!trimmed.empty())
            candidate = trimmed;
    }

    if (candidate.empty()) {
        proxy_basic_debug_log("%sNenhum candidato encontrado no cabecalho X-Forwarded-For", thread_id.c_str());
        return false;
    }

    if (is_likely_ip(candidate)) {
        proxy_basic_debug_log("%sUltimo token do X-Forwarded-For parece um IP ('%s'), ignorando", thread_id.c_str(), candidate.c_str());
        return false;
    }

    username = candidate;
    proxy_basic_debug_log("%sUsuario extraido do X-Forwarded-For: '%s'", thread_id.c_str(), username.c_str());
    return true;
}

// IMPLEMENTATION

AuthPlugin::AuthPlugin(ConfigVar &definition)
    : is_connection_based(false), needs_proxy_query(false)
{
    cv = definition;
    pluginName = cv["plugname"];
}

int AuthPlugin::init(void *args)
{
    read_def_fg();
    return 0;
}

int AuthPlugin::quit()
{
    return 0;
}

String AuthPlugin::getPluginName()
{
    return pluginName;
}

// determine what filter group the given username is in
// return -1 when user not found
int AuthPlugin::determineGroup(std::string &user, int &fg, StoryBoard & story, NaughtyFilter &cm )
{
    proxy_basic_debug_log("%sInicio determineGroup para plugin '%s' com usuario bruto '%s'", thread_id.c_str(),
                          pluginName.toCharArray(), user.c_str());
    if (user.length() < 1 || user == "-") {
        proxy_basic_debug_log("%sUsuario invalido para determineGroup (vazio ou '-')", thread_id.c_str());
        return E2AUTH_NOMATCH;
    }
    user = normalise_auth_username(user);
    String u(user);
    String lastcategory;
    u.toLower(); // since the filtergroupslist is read in in lowercase, we should do this.
    user = u.toCharArray(); // also pass back to ConnectionHandler, so appears lowercase in logs
    proxy_basic_debug_log("%sUsuario apos conversao para minusculas: '%s'", thread_id.c_str(), user.c_str());
    //  String ue(u);
    //  ue += "=";

    //char *i = ldl->filter_groups_list.findStartsWithPartial(ue.toCharArray(), lastcategory);
    //   char *i = uglc.findStartsWithPartial(ue.toCharArray(), lastcategory);
    cm.user = user;
    if (!story.runFunctEntry(story_entry, cm)) {
        int t = get_default(!cm.request_header->isProxyRequest);
        if (t > 0) {
            fg = --t;
            proxy_basic_debug_log("%sUsuario nao encontrado; aplicando grupo padrao %d", thread_id.c_str(), fg);
            if (cm.authrec != nullptr) {
                cm.authrec->filter_group = fg;
                cm.authrec->group_source = "pdef";
                if (cm.authrec->user_name.length() == 0)
                    cm.authrec->user_name = user;
            }
            return E2AUTH_OK;
        }
#ifdef E2DEBUG
        std::cerr << "User not in filter groups list for: " << pluginName.c_str() << std::endl;
#endif
        proxy_basic_debug_log("%sUsuario nao localizado em listas de grupos para plugin '%s'", thread_id.c_str(),
                              pluginName.toCharArray());
        return E2AUTH_NOGROUP;
    }

#ifdef E2DEBUG
    std::cerr << "Group found for: " << user.c_str() << " in " << pluginName.c_str() << std::endl;
#endif
    fg = cm.filtergroup;
    proxy_basic_debug_log("%sUsuario associado ao grupo %d pelo plugin '%s'", thread_id.c_str(), fg, pluginName.toCharArray());
    if (cm.authrec != nullptr) {
        cm.authrec->filter_group = fg;
        if (cm.authrec->user_name.length() == 0)
            cm.authrec->user_name = user;
        cm.authrec->is_authed = true;
    }
    return E2AUTH_OK;
}

// take in a configuration file, find the AuthPlugin class associated with the plugname variable, and return an instance
AuthPlugin *auth_plugin_load(const char *pluginConfigPath)
{
    ConfigVar cv;

    if (cv.readVar(pluginConfigPath, "=") > 0) {
        if (!is_daemonised) {
            std::cerr << thread_id << "Unable to load plugin config: " << pluginConfigPath << std::endl;
        }
        syslog(LOG_ERR, "%sUnable to load plugin config %s", thread_id.c_str(), pluginConfigPath);
        return NULL;
    }

    String plugname(cv["plugname"]);
    if (plugname.length() < 1) {
        if (!is_daemonised) {
            std::cerr << thread_id << "Unable read plugin config plugname variable: " << pluginConfigPath << std::endl;
        }
        syslog(LOG_ERR, "%sUnable read plugin config plugname variable %s", thread_id.c_str(), pluginConfigPath);
        return NULL;
    }

    if (plugname == "proxy-basic") {
#ifdef E2DEBUG
        std::cerr << thread_id << "Enabling proxy-basic auth plugin" << std::endl;
#endif
        return proxycreate(cv);
    }

    if (plugname == "proxy-digest") {
#ifdef E2DEBUG
        std::cerr << thread_id << "Enabling proxy-digest auth plugin" << std::endl;
#endif
        return digestcreate(cv);
    }

    if (plugname == "ident") {
#ifdef E2DEBUG
        std::cerr << thread_id << "Enabling ident server auth plugin" << std::endl;
#endif
        return identcreate(cv);
    }

    if (plugname == "ip") {
#ifdef E2DEBUG
        std::cerr << thread_id << "Enabling IP-based auth plugin" << std::endl;
#endif
        return ipcreate(cv);
    }

    if (plugname == "port") {
#ifdef E2DEBUG
        std::cerr << thread_id << "Enabling port-based auth plugin" << std::endl;
#endif
        return portcreate(cv);
    }

    if (plugname == "proxy-header") {
#ifdef E2DEBUG
        std::cerr << thread_id << "Enabling proxy-header auth plugin" << std::endl;
#endif
        return headercreate(cv);
    }

    if (plugname == "pf-basic") {
#ifdef E2DEBUG
        std::cerr << thread_id << "Enabling proxy-header auth plugin" << std::endl;
#endif
        return PF_basic_create(cv);
    }

#ifdef PRT_DNSAUTH
    if (plugname == "dnsauth") {
#ifdef E2DEBUG
        std::cerr << thread_id << "Enabling DNS-based auth plugin" << std::endl;
#endif
        return dnsauthcreate(cv);
    }
#endif

#ifdef ENABLE_NTLM
    if (plugname == "proxy-ntlm") {
#ifdef E2DEBUG
        std::cerr << thread_id << "Enabling proxy-NTLM auth plugin" << std::endl;
#endif
        return ntlmcreate(cv);
    }
#endif


    if (!is_daemonised) {
        std::cerr << thread_id << "Unable to load plugin: " << pluginConfigPath << std::endl;
    }
    syslog(LOG_ERR, "%sUnable to load plugin %s", thread_id.c_str(), pluginConfigPath);
    return NULL;
}

int AuthPlugin::get_default(bool is_transparent) {
    if (is_transparent && tran_default_fg > 0) {
       // syslog(LOG_ERR, "%spa default set as %d", thread_id.c_str(), tran_default_fg);
        return tran_default_fg;
    }
    else if (default_fg > 0) {
        //syslog(LOG_ERR, "%spa default set as %d", thread_id.c_str(), default_fg);
        return default_fg;
    }
    return 0;
}

void AuthPlugin::read_def_fg() {
   // syslog(LOG_ERR, "%sloading def_fg plugin ....", thread_id.c_str());
    String t = cv["defaultfiltergroup"];
    //syslog(LOG_ERR, "%sdef_fg string is %s", thread_id.c_str(), t.c_str());
    int i = t.toInteger();
    //syslog(LOG_ERR, "%sdef_fg int is %d", thread_id.c_str(), i);
    if(i > 0 && i <= o.filter_groups) {
        default_fg = i;
        //syslog(LOG_ERR, "%sdeffg loaded as %d", thread_id.c_str(), default_fg);
    }
    t = cv["defaulttransparentfiltergroup"];
    i = t.toInteger();
    if(i > 0 && i <= o.filter_groups) {
        tran_default_fg = i;
        //syslog(LOG_ERR, "%strandeffg loaded as %d", thread_id.c_str(), tran_default_fg);
    }
}
