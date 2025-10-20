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
#include <cstdio>
#include <sstream>
#include <vector>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <sys/stat.h>
#include <unistd.h>

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

namespace
{
constexpr const char *kDebugLogPath = "/var/log/e2guardian/debug.log";
std::mutex debug_log_mutex;
int debug_log_fd = -1;

void append_debug_log(const std::string &message)
{
    std::lock_guard<std::mutex> lock(debug_log_mutex);
    if (debug_log_fd == -1) {
        debug_log_fd = open(kDebugLogPath, O_WRONLY | O_CREAT | O_APPEND, 0640);
        if (debug_log_fd == -1) {
            syslog(LOG_ERR, "%sUnable to open %s for debug logging: %s", thread_id.c_str(), kDebugLogPath, strerror(errno));
            return;
        }
    }

    ssize_t ignored = write(debug_log_fd, message.c_str(), message.size());
    (void)ignored;
}
}

thread_local bool proxy_basic_debug_scope_flag = false;

// [PROXYBASIC_DEBUG] Escreve mensagens de rastreamento no arquivo dedicado.
void proxy_basic_debug_log(const char *fmt, ...)
{
    if (!proxy_basic_debug_scope_flag)
        return;

    char stack_buffer[1024];
    va_list args;
    va_start(args, fmt);
    va_list args_copy;
    va_copy(args_copy, args);
    int needed = vsnprintf(stack_buffer, sizeof(stack_buffer), fmt, args_copy);
    va_end(args_copy);

    std::string message;
    if (needed < 0) {
        message = "Falha ao formatar mensagem de debug";
    } else if (static_cast<size_t>(needed) < sizeof(stack_buffer)) {
        message.assign(stack_buffer, static_cast<size_t>(needed));
    } else {
        std::vector<char> dynamic_buffer(static_cast<size_t>(needed) + 1, '\0');
        va_list args_retry;
        va_copy(args_retry, args);
        vsnprintf(dynamic_buffer.data(), dynamic_buffer.size(), fmt, args_retry);
        va_end(args_retry);
        message.assign(dynamic_buffer.data());
    }
    va_end(args);

    std::string formatted = "[PROXYBASIC_DEBUG] ";
    formatted += message;
    formatted.push_back('\n');

    append_debug_log(formatted);
}

// [GROUPTRACE_DEBUG] Emite mensagens de rastreamento sobre atribuicao de grupos.
void group_trace_debug_log(const char *fmt, ...)
{
    char stack_buffer[1024];
    va_list args;
    va_start(args, fmt);
    va_list args_copy;
    va_copy(args_copy, args);
    int needed = vsnprintf(stack_buffer, sizeof(stack_buffer), fmt, args_copy);
    va_end(args_copy);

    std::string message;
    if (needed < 0) {
        message = "Falha ao formatar mensagem de rastreamento de grupos";
    } else if (static_cast<size_t>(needed) < sizeof(stack_buffer)) {
        message.assign(stack_buffer, static_cast<size_t>(needed));
    } else {
        std::vector<char> dynamic_buffer(static_cast<size_t>(needed) + 1, '\0');
        va_list args_retry;
        va_copy(args_retry, args);
        vsnprintf(dynamic_buffer.data(), dynamic_buffer.size(), fmt, args_retry);
        va_end(args_retry);
        message.assign(dynamic_buffer.data());
    }
    va_end(args);

    std::string tagged_message = std::string("[GROUPTRACE_DEBUG] ") + message;
    std::string formatted = thread_id + tagged_message + '\n';
    if (!is_daemonised) {
        std::cerr << formatted << std::flush;
    }
    append_debug_log(formatted);
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
    // [PROXYBASIC_DEBUG] Registrando recebimento do usuario bruto para normalizacao.
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

    // [PROXYBASIC_DEBUG] Registrando resultado da normalizacao antes de alterar caixa.
    proxy_basic_debug_log("%sUsuario apos normalizacao sem alterar caixa: '%s'", thread_id.c_str(), result.c_str());

    return result;
}

bool extract_forwarded_user(HTTPHeader &h, std::string &username)
{
    std::string forwarded = h.getXForwardedForIP();
    // [PROXYBASIC_DEBUG] Registrando conteudo bruto do cabecalho X-Forwarded-For.
    proxy_basic_debug_log("%sCabecalho X-Forwarded-For bruto: '%s'", thread_id.c_str(), forwarded.c_str());

    if (forwarded.empty()) {
        // [PROXYBASIC_DEBUG] Avisando ausencia do cabecalho X-Forwarded-For.
        proxy_basic_debug_log("%sCabecalho X-Forwarded-For ausente ou vazio", thread_id.c_str());
        return false;
    }

    std::stringstream stream(forwarded);
    std::string token;
    std::string candidate;
    while (std::getline(stream, token, ',')) {
        std::string trimmed = trim_copy(token);
        // [PROXYBASIC_DEBUG] Rastreamento de cada token analisado no X-Forwarded-For.
        proxy_basic_debug_log("%sToken X-Forwarded-For analisado: '%s'", thread_id.c_str(), trimmed.c_str());
        if (!trimmed.empty())
            candidate = trimmed;
    }

    if (candidate.empty()) {
        // [PROXYBASIC_DEBUG] Informando que nao foi encontrado token valido no cabecalho.
        proxy_basic_debug_log("%sNenhum candidato encontrado no cabecalho X-Forwarded-For", thread_id.c_str());
        return false;
    }

    if (is_likely_ip(candidate)) {
        // [PROXYBASIC_DEBUG] Indicando que o token final parece endereco IP e sera ignorado.
        proxy_basic_debug_log("%sUltimo token do X-Forwarded-For parece um IP ('%s'), ignorando", thread_id.c_str(), candidate.c_str());
        return false;
    }

    username = candidate;
    // [PROXYBASIC_DEBUG] Informando usuario obtido do X-Forwarded-For.
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
    // [PROXYBASIC_DEBUG] Iniciando determinacao de grupo para o usuario informado.
    proxy_basic_debug_log("%sInicio determineGroup para plugin '%s' com usuario bruto '%s'", thread_id.c_str(),
                          pluginName.toCharArray(), user.c_str());
    if (user.length() < 1 || user == "-") {
        // [PROXYBASIC_DEBUG] Indicando usuario invalido recebido.
        proxy_basic_debug_log("%sUsuario invalido para determineGroup (vazio ou '-')", thread_id.c_str());
        return E2AUTH_NOMATCH;
    }
    user = normalise_auth_username(user);
    String u(user);
    String lastcategory;
    u.toLower(); // since the filtergroupslist is read in in lowercase, we should do this.
    user = u.toCharArray(); // also pass back to ConnectionHandler, so appears lowercase in logs
    // [PROXYBASIC_DEBUG] Registrando usuario apos conversao para minusculas.
    proxy_basic_debug_log("%sUsuario apos conversao para minusculas: '%s'", thread_id.c_str(), user.c_str());
    std::string entry_function_name;
    std::string entry_file_name;
    unsigned int entry_index = story_entry >= 0 ? static_cast<unsigned int>(story_entry) : 0;
    bool has_entry_info = story_entry >= 0 && story.getEntryDebugInfo(entry_index, entry_function_name, entry_file_name);
    const char *function_label = (has_entry_info && !entry_function_name.empty()) ? entry_function_name.c_str() : "<desconhecido>";
    const char *file_label = (has_entry_info && !entry_file_name.empty()) ? entry_file_name.c_str() : "<desconhecido>";
    int fg_before_lookup = fg;
    // [GROUPTRACE_DEBUG] Inicio do rastreamento da determinacao de grupo.
    group_trace_debug_log("Plugin '%s' avaliara usuario '%s' usando entrada %d (funcao='%s', arquivo='%s', fg_atual=%d)",
                         pluginName.toCharArray(), user.c_str(), story_entry, function_label, file_label, fg_before_lookup);
    //  String ue(u);
    //  ue += "=";

    //char *i = ldl->filter_groups_list.findStartsWithPartial(ue.toCharArray(), lastcategory);
    //   char *i = uglc.findStartsWithPartial(ue.toCharArray(), lastcategory);
    cm.user = user;
    if (!story.runFunctEntry(story_entry, cm)) {
        int t = get_default(!cm.request_header->isProxyRequest);
        if (t > 0) {
            fg = --t;
            // [PROXYBASIC_DEBUG] Indicando aplicacao do grupo padrao por falta de correspondencia.
            proxy_basic_debug_log("%sUsuario nao encontrado; aplicando grupo padrao %d", thread_id.c_str(), fg);
            // [GROUPTRACE_DEBUG] Nenhuma correspondencia encontrada; aplicando grupo padrao.
            group_trace_debug_log("Plugin '%s' nao encontrou grupo para '%s' (entrada %d, funcao='%s', arquivo='%s'); usando padrao=%d",
                                  pluginName.toCharArray(), user.c_str(), story_entry, function_label, file_label, fg);
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
        // [PROXYBASIC_DEBUG] Informando ausencia do usuario nas listas de grupos.
        proxy_basic_debug_log("%sUsuario nao localizado em listas de grupos para plugin '%s'", thread_id.c_str(),
                              pluginName.toCharArray());
        // [GROUPTRACE_DEBUG] Falha ao localizar grupo sem padrao configurado.
        group_trace_debug_log("Plugin '%s' nao encontrou grupo para '%s' e nao ha padrao configurado (entrada %d, funcao='%s', arquivo='%s')",
                              pluginName.toCharArray(), user.c_str(), story_entry, function_label, file_label);
        return E2AUTH_NOGROUP;
    }

#ifdef E2DEBUG
    std::cerr << "Group found for: " << user.c_str() << " in " << pluginName.c_str() << std::endl;
#endif
    fg = cm.filtergroup;
    // [PROXYBASIC_DEBUG] Registrando grupo atribuido ao usuario pelo plugin.
    proxy_basic_debug_log("%sUsuario associado ao grupo %d pelo plugin '%s'", thread_id.c_str(), fg, pluginName.toCharArray());
    // [GROUPTRACE_DEBUG] Grupo encontrado com sucesso.
    group_trace_debug_log("Plugin '%s' atribuiu grupo %d ao usuario '%s' (entrada %d, funcao='%s', arquivo='%s', fg_anterior=%d)",
                          pluginName.toCharArray(), fg, user.c_str(), story_entry, function_label, file_label, fg_before_lookup);
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
