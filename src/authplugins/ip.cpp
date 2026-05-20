// IP (range, subnet) auth plugin
// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include "../Auth.hpp"
#include "../RegExp.hpp"
#include "../OptionContainer.hpp"

#include "../NaughtyFilter.hpp"
#include "../StoryBoard.hpp"

#include <syslog.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <arpa/inet.h>
#include <unistd.h>
#include <list>
#include <vector>
#include <cctype>
#include <sys/stat.h>
#include <sys/types.h>
#include <cerrno>
#include <cstring>
#include <mutex>
#include <cstdio>

// GLOBALS

extern bool is_daemonised;
extern OptionContainer o;
extern thread_local std::string thread_id;

// DECLARATIONS

namespace
{
enum class SpecialIpGroup;
}

// structs linking subnets and IP ranges to filter groups
struct ip_subnet_entry
{
    uint32_t maskedaddr;
    uint32_t mask;
    int group;
};

struct ip_range_entry
{
    uint32_t startaddr;
    uint32_t endaddr;
    int group;
};

// class for linking IPs to filter groups, complete with comparison operators
// allowing standard C++ sort to work
class ip
{
    public:
    ip(uint32_t a, int g)
    {
        addr = a;
        group = g;
    };
    uint32_t addr;
    int group;
    int operator<(const ip &a) const
    {
        return addr < a.addr;
    };
    int operator<(const uint32_t &a) const
    {
        return addr < a;
    };
    int operator==(const uint32_t &a) const
    {
        return a == addr;
    };
};

// class name is relevant!
class ipinstance : public AuthPlugin
{
    public:
    // keep credentials for the whole of a connection - IP isn't going to change.
    // not quite true - what about downstream proxy with x-forwarded-for?
    ipinstance(ConfigVar &definition)
        : AuthPlugin(definition)
    {
        if (!o.use_xforwardedfor)
            is_connection_based = true;
        client_ip_based = true;
    };

    int identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user, auth_rec &authrec) override;
    int determineGroup(std::string &user, int &rfg, StoryBoard &story, NaughtyFilter &cm) override;

    int init(void *args) override;
    int quit() override;

    private:
    std::vector<ip> iplist;
    std::list<ip_subnet_entry> ipsubnetlist;
    std::list<ip_range_entry> iprangelist;
    std::string ipgroups_path_;
    bool ipgroups_loaded_ = false;
    bool ipgroups_parse_error_logged_ = false;
    int ipgroups_reload_id_ = -1;
    bool xff_no_filter_warned_ = false;
    std::mutex ipgroups_mutex_;

    bool ensureIPGroupsLoadedLocked();
    int readIPMelangeList(const char *filename,
                          std::vector<ip> *iplist_out = nullptr,
                          std::list<ip_subnet_entry> *ipsubnetlist_out = nullptr,
                          std::list<ip_range_entry> *iprangelist_out = nullptr);
    int searchList(int a, int s, const uint32_t &ip);
    int inList(const uint32_t &ip);
    int inSubnet(const uint32_t &ip);
    int inRange(const uint32_t &ip);
    int parseFilterGroup(const String &value, const char *filename, const String &line, bool &warn, SpecialIpGroup &special_out);
};

// IMPLEMENTATION

namespace
{
enum class SpecialIpGroup
{
    None,
    Exception,
    Banned
};

constexpr int kHiddenExceptionGroup = -2;
constexpr int kHiddenBannedGroup = -3;

SpecialIpGroup classify_special_group(String token)
{
    token.toLower();
    token.removeWhiteSpace();
    token.removePunctuation();
    token.removeChar('_');
    token.removeChar('-');

    if (token.length() == 0)
        return SpecialIpGroup::None;

    if ((token == "exceptioniplist") || (token == "exceptionlist") || (token == "exceptionip"))
        return SpecialIpGroup::Exception;

    if ((token == "bannediplist") || (token == "bannedlist") || (token == "bannedip"))
        return SpecialIpGroup::Banned;

    return SpecialIpGroup::None;
}

SpecialIpGroup decode_hidden_group(int group)
{
    if (group == kHiddenExceptionGroup)
        return SpecialIpGroup::Exception;
    if (group == kHiddenBannedGroup)
        return SpecialIpGroup::Banned;
    return SpecialIpGroup::None;
}

bool apply_hidden_group(SpecialIpGroup special, const std::string &user, NaughtyFilter &cm)
{
    if (special == SpecialIpGroup::None)
        return false;

    if (cm.authrec != nullptr) {
        cm.authrec->group_source = "ip";
        cm.authrec->filter_group = -1;
        cm.authrec->is_authed = true;
        if (cm.authrec->user_name.length() == 0)
            cm.authrec->user_name = user;
    }

    if (special == SpecialIpGroup::Exception) {
        cm.isexception = true;
        cm.isException = true;
        cm.special_exception_ip = true;
        cm.nomitm = true;
        cm.automitm = false;
    } else if (special == SpecialIpGroup::Banned) {
        cm.isBlocked = true;
        cm.isItNaughty = true;
        cm.special_banned_ip = true;
    }

    return true;
}

int ensure_directories(const std::string &path)
{
    if (path.empty())
        return 0;

    for (size_t pos = 1; pos < path.size(); ++pos) {
        if (path[pos] != '/')
            continue;

        std::string sub = path.substr(0, pos);
        if (sub.empty())
            continue;

        if (mkdir(sub.c_str(), 0755) == -1 && errno != EEXIST)
            return -1;
    }

    if (mkdir(path.c_str(), 0755) == -1 && errno != EEXIST)
        return -1;

    return 0;
}

bool copy_file(const std::string &source, const std::string &destination)
{
    std::ifstream in(source.c_str(), std::ios::binary);
    if (!in)
        return false;

    std::ofstream out(destination.c_str(), std::ios::binary | std::ios::trunc);
    if (!out)
        return false;

    out << in.rdbuf();
    return out.good();
}

std::string trim_copy(const std::string &value)
{
    std::string::size_type start = 0;
    std::string::size_type end = value.size();

    while (start < end && std::isspace(static_cast<unsigned char>(value[start])))
        ++start;

    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1])))
        --end;

    return value.substr(start, end - start);
}

std::string normalise_forwarded_ip(const std::string &value)
{
    if (value.empty())
        return value;

    std::string first = value;
    std::string::size_type comma = first.find(',');
    if (comma != std::string::npos)
        first = first.substr(0, comma);

    return trim_copy(first);
}

bool is_valid_ipv4_literal(const std::string &value)
{
    if (value.empty())
        return false;

    struct in_addr sin;
    return inet_aton(value.c_str(), &sin) != 0;
}

std::string select_first_valid_ip(const std::vector<std::string> &candidates)
{
    for (const auto &candidate : candidates) {
        std::string trimmed = trim_copy(candidate);
        if (!trimmed.empty() && is_valid_ipv4_literal(trimmed))
            return trimmed;
    }

    return "";
}
} // namespace

// class factory code *MUST* be included in every plugin

AuthPlugin *ipcreate(ConfigVar &definition)
{
    return new ipinstance(definition);
}

// end of Class factory

//
//
// Standard plugin funcs
//
//

// plugin quit - clear IP, subnet & range lists
int ipinstance::quit()
{
    std::lock_guard<std::mutex> guard(ipgroups_mutex_);
    iplist.clear();
    ipsubnetlist.clear();
    iprangelist.clear();
    ipgroups_path_.clear();
    ipgroups_loaded_ = false;
    ipgroups_parse_error_logged_ = false;
    ipgroups_reload_id_ = -1;
    return 0;
}

// plugin init - read in ip melange list
int ipinstance::init(void *args)
{
    OptionContainer::auth_entry sen;
    sen.entry_function = cv["story_function"];
    if (sen.entry_function.length() > 0) {
        sen.entry_id = ENT_STORYA_AUTH_IP;
        story_entry = sen.entry_id;
        o.auth_entry_dq.push_back(sen);
    } else {
        if (!is_daemonised)
            std::cerr << thread_id << "No story_function defined in IP auth plugin config" << std::endl;
        syslog(LOG_ERR, "No story_function defined in IP auth plugin config");
        return -1;
    }

    std::string ipgroups_path_value;
    String fname(cv["ipgroups"]);
    if (fname.length() > 0) {
        ipgroups_path_value = fname.toCharArray();
    } else {
        for (const auto &entry : o.ipmaplist_dq) {
            std::string token;
            std::string name;
            std::string path;
            std::stringstream ss(entry.toCharArray());
            while (std::getline(ss, token, ',')) {
                std::string::size_type start = token.find_first_not_of(" \t");
                if (start == std::string::npos)
                    continue;
                std::string::size_type end = token.find_last_not_of(" \t");
                std::string trimmed = token.substr(start, end - start + 1);
                if (trimmed.rfind("name=", 0) == 0) {
                    name = trimmed.substr(5);
                } else if (trimmed.rfind("path=", 0) == 0) {
                    path = trimmed.substr(5);
                }
            }
            if (!name.empty() && name == "ipmap" && !path.empty()) {
                ipgroups_path_value = path;
                break;
            }
        }
    }

    if (ipgroups_path_value.empty()) {
        std::string default_ipgroups = std::string(__CONFDIR) + "/lists/authplugins/ipgroups";
        ipgroups_path_value = default_ipgroups;

        if (access(default_ipgroups.c_str(), R_OK) == 0) {
            if (!is_daemonised)
                std::cerr << thread_id << "No ipgroups list defined for IP auth plugin, falling back to "
                          << ipgroups_path_value << std::endl;
            syslog(LOG_INFO, "No ipgroups list defined for IP auth plugin, falling back to %s", ipgroups_path_value.c_str());
        } else {
            if (!is_daemonised)
                std::cerr << thread_id << "No ipgroups list defined for IP auth plugin, creating default at "
                          << ipgroups_path_value << std::endl;
            syslog(LOG_INFO, "No ipgroups list defined for IP auth plugin, creating default at %s",
                   ipgroups_path_value.c_str());
        }
    }

    if (ipgroups_path_value.empty()) {
        if (!is_daemonised)
            std::cerr << thread_id << "No ipgroups file defined for IP auth plugin" << std::endl;
        syslog(LOG_ERR, "No ipgroups file defined for IP auth plugin");
        return -1;
    }

    if (access(ipgroups_path_value.c_str(), R_OK) != 0) {
        std::string directory;
        std::string::size_type separator = ipgroups_path_value.find_last_of('/');
        if (separator != std::string::npos)
            directory = ipgroups_path_value.substr(0, separator);

        if (!directory.empty()) {
            if (ensure_directories(directory) == -1) {
                int saved_errno = errno;
                if (!is_daemonised)
                    std::cerr << thread_id << "Unable to create directory for ipgroups file (" << directory
                              << "): " << strerror(saved_errno) << std::endl;
                syslog(LOG_ERR, "Unable to create directory for ipgroups file (%s): %s", directory.c_str(),
                       strerror(saved_errno));
                return -1;
            }
        }

        bool created = false;
        std::string sample_path = ipgroups_path_value + ".sample";
        errno = 0;
        if (access(sample_path.c_str(), R_OK) == 0) {
            created = copy_file(sample_path, ipgroups_path_value);
        } else {
            std::ofstream out(ipgroups_path_value.c_str(), std::ios::out | std::ios::trunc);
            if (out) {
                out << "# e2guardian ipgroups auto-generated" << std::endl;
                out << "# Formato: <filtro> <IP>/<mascara> ou <inicio>-<fim>" << std::endl;
                created = true;
            }
        }

        if (created) {
            if (!is_daemonised)
                std::cerr << thread_id << "Created default ipgroups file at " << ipgroups_path_value << std::endl;
            syslog(LOG_INFO, "Created default ipgroups file at %s", ipgroups_path_value.c_str());
        } else {
            int saved_errno = errno != 0 ? errno : EIO;
            if (!is_daemonised)
                std::cerr << thread_id << "Unable to create ipgroups file at " << ipgroups_path_value << ": "
                          << strerror(saved_errno) << std::endl;
            syslog(LOG_ERR, "Unable to create ipgroups file at %s: %s", ipgroups_path_value.c_str(), strerror(saved_errno));
            return -1;
        }
    }

    if (access(ipgroups_path_value.c_str(), R_OK) != 0) {
        int saved_errno = errno;
        if (!is_daemonised)
            std::cerr << thread_id << "ipgroups file not readable at " << ipgroups_path_value << ": "
                      << strerror(saved_errno) << std::endl;
        syslog(LOG_ERR, "ipgroups file not readable at %s: %s", ipgroups_path_value.c_str(), strerror(saved_errno));
        return -1;
    }

    std::vector<ip> new_iplist;
    std::list<ip_subnet_entry> new_ipsubnetlist;
    std::list<ip_range_entry> new_iprangelist;

    int read_result = readIPMelangeList(ipgroups_path_value.c_str(), &new_iplist, &new_ipsubnetlist, &new_iprangelist);
    if (read_result < 0)
        return read_result;

    {
        std::lock_guard<std::mutex> guard(ipgroups_mutex_);
        ipgroups_path_ = ipgroups_path_value;
        ipgroups_parse_error_logged_ = false;
        iplist.swap(new_iplist);
        ipsubnetlist.swap(new_ipsubnetlist);
        iprangelist.swap(new_iprangelist);
        ipgroups_loaded_ = true;
        if (auto lists = o.currentLists())
            ipgroups_reload_id_ = lists->reload_id;
        else
            ipgroups_reload_id_ = -1;
    }

    read_def_fg();
    return read_result;
}

// IP-based filter group determination
// never actually return NOUSER from this, because we don't actually look in the filtergroupslist.
// NOUSER stops ConnectionHandler from querying subsequent plugins.
int ipinstance::identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user, auth_rec &authrec)
{
    // we don't get usernames out of this plugin, just a filter group
    // for now, use the IP as the username
    bool use_xforwardedfor;
    use_xforwardedfor = false;
    if (o.use_xforwardedfor == 1) {
        if (o.xforwardedfor_filter_ip.size() > 0) {
            const char *ip = peercon.getPeerIP().c_str();
            for (unsigned int i = 0; i < o.xforwardedfor_filter_ip.size(); i++) {
                if (strcmp(ip, o.xforwardedfor_filter_ip[i].c_str()) == 0) {
                    use_xforwardedfor = true;
                    break;
                }
            }
        } else {
            if (!xff_no_filter_warned_) {
                if (!is_daemonised)
                    std::cerr << thread_id
                              << "IP auth plugin: usexforwardedfor is enabled with empty xforwardedforfilterip; "
                              << "trusting X-Forwarded-For from all peers" << std::endl;
                syslog(LOG_WARNING,
                       "%s",
                       "IP auth plugin: usexforwardedfor is enabled with empty xforwardedforfilterip; trusting X-Forwarded-For from all peers");
                xff_no_filter_warned_ = true;
            }
            use_xforwardedfor = true;
        }
    }
    std::vector<std::string> candidates;

    if (use_xforwardedfor == 1) {
        candidates.emplace_back(normalise_forwarded_ip(h.getXForwardedForIP()));
        candidates.emplace_back(h.getClientIP());
    } else {
        candidates.emplace_back(h.getClientIP());
    }

    std::string peer_ip = peercon.getPeerIP();
    candidates.emplace_back(peer_ip);

    string = select_first_valid_ip(candidates);
    if (string.empty())
        string = trim_copy(peer_ip);
    if (string.empty())
        string = "-";

    authrec.user_name = string;
    authrec.user_source = "ip";
    is_real_user = true;
    return E2AUTH_OK;
}

bool ipinstance::ensureIPGroupsLoadedLocked()
{
    if (ipgroups_path_.empty())
        return ipgroups_loaded_;

    int current_reload_id = -1;
    if (auto lists = o.currentLists())
        current_reload_id = lists->reload_id;

    if (!ipgroups_loaded_ || current_reload_id != ipgroups_reload_id_) {
        std::vector<ip> new_iplist;
        std::list<ip_subnet_entry> new_ipsubnetlist;
        std::list<ip_range_entry> new_iprangelist;

        int read_result = readIPMelangeList(ipgroups_path_.c_str(), &new_iplist, &new_ipsubnetlist, &new_iprangelist);
        if (read_result < 0) {
            if (!ipgroups_parse_error_logged_) {
                if (!is_daemonised)
                    std::cerr << thread_id << "Error reloading ipgroups file at " << ipgroups_path_ << std::endl;
                syslog(LOG_ERR, "Error reloading ipgroups file at %s", ipgroups_path_.c_str());
                ipgroups_parse_error_logged_ = true;
            }
            return ipgroups_loaded_;
        }

        ipgroups_parse_error_logged_ = false;
        iplist.swap(new_iplist);
        ipsubnetlist.swap(new_ipsubnetlist);
        iprangelist.swap(new_iprangelist);
        ipgroups_reload_id_ = current_reload_id;
        ipgroups_loaded_ = true;
        syslog(LOG_NOTICE,
               "IP auth reloaded ipgroups: path=%s reload_id=%d ips=%zu subnets=%zu ranges=%zu",
               ipgroups_path_.c_str(),
               ipgroups_reload_id_,
               iplist.size(),
               ipsubnetlist.size(),
               iprangelist.size());
    }

    return ipgroups_loaded_;
}

int ipinstance::determineGroup(std::string &user, int &rfg, StoryBoard &story, NaughtyFilter &cm)
{
    user = trim_copy(user);
    struct in_addr sin;
    if (inet_aton(user.c_str(), &sin) == 0) {
        if (!is_daemonised)
            std::cerr << thread_id << "Unable to parse client IP \"" << user << "\" for IP auth" << std::endl;
        syslog(LOG_ERR, "Unable to parse client IP %s for IP auth", user.c_str());
        (void)story;
        return E2AUTH_NOMATCH;
    }
    uint32_t addr = ntohl(sin.s_addr);
    std::lock_guard<std::mutex> guard(ipgroups_mutex_);
    if (!ensureIPGroupsLoadedLocked())
        return E2AUTH_NOMATCH;
    int fg;
    // check straight IPs, subnets, and ranges
    fg = inList(addr);
    SpecialIpGroup special = decode_hidden_group(fg);
    if (apply_hidden_group(special, user, cm)) {
        cm.filtergroup = rfg;
        syslog(LOG_NOTICE, "IP auth decision: ip=%s source=iplist special=%s result=nogroup",
               user.c_str(),
               special == SpecialIpGroup::Banned ? "banned" : "exception");
        return E2AUTH_NOGROUP;
    }
    if (fg >= 0) {
        rfg = fg;
        cm.filtergroup = rfg;
        if (cm.authrec != nullptr) {
            cm.authrec->group_source = "ip";
            cm.authrec->filter_group = rfg;
            if (cm.authrec->user_name.length() == 0)
                cm.authrec->user_name = user;
        }
#ifdef E2DEBUG
        std::cerr << thread_id << "Matched IP " << user << " to straight IP list" << std::endl;
#endif
        syslog(LOG_NOTICE,
               "IP auth decision: ip=%s source=iplist result=group%d reason=exact_ip_match",
               user.c_str(),
               rfg + 1);
        return E2AUTH_OK;
    }
    fg = inSubnet(addr);
    special = decode_hidden_group(fg);
    if (apply_hidden_group(special, user, cm)) {
        cm.filtergroup = rfg;
        syslog(LOG_NOTICE, "IP auth decision: ip=%s source=subnet special=%s result=nogroup",
               user.c_str(),
               special == SpecialIpGroup::Banned ? "banned" : "exception");
        return E2AUTH_NOGROUP;
    }
    if (fg >= 0) {
        rfg = fg;
        cm.filtergroup = rfg;
        if (cm.authrec != nullptr) {
            cm.authrec->group_source = "ip";
            cm.authrec->filter_group = rfg;
            if (cm.authrec->user_name.length() == 0)
                cm.authrec->user_name = user;
        }
#ifdef E2DEBUG
        std::cerr << thread_id << "Matched IP " << user << " to subnet" << std::endl;
#endif
        uint32_t matched_mask = 0;
        uint32_t matched_network = 0;
        for (std::list<ip_subnet_entry>::const_iterator i = ipsubnetlist.begin(); i != ipsubnetlist.end(); ++i) {
            if (i->maskedaddr == (addr & i->mask)) {
                matched_mask = i->mask;
                matched_network = i->maskedaddr;
                break;
            }
        }
        char netbuf[INET_ADDRSTRLEN] = {0};
        char maskbuf[INET_ADDRSTRLEN] = {0};
        struct in_addr net_addr;
        struct in_addr mask_addr;
        net_addr.s_addr = htonl(matched_network);
        mask_addr.s_addr = htonl(matched_mask);
        inet_ntop(AF_INET, &net_addr, netbuf, sizeof(netbuf));
        inet_ntop(AF_INET, &mask_addr, maskbuf, sizeof(maskbuf));
        syslog(LOG_NOTICE,
               "IP auth decision: ip=%s source=subnet result=group%d reason=subnet_match network=%s mask=%s masked_ip=%s",
               user.c_str(),
               rfg + 1,
               netbuf,
               maskbuf,
               (netbuf[0] != '\0') ? netbuf : "-");
        return E2AUTH_OK;
    }
    fg = inRange(addr);
    special = decode_hidden_group(fg);
    if (apply_hidden_group(special, user, cm)) {
        cm.filtergroup = rfg;
        syslog(LOG_NOTICE, "IP auth decision: ip=%s source=range special=%s result=nogroup",
               user.c_str(),
               special == SpecialIpGroup::Banned ? "banned" : "exception");
        return E2AUTH_NOGROUP;
    }
    if (fg >= 0) {
        rfg = fg;
        cm.filtergroup = rfg;
        if (cm.authrec != nullptr) {
            cm.authrec->group_source = "ip";
            cm.authrec->filter_group = rfg;
            if (cm.authrec->user_name.length() == 0)
                cm.authrec->user_name = user;
        }
#ifdef E2DEBUG
        std::cerr << thread_id << "Matched IP " << user << " to range" << std::endl;
#endif
        uint32_t matched_start = 0;
        uint32_t matched_end = 0;
        for (std::list<ip_range_entry>::const_iterator i = iprangelist.begin(); i != iprangelist.end(); ++i) {
            if ((addr >= i->startaddr) && (addr <= i->endaddr)) {
                matched_start = i->startaddr;
                matched_end = i->endaddr;
                break;
            }
        }
        char startbuf[INET_ADDRSTRLEN] = {0};
        char endbuf[INET_ADDRSTRLEN] = {0};
        struct in_addr start_addr;
        struct in_addr end_addr;
        start_addr.s_addr = htonl(matched_start);
        end_addr.s_addr = htonl(matched_end);
        inet_ntop(AF_INET, &start_addr, startbuf, sizeof(startbuf));
        inet_ntop(AF_INET, &end_addr, endbuf, sizeof(endbuf));
        syslog(LOG_NOTICE,
               "IP auth decision: ip=%s source=range result=group%d reason=range_match range_start=%s range_end=%s",
               user.c_str(),
               rfg + 1,
               startbuf,
               endbuf);
        return E2AUTH_OK;
    }
#ifdef E2DEBUG
    std::cerr << thread_id << "Matched IP " << user << " to nothing" << std::endl;
#endif
    syslog(LOG_NOTICE,
           "IP auth decision: ip=%s source=none result=nomatch default_group=%d reload_id=%d loaded=%d ips=%zu subnets=%zu ranges=%zu reason=no_exact_no_subnet_no_range",
           user.c_str(),
           rfg + 1,
           ipgroups_reload_id_,
           ipgroups_loaded_ ? 1 : 0,
           iplist.size(),
           ipsubnetlist.size(),
           iprangelist.size());
    (void)story;
    return E2AUTH_NOMATCH;
}
//
//
// IP list functions (straight match, range match, subnet match)
//
//

// search for IP in list & return filter group on success, -1 on failure
int ipinstance::inList(const uint32_t &ip)
{
    if (iplist.size() > 0) {
        return searchList(0, static_cast<int>(iplist.size()) - 1, ip);
    }
    return -1;
}

// binary search list for given IP & return filter group, or -1 on failure
int ipinstance::searchList(int a, int s, const uint32_t &ip)
{
    if (a > s)
        return -1;
    int m = (a + s) / 2;
    if (iplist[m] == ip)
        return iplist[m].group;
    if (iplist[m] < ip)
        return searchList(m + 1, s, ip);
    if (a == s)
        return -1;
    return searchList(a, m - 1, ip);
}

// search subnet list for given IP & return filter group or -1
int ipinstance::inSubnet(const uint32_t &ip)
{
    for (std::list<ip_subnet_entry>::const_iterator i = ipsubnetlist.begin(); i != ipsubnetlist.end(); ++i) {
        if (i->maskedaddr == (ip & i->mask)) {
            return i->group;
        }
    }
    return -1;
}

// search range list for a range containing given IP & return filter group or -1
int ipinstance::inRange(const uint32_t &ip)
{
    for (std::list<ip_range_entry>::const_iterator i = iprangelist.begin(); i != iprangelist.end(); ++i) {
        if ((ip >= i->startaddr) && (ip <= i->endaddr)) {
            return i->group;
        }
    }
    return -1;
}

int ipinstance::parseFilterGroup(const String &value, const char *filename, const String &line, bool &warn, SpecialIpGroup &special)
{
    special = classify_special_group(value);
    if (special == SpecialIpGroup::Exception)
        return kHiddenExceptionGroup;
    if (special == SpecialIpGroup::Banned)
        return kHiddenBannedGroup;

    String normalised(value);
    normalised.toLower();
    normalised.removeWhiteSpace();
    if (normalised.startsWith("filter"))
        normalised = normalised.after("filter");
    if (normalised.startsWith("group"))
        normalised = normalised.after("group");
    normalised.removeWhiteSpace();

    String digits;
    const char *ptr = normalised.toCharArray();
    for (size_t i = 0; ptr[i] != '\0'; ++i) {
        if (isdigit(static_cast<unsigned char>(ptr[i]))) {
            digits += ptr[i];
        } else if (digits.length() > 0) {
            break;
        }
    }

    String numeric = (digits.length() > 0) ? digits : normalised;
    int group = numeric.toInteger();
    if ((group < 1) || (group > o.filter_groups)) {
        if (!is_daemonised)
            std::cerr << thread_id << "Filter group out of range; entry " << line << " in " << filename << std::endl;
        syslog(LOG_ERR, "Filter group out of range; entry %s in %s", line.toCharArray(), filename);
        warn = true;
        return -1;
    }

    return group - 1;
}
// read in a list linking IPs, subnets & IP ranges to filter groups
// return 0 for success, -1 for failure, 1 for warning
int ipinstance::readIPMelangeList(const char *filename,
                                  std::vector<ip> *iplist_out,
                                  std::list<ip_subnet_entry> *ipsubnetlist_out,
                                  std::list<ip_range_entry> *iprangelist_out)
{
    std::vector<ip> &target_iplist = iplist_out ? *iplist_out : iplist;
    std::list<ip_subnet_entry> &target_ipsubnetlist = ipsubnetlist_out ? *ipsubnetlist_out : ipsubnetlist;
    std::list<ip_range_entry> &target_iprangelist = iprangelist_out ? *iprangelist_out : iprangelist;

    target_iplist.clear();
    target_ipsubnetlist.clear();
    target_iprangelist.clear();

    // load in the list file
    std::ifstream input(filename);
    if (!input) {
        if (!is_daemonised) {
            std::cerr << thread_id << "Error reading file (does it exist?): " << filename << std::endl;
        }
        syslog(LOG_ERR, "%s%s", "Error reading file (does it exist?): ", filename);
        return -1;
    }

    // compile regexps for determining whether a list entry is an IP, a subnet (IP + mask), or a range
    RegExp matchIP, matchSubnet, matchRange, matchCIDR;
#ifdef HAVE_PCRE
    matchIP.comp("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    matchSubnet.comp("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    matchCIDR.comp("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}$");
    matchRange.comp("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}-\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
#else
    matchIP.comp("^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$");
    matchSubnet.comp("^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$");
    matchCIDR.comp("^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,2}$");
    matchRange.comp("^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}-[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$");
#endif
    RegResult Rre;

    // read in the file
    String line;
    String key, value;
    char buffer[2048];
    bool warn = false;
    while (input) {
        if (!input.getline(buffer, sizeof(buffer))) {
            break;
        }
        // ignore comments
        if (buffer[0] == '#')
            continue;
        // ignore blank lines
        String raw(buffer);
        raw.removeWhiteSpace();
        if (raw.length() == 0)
            continue;
        line = buffer;
        // split into key & value
        if (line.contains("=")) {
            key = line.before("=");
            key.removeWhiteSpace();
            value = line.after("=");
            value.removeWhiteSpace();
        } else {
            if (!is_daemonised)
                std::cerr << thread_id << "No filter group given; entry " << line << " in " << filename << std::endl;
            syslog(LOG_ERR, "No filter group given; entry %s in %s", line.toCharArray(), filename);
            warn = true;
            continue;
        }
        SpecialIpGroup special = SpecialIpGroup::None;
        int group = parseFilterGroup(value, filename, line, warn, special);
        if ((group < 0) && (special == SpecialIpGroup::None))
            continue;
        if (special != SpecialIpGroup::None) {
            if (!is_daemonised)
                std::cerr << thread_id << "Matched special IP list entry " << line << " in " << filename << std::endl;
            syslog(LOG_INFO, "Matched special IP list entry %s in %s", line.toCharArray(), filename);
        }
        // store the IP address (numerically, not as a string) and filter group in either the IP list, subnet list or range list
        if (matchIP.match(key.toCharArray(),Rre)) {
            struct in_addr address;
            if (inet_aton(key.toCharArray(), &address)) {
                target_iplist.push_back(ip(ntohl(address.s_addr), group));
            }
        } else if (matchSubnet.match(key.toCharArray(),Rre)) {
            struct in_addr address;
            struct in_addr addressmask;
            String subnet(key.before("/"));
            String mask(key.after("/"));
            if (inet_aton(subnet.toCharArray(), &address) && inet_aton(mask.toCharArray(), &addressmask)) {
                ip_subnet_entry s;
                int addr = ntohl(address.s_addr);
                s.mask = ntohl(addressmask.s_addr);
                // pre-mask the address for quick comparison
                s.maskedaddr = addr & s.mask;
                s.group = group;
                target_ipsubnetlist.push_back(s);
            }
        } else if (matchCIDR.match(key.toCharArray(),Rre)) {
            struct in_addr address;
            String subnet(key.before("/"));
            String cidr(key.after("/"));
            int m = cidr.toInteger();
            if (m < 0 || m > 32) {
                if (!is_daemonised)
                    std::cerr << thread_id << "Invalid CIDR prefix; entry " << line << " in " << filename << std::endl;
                syslog(LOG_ERR, "Invalid CIDR prefix; entry %s in %s", line.toCharArray(), filename);
                warn = true;
                continue;
            }
            if (inet_aton(subnet.toCharArray(), &address)) {
                uint32_t addr = ntohl(address.s_addr);
                uint32_t mask = (m == 0) ? 0 : (0xFFFFFFFFu << (32 - m));
                ip_subnet_entry s;
                s.mask = mask;
                // pre-mask the address for quick comparison
                s.maskedaddr = addr & s.mask;
                s.group = group;
                target_ipsubnetlist.push_back(s);
            }
        } else if (matchRange.match(key.toCharArray(),Rre)) {
            struct in_addr addressstart;
            struct in_addr addressend;
            String start(key.before("-"));
            String end(key.after("-"));
            if (inet_aton(start.toCharArray(), &addressstart) && inet_aton(end.toCharArray(), &addressend)) {
                ip_range_entry r;
                r.startaddr = ntohl(addressstart.s_addr);
                r.endaddr = ntohl(addressend.s_addr);
                r.group = group;
                target_iprangelist.push_back(r);
            }
        }
        // hmmm. the key didn't match any of our regular expressions. output message & return a warning value.
        else {
            if (!is_daemonised)
                std::cerr << thread_id << "Entry " << line << " in " << filename << " was not recognised as an IP address, subnet or range" << std::endl;
            syslog(LOG_ERR, "Entry %s in %s was not recognised as an IP address, subnet or range", line.toCharArray(), filename);
            warn = true;
        }
    }
    input.close();
#ifdef E2DEBUG
    std::cerr << thread_id << "starting sort" << std::endl;
#endif
    std::sort(target_iplist.begin(), target_iplist.end());
#ifdef E2DEBUG
    std::cerr << thread_id << "sort complete" << std::endl;
    std::cerr << thread_id << "ip list dump:" << std::endl;
    std::vector<ip>::const_iterator i = target_iplist.begin();
    while (i != target_iplist.end()) {
        std::cerr << thread_id << "IP: " << i->addr << " Group: " << i->group << std::endl;
        ++i;
    }
    std::cerr << thread_id << "subnet list dump:" << std::endl;
    std::list<ip_subnet_entry>::const_iterator j = target_ipsubnetlist.begin();
    while (j != target_ipsubnetlist.end()) {
        std::cerr << thread_id << "Masked IP: " << j->maskedaddr << " Mask: " << j->mask << " Group: " << j->group << std::endl;
        ++j;
    }
    std::cerr << thread_id << "range list dump:" << std::endl;
    std::list<ip_range_entry>::const_iterator k = target_iprangelist.begin();
    while (k != target_iprangelist.end()) {
        std::cerr << thread_id << "Start IP: " << k->startaddr << " End IP: " << k->endaddr << " Group: " << k->group << std::endl;
        ++k;
    }
#endif
    // return either warning or success
    return warn ? 1 : 0;
}
