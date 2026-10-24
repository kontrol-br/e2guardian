// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_LOPTIONCONTAINER
#define __HPP_LOPTIONCONTAINER

// INCLUDES

#include "DownloadManager.hpp"
#include "ContentScanner.hpp"
#include "String.hpp"
#include "HTMLTemplate.hpp"
#include "ListContainer.hpp"
#include "ListManager.hpp"
#include "FOptionContainer.hpp"
#include "LanguageContainer.hpp"
#include "ImageContainer.hpp"
#include "RegExp.hpp"
#include "Auth.hpp"
#include "IPList.hpp"
#include "Queue.hpp"

#include <deque>
#include <vector>
#include <map>
#include <atomic>

#ifdef __SSLMITM
#include "CertificateAuthority.hpp"
#endif


// DECLARATIONS
struct GatewayEndpoint {
    std::string name;
    std::string if_name;
    std::string local_ip;
    std::string gw_ip;
    int tos = -1;
    int tier = 1;
    int weight = 1;
    bool up = true;
};

struct GatewayRule {
    enum SrcType { SRC_ANY = 0, SRC_IP, SRC_USER } src_type = SRC_ANY;
    enum DstType { DST_ANY = 0, DST_DOMAIN, DST_URL, DST_IP } dst_type = DST_ANY;

    std::vector<uint32_t> src_ips;
    std::vector<ipl_rangestruct> src_ranges;
    std::vector<ipl_subnetstruct> src_subnets;
    std::vector<std::string> src_users;

    std::vector<std::string> dst_domains_exact;
    std::vector<std::string> dst_domains_wild;
    std::vector<std::string> dst_urls;
    std::vector<uint32_t> dst_ips;
    std::vector<ipl_rangestruct> dst_ranges;
    std::vector<ipl_subnetstruct> dst_subnets;

    std::string gateway;
    std::string name;
};

struct room_item {
    std::string name;
    IPList *iplist;
    ListContainer *sitelist;
    ListContainer *urllist;
    bool block;
    bool part_block;
};


class LOptionContainer
{
    public:
    //Queue<std::string>* log_Q;
    //Queue<Socket*>* http_worker_Q;

    // all our options

    std::string name_suffix;

    HTMLTemplate html_template;
    ListContainer filter_groups_list;
    IPList exception_ip_list;
    IPList banned_ip_list;
    ListMeta LMeta;
    StoryBoard StoryA;
    ListManager lm;
    FOptionContainer **fg = nullptr;
    bool loaded_ok;
    int reload_id;
    int numfg = 0;
    String start_time;

    // access denied domain (when using the CGI)
    String access_denied_domain;

    void deleteFilterGroups();
    void deleteFilterGroupsJustListData();

    //...and the functions that read them

    LOptionContainer();
    LOptionContainer(int reload_id);
    ~LOptionContainer();
    bool read(std::string& filename, int type, std::string& exception_ip_list_location,
              std::string& banned_ip_list_location);
    void reset();
    bool inExceptionIPList(const std::string *ip, std::string *&host);
    //bool inBannedIPList(const std::string *ip, std::string *&host);
    bool readFilterGroupConf();
    // public so fc_controlit can reload filter group config files
    bool doReadItemList(const char *filename, ListContainer *lc, const char *fname, bool swsort);

    // per-room blocking and URL whitelisting: see if given IP is in a room; if it is, return true and put the room name in "room"
    bool inRoom(const std::string &ip, std::string &room, std::string *host, bool *block, bool *part_block, bool *isexception, String url);
    void loadRooms(bool throw_error);
    void deleteRooms();

    const char *inSiteList(String &url, ListContainer *lc, bool swsort, bool ip);
    char *inURLList(String &url, ListContainer *lc, bool swsort, bool ip);

    String ISTag() {
        return start_time;
    }

    bool hasGatewayRules() const { return !gateway_rules.empty(); }
    void loadGatewayRules(const std::string &filename);
    std::string matchGatewayRule(const std::string &client_ip, const std::string &client_user,
                                 const String &domain, const String &url, const std::string &dest_ip) const;
    std::vector<GatewayEndpoint> getGatewayEndpoints(const std::string &gw_name) const;


    private:
    std::vector<GatewayRule> gateway_rules;
    std::map<std::string, GatewayEndpoint> gateways_map;
    std::map<std::string, std::vector<GatewayEndpoint>> gateway_groups_map;
    mutable std::atomic<uint32_t> gw_rr_counter{0};
    std::string per_room_directory_location;
    std::deque<std::string> conffile;
    std::string conffilename;
    int reporting_level = 0;

    std::string html_template_location;
    std::string group_names_list_location;


    bool precompileregexps();
    long int findoptionI(const char *option);
    std::string findoptionS(const char *option);
    //bool realitycheck(long int l, long int minl, long int maxl, const char *emessage);
    bool readAnotherFilterGroupConf(const char *filename, const char *groupname, bool &need_html, int fg_no);
    std::deque<String> findoptionM(const char *option);

    //bool inIPList(const std::string *ip, ListContainer &list, std::string *&host);
    std::list<room_item> rooms;
    void normaliseAuthMapGroups();
};

#endif
