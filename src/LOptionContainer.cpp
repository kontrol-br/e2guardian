// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "LOptionContainer.hpp"
#include "OptionContainer.hpp"
#include "RegExp.hpp"
#include "ConfigVar.hpp"

#include <cstdio>
#include <iostream>
#include <fstream>
#include <sstream>
#include <syslog.h>
#include <dirent.h>
#include <cstdlib>
#include <map>
#include <utility>
#include <algorithm>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <unistd.h> // checkme: remove?

// GLOBALS

extern bool is_daemonised;

extern OptionContainer o;
extern thread_local std::string thread_id;



// IMPLEMENTATION

LOptionContainer::LOptionContainer()
{
}

LOptionContainer::LOptionContainer(int load_id)
{
    char buff[40];

    sprintf(buff, "%ld", time(NULL));
    start_time = buff;

    loaded_ok = true;

    {
#ifdef E2DEBUG
        std::cerr << thread_id << "iplist deque is size " << o.iplist_dq.size() << std::endl;
#endif
        if(!LMeta.load_type(LIST_TYPE_IP, o.iplist_dq))
            loaded_ok = false;
    }

    {
#ifdef E2DEBUG
        std::cerr << thread_id << "sitelist deque is size " << o.sitelist_dq.size() << std::endl;
#endif
        if(!LMeta.load_type(LIST_TYPE_SITE, o.sitelist_dq))
        loaded_ok = false;
    }

    {
#ifdef E2DEBUG
        std::cerr << thread_id << "ipsitelist deque is size " << o.ipsitelist_dq.size() << std::endl;
#endif
        if(!LMeta.load_type(LIST_TYPE_IPSITE, o.ipsitelist_dq))
        loaded_ok = false;
    }

    {
#ifdef E2DEBUG
        std::cerr << thread_id << "urllist deque is size " << o.urllist_dq.size() << std::endl;
#endif
        if(!LMeta.load_type(LIST_TYPE_URL, o.urllist_dq))
        loaded_ok = false;
    }

    {
#ifdef E2DEBUG
        std::cerr << thread_id << "regexpboollist deque is size " << o.regexpboollist_dq.size() << std::endl;
#endif
        if(!LMeta.load_type(LIST_TYPE_REGEXP_BOOL, o.regexpboollist_dq))
            loaded_ok = false;
    }

    {
#ifdef E2DEBUG
        std::cerr << thread_id << "maplist deque is size " << o.maplist_dq.size() << std::endl;
#endif
        if(!LMeta.load_type(LIST_TYPE_MAP, o.maplist_dq))
            loaded_ok = false;
    }

    {
#ifdef E2DEBUG
        std::cerr << thread_id << "ipmaplist deque is size " << o.ipmaplist_dq.size() << std::endl;
#endif
        if(!LMeta.load_type(LIST_TYPE_IPMAP, o.ipmaplist_dq))
            loaded_ok = false;
    }

    if (!StoryA.readFile(o.storyboard_location.c_str(), LMeta, true)) {
        std::cerr << thread_id << "Storyboard not loaded OK" << std::endl;
        loaded_ok = false;
    }

    if (loaded_ok && !StoryA.setEntry(ENT_STORYA_PRE_AUTH,"pre-authcheck")) {
        std::cerr << thread_id << "Required storyboard entry function 'pre-authcheck' is missing" << std::endl;
        loaded_ok = false;
    }

    if (loaded_ok && (o.transparenthttps_port > 0) && !StoryA.setEntry(ENT_STORYA_PRE_AUTH_THTTPS,"thttps-pre-authcheck")) {
        std::cerr << thread_id << "Required storyboard entry function 'thttps-pre-authcheck' is missing" << std::endl;
        loaded_ok = false;
    }

    if (loaded_ok && (o.icap_port > 0) && !StoryA.setEntry(ENT_STORYA_PRE_AUTH_ICAP,"icap-pre-authcheck")) {
        std::cerr << thread_id << "Required storyboard entry function 'icap-pre-authcheck' is missing" << std::endl;
        loaded_ok = false;
    }

 //   if (loaded_ok && o.use_filter_groups_list)  {
 //       if (!doReadItemList(o.filter_groups_list_location.c_str(), &filter_groups_list, "filtergroupslist", true)) {
 //           std::cerr << thread_id << "Failed to read filtergroupslist" << std::endl;
 //           loaded_ok = false;
 //       }
 //   }

    if (loaded_ok && o.auth_entry_dq.size() > 0)  {
            for (std::deque<struct OptionContainer::auth_entry>::const_iterator i = o.auth_entry_dq.begin(); i != o.auth_entry_dq.end(); ++i) {
                if (!StoryA.setEntry(i->entry_id, i->entry_function)) {
                    std::cerr << thread_id << "Required auth storyboard entry function" << i->entry_function.c_str()
                              << " is missing from pre_auth.story" << std::endl;
                    loaded_ok = false;
                }
            }
    }


    if(loaded_ok && (!readFilterGroupConf() || (o.abort_on_missing_list && o.config_error)))  {
        loaded_ok = false;
        if (!is_daemonised)
            std::cerr << thread_id << "Error in reading filter group files" << std::endl;
        else
            syslog(LOG_INFO, "Error in reading filter group files");
    }
    if (loaded_ok) {
        normaliseAuthMapGroups();
        loadGatewayRules(o.gateway_rules_location);
    }
    reload_id = load_id;
    ++o.LC_cnt;
    if (load_id == 0)    o.numfg = numfg;   // do this on first load only
}

void LOptionContainer::normaliseAuthMapGroups()
{
    std::map<std::string, int> name_lookup;

    auto add_alias = [&](const String &label, int group_no) {
        if (label.length() == 0)
            return;
        std::string key = normalise_group_label(label);
        if (key.empty())
            return;
        if (name_lookup.find(key) == name_lookup.end())
            name_lookup.emplace(std::move(key), group_no);
    };

    for (int idx = 0; idx < numfg; ++idx) {
        if (fg[idx] == nullptr)
            continue;

        String base_name;
        if (!fg[idx]->name.empty())
            base_name = fg[idx]->name.c_str();
        else {
            base_name = "group";
            base_name += String(idx + 1);
        }

        add_alias(base_name, idx + 1);
        if (base_name.contains(" "))
            add_alias(base_name.before(" "), idx + 1);

        String alias("group");
        alias += String(idx + 1);
        add_alias(alias, idx + 1);

        alias = "filter";
        alias += String(idx + 1);
        add_alias(alias, idx + 1);

        alias = "grp";
        alias += String(idx + 1);
        add_alias(alias, idx + 1);

        alias = String(idx + 1);
        add_alias(alias, idx + 1);
    }

    int default_group = 1;
    if (o.default_fg >= 0 && o.default_fg < numfg)
        default_group = o.default_fg + 1;

    add_alias(String("default"), default_group);
    add_alias(String("defaultgroup"), default_group);
    add_alias(String("defaultfiltergroup"), default_group);

    if (name_lookup.empty())
        return;

    for (const auto &info : LMeta.list_vec) {
        if (info.type != LIST_TYPE_MAP)
            continue;
        if (info.list_ref >= o.lm.l.size())
            continue;
        ListContainer *container = o.lm.l[info.list_ref];
        if (container == nullptr)
            continue;
        container->normaliseDataMapGroups(name_lookup, info.name);
    }
}


const char *LOptionContainer::inSiteList(String &url, ListContainer *lc, bool ip, bool ssl)
{
    String lastcategory;
    url.removeWhiteSpace(); // just in case of weird browser crap
    url.toLower();
    url.removePTP(); // chop off the ht(f)tp(s)://
    if (url.contains("/")) {
        url = url.before("/"); // chop off any path after the domain
    }
    const char *i;
    //bool isipurl = isIPHostname(url);
    while (url.contains(".")) {
        i = lc->findInList(url.toCharArray(), lastcategory);
        if (i != NULL) {
            return i; // exact match
        }
        url = url.after("."); // check for being in higher level domains
    }
    if (url.length() > 1) { // allows matching of .tld
        url = "." + url;
        i = lc->findInList(url.toCharArray(), lastcategory);
        if (i != NULL) {
            return i; // exact match
        }
    }
    return NULL; // and our survey said "UUHH UURRGHH"
}

// look in given URL list for given URL
char *LOptionContainer::inURLList(String &url, ListContainer *lc, bool ip, bool ssl)
{
    unsigned int fl;
    char *i;
    String lastcategory;
    String foundurl;
#ifdef E2DEBUG
    std::cerr << thread_id << "inURLList: " << url << std::endl;
#endif
    //syslog(LOG_ERR, "inURLList url %s", url.c_str());
    url.removeWhiteSpace(); // just in case of weird browser crap
    url.toLower();
    url.removePTP(); // chop off the ht(f)tp(s)://
    if (url.contains("/")) {
        String tpath("/");
        tpath += url.after("/");
        url = url.before("/");
        tpath.hexDecode();
        tpath.realPath();
        url += tpath; // will resolve ../ and %2e2e/ and // etc
    }
    if (url.endsWith("/")) {
        url.chop(); // chop off trailing / if any
    }
#ifdef E2DEBUG
    std::cerr << thread_id << "inURLList (processed): " << url << std::endl;
#endif
    //  syslog(LOG_ERR, "inURLList (processed) url %s", url.c_str());
    while (url.before("/").contains(".")) {
        i = lc->findStartsWith(url.toCharArray(), lastcategory);
        if (i != NULL) {
            foundurl = i;
            fl = foundurl.length();
#ifdef E2DEBUG
            std::cerr << thread_id << "foundurl: " << foundurl << foundurl.length() << std::endl;
            std::cerr << thread_id << "url: " << url << fl << std::endl;
#endif
            //syslog(LOG_ERR, "inURLList foundurl  %s", foundurl.c_str());
            if (url.length() > fl) {
                if (url[fl] == '/' || url[fl] == '?' || url[fl] == '&' || url[fl] == '=') {
                    return i; // matches /blah/ or /blah/foo but not /blahfoo
                }
            } else {
                return i; // exact match
            }
        }
        url = url.after("."); // check for being in higher level domains
    }
    return NULL;
}

#ifdef NOTDEF
bool LOptionContainer::doReadItemList(const char *filename, ListContainer *lc, const char *fname, bool swsort)
{
    bool result = lc->readItemList(filename, false, 0);
    if (!result) {
        if (!is_daemonised) {
            std::cerr << thread_id << "Error opening " << fname << std::endl;
        }
        syslog(LOG_ERR, "Error opening %s", fname);
        return false;
    }
    if (swsort)
        lc->doSort(true);
    else
        lc->doSort(false);
    return true;
}
#endif

bool LOptionContainer::inExceptionIPList(const std::string *ip, std::string *&host)
{
    return exception_ip_list.inList(*ip, host);
}

// TODO: Filter rules should migrate to FOptionContainer.cpp ?  -- No, these are not filtergroup rules but nmaybe to their own cpp??

bool LOptionContainer::inRoom(const std::string &ip, std::string &room, std::string *host, bool *block, bool *part_block, bool *isexception, String url)
{
    String temp;
    for (std::list<struct room_item>::const_iterator i = rooms.begin(); i != rooms.end(); ++i) {
        if (i->iplist->inList(ip, host)) {
#ifdef E2DEBUG
            std::cerr << thread_id << " IP is in room: " << i->name << std::endl;
#endif
            temp = url;
            ListContainer *lc;
            if (i->sitelist) {
                lc = i->sitelist;
                if (inSiteList(temp, lc, false, false)) {
#ifdef E2DEBUG
                    std::cerr << thread_id << " room site exception found: " << std::endl;
#endif
                    *isexception = true;
                    room = i->name;
                    return true;
                }
            }
            temp = url;
            if (i->urllist && inURLList(temp, i->urllist, false, false)) {
#ifdef E2DEBUG
                std::cerr << thread_id << " room url exception found: " << std::endl;
#endif
                *isexception = true;
                room = i->name;
                return true;
            }
            if (i->block) {
                *block = true;
                *part_block = i->part_block;
                room = i->name;
#ifdef E2DEBUG
                std::cerr << thread_id << " room blanket block active: " << std::endl;
#endif
                return true;
            } else {
#ifdef E2DEBUG
                std::cerr << thread_id << " room - no url/site exception or block found: " << std::endl;
#endif
                return false;
            }
        }
    }
    return false;
}



LOptionContainer::~LOptionContainer()
{
    reset();
}

void LOptionContainer::reset()
{
    deleteFilterGroups();
    deleteRooms();
    gateway_rules.clear();
    gateways_map.clear();
    gateway_groups_map.clear();
    conffile.clear();
    --o.LC_cnt;
}

void LOptionContainer::deleteFilterGroups()
{
    for (int i = 0; i < numfg; i++) {
        if (fg[i] != NULL) {
#ifdef E2DEBUG
            std::cerr << thread_id << "In deleteFilterGroups loop" << std::endl;
#endif
            delete fg[i]; // delete extra FOptionContainer objects
            fg[i] = NULL;
        }
    }
    if (numfg > 0) {
        delete[] fg;
        numfg = 0;
    }
}

void LOptionContainer::deleteFilterGroupsJustListData()
{
    for (int i = 0; i < numfg; i++) {
        if (fg[i] != NULL) {
            fg[i]->resetJustListData();
        }
    }
}

#ifdef NOTDEF
bool LOptionContainer::read(std::string& filename, int type, std::string& exception_ip_list_location,
                            std::string& banned_ip_list_location)
{
	conffilename = filename;

	// all sorts of exceptions could occur reading conf files
	try {
		std::string linebuffer;
		String temp;  // for tempory conversion and storage
		std::ifstream conffiles(filename.c_str(), std::ios::in);  // e2guardian.conf
		if (!conffiles.good()) {
			if (!is_daemonised) {
				std::cerr << thread_id << "error reading: " << filename.c_str() << std::endl;
			}
			syslog(LOG_ERR, "%s", "error reading e2guardian.conf");
			return false;
		}
		while (!conffiles.eof()) {
			getline(conffiles, linebuffer);
			if (!conffiles.eof() && linebuffer.length() != 0) {
				if (linebuffer[0] != '#') {	// i.e. not commented out
					temp = (char *) linebuffer.c_str();
					if (temp.contains("#")) {
						temp = temp.before("#");
					}
					temp.removeWhiteSpace();  // get rid of spaces at end of line
					linebuffer = temp.toCharArray();
					conffile.push_back(linebuffer);  // stick option in deque
				}
			}
		}
		conffiles.close();

		if (type == 0 || type == 2) {



            if (type == 0) {
				return true;
			}
		}



        if (((per_room_directory_location = findoptionS("perroomdirectory")) != "") || ((per_room_directory_location = findoptionS("perroomblockingdirectory")) != "")) {
            loadRooms(true);
        }


//        filter_groups_list_location = findoptionS("filtergroupslist");
//        std::string banned_ip_list_location(findoptionS("bannediplist"));
//        std::string exception_ip_list_location(findoptionS("exceptioniplist"));
//        group_names_list_location = findoptionS("groupnamesfile");
//        std::string language_list_location(languagepath + "messages");
        {
            std::deque<String> dq = findoptionM("iplist");
            std::cerr << thread_id << "iplist deque is size " << dq.size() << std::endl;
            LMeta.load_type(LIST_TYPE_IP, dq);
        }

        {
            std::deque<String> dq = findoptionM("sitelist");
            std::cerr << thread_id << "sitelist deque is size " << dq.size() << std::endl;
            LMeta.load_type(LIST_TYPE_SITE, dq);
        }

        {
            std::deque<String> dq = findoptionM("ipsitelist");
            std::cerr << thread_id << "ipsitelist deque is size " << dq.size() << std::endl;
            LMeta.load_type(LIST_TYPE_IPSITE, dq);
        }

        {
            std::deque<String> dq = findoptionM("urllist");
            std::cerr << thread_id << "urllist deque is size " << dq.size() << std::endl;
            LMeta.load_type(LIST_TYPE_URL, dq);
        }

        if (!StoryA.readFile(o.storyboard_location.c_str(), LMeta, true))
            return false;

        if (!StoryA.setEntry1("pre-authcheck")) {
            std::cerr << thread_id << "Required storyboard entry function 'pre-authcheck' is missing" << std::endl;
            return false;
        }

        if (!readFilterGroupConf()) {
            if (!is_daemonised) {
                std::cerr << thread_id << "Error reading filter group conf file(s)." << std::endl;
            }
            syslog(LOG_ERR, "%s", "Error reading filter group conf file(s).");
            return false;
        }

    } catch (std::exception &e) {
        if (!is_daemonised) {
            std::cerr << thread_id << e.what() << std::endl; // when called the daemon has not
            // detached so we can do this
        }
        return false;
    }
    return true;
}
#endif





// TODO: Filter rules should migrate to FOptionContainer.cpp ?  -- No, these are not filtergroup rules but nmaybe to their own cpp??



void LOptionContainer::loadRooms(bool throw_error)
{
    if (!throw_error && (per_room_directory_location == ""))
        return;
    DIR *d = opendir(per_room_directory_location.c_str());
    if (d == NULL) {
        if (throw_error) {
            syslog(LOG_ERR, "Could not open room definitions directory: %s", strerror(errno));
            std::cerr << thread_id << "Could not open room definitions directory" << std::endl;
            exit(1);
        } else {
            return;
        }
    }

    struct dirent *f;
    while ((f = readdir(d))) {
        if (f->d_name[0] == '.')
            continue;
        std::string filename(per_room_directory_location);
        filename.append(f->d_name);
#ifdef E2DEBUG
        std::cerr << thread_id << " Room file found : " << filename.c_str() << std::endl;
#endif
        std::ifstream infile(filename.c_str(), std::ios::in);
        if (!infile.good()) {
            syslog(LOG_ERR, " Could not open file room definitions ");
            std::cerr << thread_id << " Could not open file room definitions: " << filename.c_str() << std::endl;
            exit(1);
        }
#ifdef E2DEBUG
        std::cerr << thread_id << " Opened room file : " << filename.c_str() << std::endl;
#endif

        std::string roomname;
#ifdef E2DEBUG
        std::cerr << thread_id << " Reading room file : " << filename.c_str() << std::endl;
#endif
        getline(infile, roomname);
        if (infile.eof()) {
            syslog(LOG_ERR, " Unexpected EOF ");
            std::cerr << thread_id << " Unexpected EOF: " << filename.c_str() << std::endl;
            exit(1);
        }
        if (infile.fail()) {
            syslog(LOG_ERR, " Unexpected failure on read");
            std::cerr << thread_id << " Unexpected failure on read: " << filename.c_str() << std::endl;
            exit(1);
        }
        if (infile.bad()) {
            syslog(LOG_ERR, " Unexpected badbit failure on read");
            std::cerr << thread_id << " Unexpected badbit failure on read: " << filename.c_str() << std::endl;
            exit(1);
        }
        if (!infile.good()) {
            syslog(LOG_ERR, " Could not open file room definitions ");
            std::cerr << thread_id << " Could not open file room definitions: " << filename.c_str() << std::endl;
            exit(1);
        }
#ifdef E2DEBUG
        std::cerr << thread_id << " Room name is: " << roomname.c_str() << std::endl;
#endif
        roomname = roomname.substr(1);
        room_item this_room;
        this_room.name = roomname;
        this_room.block = false;
        this_room.part_block = false;
        this_room.sitelist = NULL;
        this_room.urllist = NULL;

        IPList *contents = new IPList();
        contents->ifsreadIPMelangeList(&infile, true, "#ENDLIST");
        this_room.iplist = contents;
        if (infile.eof()) { // is old style room block
            this_room.block = true;
            this_room.sitelist = NULL;
            this_room.urllist = NULL;
        } else {
            std::string linestr;
            String temp;
            while (infile.good()) {
                std::getline(infile, linestr);
                if (infile.eof())
                    break;
                temp = linestr;
                if (temp.startsWith("#SITELIST")) {
                    ListContainer *sitelist = new ListContainer();
                    if (sitelist->ifsReadSortItemList(&infile, "", "", true, "#ENDLIST", false, false, 0, filename.c_str())) {
                        this_room.sitelist = sitelist;
                    } else {
                        delete sitelist;
                    }
                } else if (temp.startsWith("#URLLIST")) {
                    ListContainer *urllist = new ListContainer();
                    if (urllist->ifsReadSortItemList(&infile,"", "",  true, "#ENDLIST", false, true, 0, filename.c_str())) {
                        this_room.urllist = urllist;
                    } else {
                        delete urllist;
                    }
                } else if (temp.startsWith("#BLOCK")) {
                    this_room.block = true;
                }
            }
        }
        if (this_room.block && (this_room.sitelist || this_room.urllist))
            this_room.part_block = true;
        rooms.push_back(this_room);
        infile.close();
        if (roomname.size() <= 2) {
            if (!is_daemonised) {
                std::cerr << thread_id << "Could not read room from definitions file \"" << filename << '"' << std::endl;
            }
            syslog(LOG_ERR, "Could not read room from definitions file \"%s\"",
                filename.c_str());
            exit(1);
        }
        roomname = roomname.substr(1); // remove leading '#'
    }

    if (closedir(d) != 0) {
        if (errno != EINTR) {
            syslog(LOG_ERR, "Could not close room definitions directory: %s", strerror(errno));
            exit(1);
        }
    }
}

void LOptionContainer::deleteRooms()
{
    for (std::list<room_item>::iterator i = rooms.begin(); i != rooms.end(); ++i) {
        delete i->iplist;
        if (i->sitelist != NULL)
            delete i->sitelist;
        if (i->urllist != NULL)
            delete i->urllist;
    }
    rooms.clear();
}

long int LOptionContainer::findoptionI(const char *option)
{
    long int res = String(findoptionS(option).c_str()).toLong();
    return res;
}

std::string LOptionContainer::findoptionS(const char *option)
{
    // findoptionS returns a found option stored in the deque
    String temp;
    String temp2;
    String o(option);

    for (std::deque<std::string>::iterator i = conffile.begin(); i != conffile.end(); i++) {
        if ((*i).empty())
            continue;
        temp = (*i).c_str();
        temp2 = temp.before("=");
        while (temp2.endsWith(" ")) { // get rid of tailing spaces before =
            temp2.chop();
        }
        if (o == temp2) {
            temp = temp.after("=");
            while (temp.startsWith(" ")) { // get rid of heading spaces
                temp.lop();
            }
            if (temp.startsWith("'")) { // inverted commas
                temp.lop();
            }
            while (temp.endsWith(" ")) { // get rid of tailing spaces
                temp.chop();
            }
            if (temp.endsWith("'")) { // inverted commas
                temp.chop();
            }
            return temp.toCharArray();
        }
    }
    return "";
}

std::deque<String> LOptionContainer::findoptionM(const char *option)
{
    // findoptionS returns all the matching options
    String temp;
    String temp2;
    String o(option);
    std::deque<String> results;

    for (std::deque<std::string>::iterator i = conffile.begin(); i != conffile.end(); i++) {
        if ((*i).empty())
            continue;
        temp = (*i).c_str();
        temp2 = temp.before("=");
        while (temp2.endsWith(" ")) { // get rid of tailing spaces before =
            temp2.chop();
        }
        if (o == temp2) {
            temp = temp.after("=");
            while (temp.startsWith(" ")) { // get rid of heading spaces
                temp.lop();
            }
            if (temp.startsWith("'")) { // inverted commas
                temp.lop();
            }
            while (temp.endsWith(" ")) { // get rid of tailing spaces
                temp.chop();
            }
            if (temp.endsWith("'")) { // inverted commas
                temp.chop();
            }
            results.push_back(temp);
        }
    }
    return results;
}

#ifdef NOTDEF
bool LOptionContainer::realitycheck(long int l, long int minl, long int maxl, const char *emessage)
{
    // realitycheck checks an amount for certain expected criteria
    // so we can spot problems in the conf files easier
    if ((l < minl) || ((maxl > 0) && (l > maxl))) {
        if (!is_daemonised) {
            // when called we have not detached from
            // the console so we can write back an
            // error

            std::cerr << thread_id << "Config problem; check allowed values for " << emessage << std::endl;
        }
        syslog(LOG_ERR, "Config problem; check allowed values for %s", emessage);
        return false;
    }
    return true;
}
#endif

bool LOptionContainer::readFilterGroupConf()
{
    String prefix(o.conffilename);
    prefix = prefix.before(".conf");
    prefix += "f";
    String file;
    ConfigVar groupnamesfile;
    String groupname;
    bool need_html = false;
    if (o.use_group_names_list) {
        int result = groupnamesfile.readVar(group_names_list_location.c_str(), "=");
        if (result != 0) {
            if (!is_daemonised)
                std::cerr << thread_id << "Error opening group names file: " << group_names_list_location << std::endl;
            syslog(LOG_ERR, "Error opening group names file: %s", group_names_list_location.c_str());
            return false;
        }
    }
    for (int i = 1; i <= o.filter_groups; i++) {
        file = prefix;
        file += String(i);
        file += ".conf";
        if (o.use_group_names_list) {
            std::ostringstream groupnum;
            groupnum << i;
            groupname = groupnamesfile[groupnum.str().c_str()];
            if (groupname.length() == 0) {
                if (!is_daemonised)
                    std::cerr << thread_id << "Group names file too short: " << group_names_list_location << std::endl;
                syslog(LOG_ERR, "Group names file too short: %s", group_names_list_location.c_str());
                return false;
            }
#ifdef E2DEBUG
            std::cerr << thread_id << "Group name: " << groupname << std::endl;
#endif
        }
        if (!readAnotherFilterGroupConf(file.toCharArray(), groupname.toCharArray(), need_html, i)) {
            if (!is_daemonised) {
                std::cerr << thread_id << "Error opening filter group config: " << file << std::endl;
            }
            syslog(LOG_ERR, "Error opening filter group config: %s", file.toCharArray());
            return false;
        }
    }
    return true;
}

bool LOptionContainer::readAnotherFilterGroupConf(const char *filename, const char *groupname, bool &need_html, int fg_no)
{
#ifdef E2DEBUG
    std::cerr << thread_id << "adding filter group: " << numfg << " " << filename << std::endl;
#endif

    // array of pointers to FOptionContainer
    typedef FOptionContainer *PFOptionContainer;
    FOptionContainer **temp = new PFOptionContainer[numfg + 1];
    for (int i = 0; i < numfg; i++) {
        temp[i] = fg[i];
    }
    if (numfg > 0) {
        delete[] fg;
    }
    fg = temp;
    fg[numfg] = new FOptionContainer;

#ifdef E2DEBUG
    std::cerr << thread_id << "added filter group: " << numfg << " " << filename << std::endl;
#endif

    // pass all the vars from OptionContainer needed
    (*fg[numfg]).weighted_phrase_mode = o.weighted_phrase_mode;
    (*fg[numfg]).force_quick_search = o.force_quick_search;
    (*fg[numfg]).reverse_lookups = o.reverse_lookups;

    // pass in the group name
    (*fg[numfg]).name = groupname;

    // pass in the group number
    (*fg[numfg]).filtergroup = fg_no;

    // pass in the reporting level - can be overridden
    (*fg[numfg]).reporting_level = reporting_level;

#ifdef E2DEBUG
    std::cerr << thread_id << "passed variables to filter group: " << numfg << " " << filename << std::endl;
#endif

    bool rc = (*fg[numfg]).read(filename);
#ifdef E2DEBUG
    std::cerr << thread_id << "read filter group: " << numfg << " " << filename << " return is " << rc << std::endl;
#endif

    numfg++;

    if (!rc) {
        return false;
    }
    return true;
}

static std::string trim_str(const std::string &s)
{
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos)
        return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static std::string to_lower_str(std::string s)
{
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] >= 'A' && s[i] <= 'Z')
            s[i] = s[i] - 'A' + 'a';
    }
    return s;
}

static std::vector<std::string> split_tokens(const std::string &str, const char *delims)
{
    std::vector<std::string> out;
    size_t start = 0;
    while (start < str.size()) {
        size_t pos = str.find_first_of(delims, start);
        if (pos == std::string::npos) {
            std::string tok = trim_str(str.substr(start));
            if (!tok.empty())
                out.push_back(tok);
            break;
        }
        std::string tok = trim_str(str.substr(start, pos - start));
        if (!tok.empty())
            out.push_back(tok);
        start = pos + 1;
    }
    return out;
}

static void parse_ip_spec_list(const std::string &spec,
                               std::vector<uint32_t> &ips,
                               std::vector<ipl_rangestruct> &ranges,
                               std::vector<ipl_subnetstruct> &subnets)
{
    std::vector<std::string> tokens = split_tokens(spec, ",; ");
    for (const auto &tok : tokens) {
        size_t slash_pos = tok.find('/');
        size_t dash_pos = tok.find('-');
        if (slash_pos != std::string::npos) {
            std::string ip_part = trim_str(tok.substr(0, slash_pos));
            std::string mask_part = trim_str(tok.substr(slash_pos + 1));
            struct in_addr addr;
            if (inet_aton(ip_part.c_str(), &addr) == 0)
                continue;
            uint32_t host_ip = ntohl(addr.s_addr);
            uint32_t mask = 0;
            if (mask_part.find('.') != std::string::npos) {
                struct in_addr maddr;
                if (inet_aton(mask_part.c_str(), &maddr) == 0)
                    continue;
                mask = ntohl(maddr.s_addr);
            } else {
                int cidr = atoi(mask_part.c_str());
                if (cidr < 0 || cidr > 32)
                    continue;
                mask = (cidr == 0) ? 0 : (0xFFFFFFFFu << (32 - cidr));
            }
            ipl_subnetstruct sub;
            sub.mask = mask;
            sub.maskedaddr = host_ip & mask;
            subnets.push_back(sub);
        } else if (dash_pos != std::string::npos) {
            std::string start_part = trim_str(tok.substr(0, dash_pos));
            std::string end_part = trim_str(tok.substr(dash_pos + 1));
            struct in_addr saddr, eaddr;
            if (inet_aton(start_part.c_str(), &saddr) != 0 && inet_aton(end_part.c_str(), &eaddr) != 0) {
                ipl_rangestruct r;
                r.startaddr = ntohl(saddr.s_addr);
                r.endaddr = ntohl(eaddr.s_addr);
                if (r.startaddr > r.endaddr)
                    std::swap(r.startaddr, r.endaddr);
                ranges.push_back(r);
            }
        } else {
            struct in_addr addr;
            if (inet_aton(tok.c_str(), &addr) != 0) {
                ips.push_back(ntohl(addr.s_addr));
            }
        }
    }
    std::sort(ips.begin(), ips.end());
}

static bool match_ip_spec(const std::string &ip_str,
                          const std::vector<uint32_t> &ips,
                          const std::vector<ipl_rangestruct> &ranges,
                          const std::vector<ipl_subnetstruct> &subnets)
{
    if (ip_str.empty())
        return false;
    struct in_addr addr;
    if (inet_aton(ip_str.c_str(), &addr) == 0)
        return false;
    uint32_t ip = ntohl(addr.s_addr);
    if (std::binary_search(ips.begin(), ips.end(), ip))
        return true;
    for (const auto &r : ranges) {
        if (ip >= r.startaddr && ip <= r.endaddr)
            return true;
    }
    for (const auto &s : subnets) {
        if ((ip & s.mask) == s.maskedaddr)
            return true;
    }
    return false;
}

static std::string lookup_interface_ipv4(const std::string &if_name)
{
    if (if_name.empty())
        return "";
    struct ifaddrs *ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1)
        return "";
    std::string result;
    for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_name == nullptr)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET && if_name == ifa->ifa_name) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            char buf[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) != nullptr) {
                result = buf;
                break;
            }
        }
    }
    freeifaddrs(ifaddr);
    return result;
}

void LOptionContainer::loadGatewayRules(const std::string &filename)
{
    gateway_rules.clear();
    gateways_map.clear();
    gateway_groups_map.clear();

    if (filename.empty())
        return;

    std::ifstream infile(filename.c_str(), std::ios::in);
    if (!infile.good()) {
        return; // gatewayrules file is optional
    }

    std::string line;
    while (std::getline(infile, line)) {
        std::string trimmed = trim_str(line);
        if (trimmed.empty() || trimmed[0] == '#')
            continue;

        std::vector<std::string> fields;
        size_t start = 0;
        while (true) {
            size_t pos = trimmed.find('|', start);
            if (pos == std::string::npos) {
                fields.push_back(trim_str(trimmed.substr(start)));
                break;
            }
            fields.push_back(trim_str(trimmed.substr(start, pos - start)));
            start = pos + 1;
        }
        if (fields.empty())
            continue;

        std::string type = to_lower_str(fields[0]);
        if (type == "gateway" && fields.size() >= 6) {
            // GATEWAY|name|if_name|local_ip|gw_ip|tos|status
            GatewayEndpoint ep;
            ep.name = fields[1];
            ep.if_name = fields[2];
            ep.local_ip = fields[3];
            ep.gw_ip = fields[4];
            ep.tos = (int)strtol(fields[5].c_str(), nullptr, 0);
            if (fields.size() >= 7) {
                std::string st = to_lower_str(fields[6]);
                ep.up = (st != "down" && st != "0" && st != "false" && st != "offline");
            } else {
                ep.up = true;
            }
            if ((ep.local_ip.empty() || ep.local_ip == "dynamic" || ep.local_ip == "0.0.0.0") && !ep.if_name.empty()) {
                ep.local_ip = lookup_interface_ipv4(ep.if_name);
            }
            gateways_map[ep.name] = ep;
        } else if (type == "gwgroup" && fields.size() >= 3) {
            // GWGROUP|group_name|gw1:tier:weight:up,gw2:tier:weight:up
            std::string gname = fields[1];
            std::vector<GatewayEndpoint> group_eps;
            std::vector<std::string> members = split_tokens(fields[2], ",");
            for (const auto &m : members) {
                std::vector<std::string> parts = split_tokens(m, ":");
                if (parts.empty())
                    continue;
                std::string gw_name = parts[0];
                int tier = (parts.size() >= 2) ? atoi(parts[1].c_str()) : 1;
                int weight = (parts.size() >= 3) ? atoi(parts[2].c_str()) : 1;
                if (tier < 1) tier = 1;
                if (weight < 1) weight = 1;
                bool member_up = true;
                if (parts.size() >= 4) {
                    std::string st = to_lower_str(parts[3]);
                    member_up = (st != "down" && st != "0" && st != "false" && st != "offline");
                }
                auto it = gateways_map.find(gw_name);
                if (it != gateways_map.end()) {
                    GatewayEndpoint ep = it->second;
                    ep.tier = tier;
                    ep.weight = weight;
                    ep.up = ep.up && member_up;
                    group_eps.push_back(ep);
                } else {
                    GatewayEndpoint ep;
                    ep.name = gw_name;
                    ep.tier = tier;
                    ep.weight = weight;
                    ep.up = member_up;
                    group_eps.push_back(ep);
                }
            }
            gateway_groups_map[gname] = group_eps;
        } else if (type == "rule" && fields.size() >= 6) {
            // RULE|src_type|src_val|dst_type|dst_val|gateway|rule_name
            GatewayRule rule;
            std::string stype = to_lower_str(fields[1]);
            std::string sval = fields[2];
            std::string dtype = to_lower_str(fields[3]);
            std::string dval = fields[4];
            rule.gateway = fields[5];
            if (fields.size() >= 7)
                rule.name = fields[6];

            if (stype == "ip") {
                rule.src_type = GatewayRule::SRC_IP;
                parse_ip_spec_list(sval, rule.src_ips, rule.src_ranges, rule.src_subnets);
            } else if (stype == "user") {
                rule.src_type = GatewayRule::SRC_USER;
                std::vector<std::string> utoks = split_tokens(sval, ",;");
                for (const auto &u : utoks) {
                    std::string lu = to_lower_str(u);
                    if (!lu.empty())
                        rule.src_users.push_back(lu);
                }
            } else {
                rule.src_type = GatewayRule::SRC_ANY;
            }

            if (dtype == "domain") {
                rule.dst_type = GatewayRule::DST_DOMAIN;
                std::vector<std::string> dtoks = split_tokens(dval, ",; ");
                for (const auto &d : dtoks) {
                    std::string ld = to_lower_str(d);
                    if (ld.find("://") != std::string::npos)
                        ld = ld.substr(ld.find("://") + 3);
                    if (ld.find('/') != std::string::npos)
                        ld = ld.substr(0, ld.find('/'));
                    if (ld.find(':') != std::string::npos)
                        ld = ld.substr(0, ld.find(':'));
                    if (ld.empty())
                        continue;
                    if (ld.size() > 2 && ld[0] == '*' && ld[1] == '.') {
                        rule.dst_domains_wild.push_back(ld.substr(2));
                    } else if (ld.size() > 1 && ld[0] == '.') {
                        rule.dst_domains_wild.push_back(ld.substr(1));
                    } else {
                        rule.dst_domains_exact.push_back(ld);
                    }
                }
            } else if (dtype == "url") {
                rule.dst_type = GatewayRule::DST_URL;
                std::vector<std::string> utoks = split_tokens(dval, ",; ");
                for (const auto &u : utoks) {
                    std::string lu = to_lower_str(u);
                    if (lu.find("://") != std::string::npos)
                        lu = lu.substr(lu.find("://") + 3);
                    while (!lu.empty() && lu.back() == '/')
                        lu.pop_back();
                    if (!lu.empty())
                        rule.dst_urls.push_back(lu);
                }
            } else if (dtype == "ip") {
                rule.dst_type = GatewayRule::DST_IP;
                parse_ip_spec_list(dval, rule.dst_ips, rule.dst_ranges, rule.dst_subnets);
            } else {
                rule.dst_type = GatewayRule::DST_ANY;
            }

            gateway_rules.push_back(rule);
        }
    }

    syslog(LOG_INFO, "Loaded %zu gateway definitions, %zu gateway groups, and %zu outbound gateway rules",
           gateways_map.size(), gateway_groups_map.size(), gateway_rules.size());
}

std::string LOptionContainer::matchGatewayRule(const std::string &client_ip, const std::string &client_user,
                                               const String &domain, const String &url, const std::string &dest_ip) const
{
    if (gateway_rules.empty())
        return "";

    std::string norm_user = to_lower_str(trim_str(client_user));
    std::string short_user = norm_user;
    size_t bslash = short_user.find_last_of('\\');
    if (bslash != std::string::npos)
        short_user = short_user.substr(bslash + 1);
    size_t fslash = short_user.find_last_of('/');
    if (fslash != std::string::npos)
        short_user = short_user.substr(fslash + 1);
    size_t atpos = short_user.find('@');
    if (atpos != std::string::npos)
        short_user = short_user.substr(0, atpos);

    std::string norm_domain = to_lower_str(domain.c_str());
    if (norm_domain.find(':') != std::string::npos)
        norm_domain = norm_domain.substr(0, norm_domain.find(':'));

    std::string norm_url = to_lower_str(url.c_str());
    if (norm_url.find("://") != std::string::npos)
        norm_url = norm_url.substr(norm_url.find("://") + 3);

    for (const auto &rule : gateway_rules) {
        // 1. Check Source
        bool src_ok = false;
        if (rule.src_type == GatewayRule::SRC_ANY) {
            src_ok = true;
        } else if (rule.src_type == GatewayRule::SRC_IP) {
            src_ok = match_ip_spec(client_ip, rule.src_ips, rule.src_ranges, rule.src_subnets);
        } else if (rule.src_type == GatewayRule::SRC_USER) {
            if (!norm_user.empty() && norm_user != "-") {
                for (const auto &ru : rule.src_users) {
                    if (ru == norm_user || ru == short_user) {
                        src_ok = true;
                        break;
                    }
                }
            }
        }
        if (!src_ok)
            continue;

        // 2. Check Destination
        bool dst_ok = false;
        if (rule.dst_type == GatewayRule::DST_ANY) {
            dst_ok = true;
        } else if (rule.dst_type == GatewayRule::DST_DOMAIN) {
            if (!norm_domain.empty()) {
                for (const auto &ed : rule.dst_domains_exact) {
                    if (norm_domain == ed) {
                        dst_ok = true;
                        break;
                    }
                }
                if (!dst_ok) {
                    for (const auto &wd : rule.dst_domains_wild) {
                        if (norm_domain == wd) {
                            dst_ok = true;
                            break;
                        }
                        if (norm_domain.size() > wd.size() + 1 &&
                            norm_domain[norm_domain.size() - wd.size() - 1] == '.' &&
                            norm_domain.compare(norm_domain.size() - wd.size(), wd.size(), wd) == 0) {
                            dst_ok = true;
                            break;
                        }
                    }
                }
            }
        } else if (rule.dst_type == GatewayRule::DST_URL) {
            if (!norm_url.empty()) {
                for (const auto &u : rule.dst_urls) {
                    if (norm_url.compare(0, u.size(), u) == 0) {
                        if (norm_url.size() == u.size() ||
                            norm_url[u.size()] == '/' ||
                            norm_url[u.size()] == '?' ||
                            norm_url[u.size()] == '&' ||
                            norm_url[u.size()] == ':') {
                            dst_ok = true;
                            break;
                        }
                    }
                    // Also check if URL pattern has no path and matches subdomain prefix or substring
                    size_t pos = norm_url.find(u);
                    if (pos != std::string::npos) {
                        bool left_ok = (pos == 0 || norm_url[pos - 1] == '.');
                        size_t end_pos = pos + u.size();
                        bool right_ok = (end_pos == norm_url.size() ||
                                         norm_url[end_pos] == '/' ||
                                         norm_url[end_pos] == '?' ||
                                         norm_url[end_pos] == '&' ||
                                         norm_url[end_pos] == ':');
                        if (left_ok && right_ok) {
                            dst_ok = true;
                            break;
                        }
                    }
                }
            }
        } else if (rule.dst_type == GatewayRule::DST_IP) {
            dst_ok = match_ip_spec(dest_ip, rule.dst_ips, rule.dst_ranges, rule.dst_subnets);
            if (!dst_ok && !norm_domain.empty() && norm_domain != dest_ip) {
                dst_ok = match_ip_spec(norm_domain, rule.dst_ips, rule.dst_ranges, rule.dst_subnets);
            }
        }

        if (dst_ok) {
            return rule.gateway;
        }
    }

    return "";
}

std::vector<GatewayEndpoint> LOptionContainer::getGatewayEndpoints(const std::string &gw_name) const
{
    std::vector<GatewayEndpoint> result;
    if (gw_name.empty() || gw_name == "default" || gw_name == "DEFAULT")
        return result;

    auto git = gateways_map.find(gw_name);
    if (git != gateways_map.end()) {
        GatewayEndpoint ep = git->second;
        if (ep.local_ip.empty() && !ep.if_name.empty()) {
            ep.local_ip = lookup_interface_ipv4(ep.if_name);
        }
        result.push_back(ep);
        return result;
    }

    auto gpit = gateway_groups_map.find(gw_name);
    if (gpit != gateway_groups_map.end()) {
        const auto &members = gpit->second;
        std::map<int, std::vector<GatewayEndpoint>> tiers_up;
        std::map<int, std::vector<GatewayEndpoint>> tiers_down;
        for (auto ep : members) {
            auto mgit = gateways_map.find(ep.name);
            if (mgit != gateways_map.end()) {
                ep.if_name = mgit->second.if_name;
                ep.local_ip = mgit->second.local_ip;
                ep.gw_ip = mgit->second.gw_ip;
                ep.tos = mgit->second.tos;
                ep.up = ep.up && mgit->second.up;
            }
            if (ep.local_ip.empty() && !ep.if_name.empty()) {
                ep.local_ip = lookup_interface_ipv4(ep.if_name);
            }
            if (ep.up) {
                tiers_up[ep.tier].push_back(ep);
            } else {
                tiers_down[ep.tier].push_back(ep);
            }
        }

        uint32_t seq = gw_rr_counter.fetch_add(1, std::memory_order_relaxed);
        auto append_tier = [&](const std::vector<GatewayEndpoint> &tier_eps) {
            if (tier_eps.empty())
                return;
            if (tier_eps.size() == 1) {
                result.push_back(tier_eps[0]);
                return;
            }
            int total_weight = 0;
            for (const auto &e : tier_eps) {
                total_weight += (e.weight > 0 ? e.weight : 1);
            }
            int pick = (total_weight > 0) ? (int)(seq % (uint32_t)total_weight) : 0;
            size_t primary_idx = 0;
            int accum = 0;
            for (size_t i = 0; i < tier_eps.size(); ++i) {
                accum += (tier_eps[i].weight > 0 ? tier_eps[i].weight : 1);
                if (pick < accum) {
                    primary_idx = i;
                    break;
                }
            }
            result.push_back(tier_eps[primary_idx]);
            for (size_t i = 1; i < tier_eps.size(); ++i) {
                size_t idx = (primary_idx + i) % tier_eps.size();
                result.push_back(tier_eps[idx]);
            }
        };

        for (const auto &kv : tiers_up) {
            append_tier(kv.second);
        }
        for (const auto &kv : tiers_down) {
            append_tier(kv.second);
        }
    }

    return result;
}

