// SocketArray - wrapper for clean handling of an array of Sockets

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "SocketArray.hpp"
#include "Queue.hpp"

#include <syslog.h>
#include <cerrno>
#include <cstring>

// GLOBALS

extern bool is_daemonised;
extern thread_local std::string thread_id;

// IMPLEMENTATION

SocketArray::~SocketArray()
{
    delete[] drawer;
}

void SocketArray::deleteAll()
{
    delete[] drawer;
    drawer = NULL;
    socknum = 0;
    lc_types.clear();
}

// close all sockets & create new ones
void SocketArray::reset(int sockcount)
{
    delete[] drawer;

    drawer = new Socket[sockcount];
    socknum = sockcount;
    lc_types.clear();
}

// bind our first socket to any IP
int SocketArray::bindSingle(int port)
{
    if (socknum < 1) {
        return -1;
    }
#ifdef E2DEBUG
    std::cerr << thread_id << "bindSingle binding port" << port << std::endl;
#endif
    lc_types.push_back(CT_PROXY);
    return drawer[0].bind(port);
}

int SocketArray::bindSingle(unsigned int index, int port, unsigned int type)
{
    if (socknum <= index) {
        return -1;
    }
#ifdef E2DEBUG
    std::cerr << thread_id << "bindSingle binding port" << port  << " with type " << type << std::endl;
#endif
    lc_types.push_back(type);
    return drawer[index].bind(port);
}


// bind our first socket to any IP and one or more ports
int SocketArray::bindSingleM(std::deque<String> &ports)
{
    if (socknum < ports.size()) {
        return -1;
    }
    for (unsigned int i = 0; i < ports.size(); i++) {
#ifdef E2DEBUG
        std::cerr << thread_id << "bindSingleM binding port" << ports[i] << std::endl;
#endif
        if (drawer[i].bind(ports[i].toInteger())) {
            if (!is_daemonised) {
                std::cerr << thread_id << "Error binding server socket: ["
                          << ports[i] << " " << i << "] (" << strerror(errno) << ")" << std::endl;
            }
            String p = ports[i];
            syslog(LOG_ERR, "Error binding socket: [%s %d] (%s)", p.toCharArray(), i, strerror(errno));
            return -1;
        }
        lc_types.push_back(CT_PROXY);
    }
    return 0;
}

// return an array of our socket FDs
int *SocketArray::getFDAll()
{
    int *fds = new int[socknum];
    for (unsigned int i = 0; i < socknum; i++) {
#ifdef E2DEBUG
        std::cerr << thread_id << "Socket " << i << " fd:" << drawer[i].getFD() << std::endl;
#endif
        fds[i] = drawer[i].getFD();
    }
    return fds;
}

// listen on all IPs with given kernel queue size
int SocketArray::listenAll(int queue)
{
    for (unsigned int i = 0; i < socknum; i++) {
        if (drawer[i].listen(queue)) {
            if (!is_daemonised) {
                std::cerr << thread_id << "Error listening to socket" << std::endl;
            }
            syslog(LOG_ERR, "%s", "Error listening to socket");
            return -1;
        }
    }
    return 0;
}

// bind all sockets to given IP list
int SocketArray::bindAll(std::deque<String> &ips, std::deque<String> &ports, bool map_ports_to_ips)
{
    if (ips.empty() || ports.empty()) {
        return -1;
    }

    const unsigned int mapped_count = ips.size();
    const unsigned int matrix_count = ips.size() * ports.size();

    // mapportstoips=on -> one-to-one IP/port mapping
    if (map_ports_to_ips) {
        if (ports.size() != ips.size()) {
            return -1;
        }
        if (socknum < mapped_count) {
            return -1;
        }

        for (unsigned int i = 0; i < ips.size(); i++) {
#ifdef E2DEBUG
            std::cerr << thread_id << "Binding server socket[" << ports[i] << " " << ips[i] << " " << i << "])" << std::endl;
#endif
            if (drawer[i].bind(ips[i].toCharArray(), ports[i].toInteger())) {
                if (!is_daemonised) {
                    std::cerr << thread_id << "Error binding server socket: ["
                              << ports[i] << " " << ips[i] << " " << i << "] (" << strerror(errno) << ")" << std::endl;
                }
                syslog(LOG_ERR, "Error binding socket: [%s %s %d] (%s)", ports[i].toCharArray(), ips[i].toCharArray(), i, strerror(errno));
                return -1;
            }
            lc_types.push_back(CT_PROXY);
        }
        return 0;
    }

    // mapportstoips=off -> bind all IP x port combinations
    if (socknum < matrix_count) {
        return -1;
    }

    if (!map_ports_to_ips) {
        unsigned int idx = 0;
        for (unsigned int i = 0; i < ips.size(); i++) {
            for (unsigned int p = 0; p < ports.size(); p++) {
#ifdef E2DEBUG
                std::cerr << thread_id << "Binding server socket[" << ports[p] << " " << ips[i] << " " << idx << "])" << std::endl;
#endif
                if (drawer[idx].bind(ips[i].toCharArray(), ports[p].toInteger())) {
                    if (!is_daemonised) {
                        std::cerr << thread_id << "Error binding server socket: ["
                                  << ports[p] << " " << ips[i] << " " << idx << "] (" << strerror(errno) << ")" << std::endl;
                    }
                    syslog(LOG_ERR, "Error binding socket: [%s %s %d] (%s)", ports[p].toCharArray(), ips[i].toCharArray(), idx, strerror(errno));
                    return -1;
                }
                lc_types.push_back(CT_PROXY);
                idx++;
            }
        }
        return 0;
    }

    return -1;
}

// try connecting to all our sockets which are still open to allow tidy close
void SocketArray::self_connect() {
    for (unsigned int i = 0; i < socknum; i++) {
        if (drawer[i].getFD() > -1) {
            std::string sip = drawer[i].getLocalIP();
            int port = drawer[i].getPort();
            Socket temp;
            temp.setTimeout(100);
            temp.connect(sip, port);
            temp.close();
        }
    }
}

unsigned int SocketArray::getType(unsigned int ind) {
    return lc_types.at(ind);
}
