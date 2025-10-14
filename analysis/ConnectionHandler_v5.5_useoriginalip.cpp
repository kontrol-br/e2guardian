// Extract from e2guardian v5.5.8r ConnectionHandler::connectUpstream
if (cm.isdirect) {
    String des_ip;
    if (cm.isiphost)
        des_ip = cm.urldomain;
    if (o.conn.use_original_ip_port && cm.got_orig_ip && (cm.connect_site == cm.urldomain))
        des_ip = cm.orig_ip;
    if (des_ip.length() > 0) {
        // ...
        int rc = sock.connect(des_ip, port);
        if (rc < 0) {
            lerr_mess = 203;
            continue;
        }
        return rc;
    }
}

// Extract from e2guardian v5.5.8r ConnectionHandler::get_original_ip_port
if (getsockopt(peerconn.getFD(), SOL_IP, SO_ORIGINAL_DST, &origaddr, &origaddrlen) < 0) {
    E2LOGGER_error("Failed to get client's original destination IP: ", strerror(errno));
    return false;
} else {
    checkme.orig_ip = inet_ntop(AF_INET, &origaddr.sin_addr, res, sizeof(res));
    if (o.net.check_ip.size() > 0) {
        for (auto it = o.net.check_ip.begin(); it != o.net.check_ip.end(); it++) {
            if (*it == checkme.orig_ip) {
                checkme.orig_ip.clear();
                return false;
            }
        }
    }
    checkme.orig_port = ntohs(origaddr.sin_port);
    checkme.got_orig_ip = true;
    return true;
}

// Extract from e2guardian v5.5.8r OptionContainer::findConnectionHandlerOptions
conn.use_original_ip_port = cr.findoptionB("useoriginalip");
