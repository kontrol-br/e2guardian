// Extractos relevantes de FatController.cpp na versão v5.5.8r
// Fonte: https://github.com/e2guardian/e2guardian/releases/tag/v5.5.8r

#include <atomic>

std::atomic<bool> ttg;
std::atomic<bool> e2logger_ttg;
std::atomic<bool> gentlereload;
std::atomic<bool> reloadconfig;
std::atomic<int> reload_cnt;
std::atomic<bool> rotate_access;
std::atomic<bool> rotate_request;
std::atomic<bool> rotate_dstat;

void stat_rec::start(bool firsttime = true) {
    if (firsttime) {
        clear();
        start_int = time(NULL);
        end_int = start_int + o.dstat.dstat_interval;
        maxusedfd = 0;
    }
    if (o.dstat.dstat_log_flag) {
        std::string outmess;
        if (o.dstat.stats_human_readable) {
            outmess = "time                     httpw   busy    httpwQ  logQ    conx    conx/s   reqs   reqs/s  maxfd   LCcnt";
        } else {
            outmess = "time             httpw   busy    httpwQ  logQ    conx    conx/s  reqs    reqs/s  maxfd   LCcnt";
        }
        E2LOGGER_dstatslog(outmess);
        e2logger.flush(LoggerSource::dstatslog);
    }
}

int fc_controlit() {
    sigset_t signal_set;
    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGHUP);
    sigaddset(&signal_set, SIGPIPE);
    sigaddset(&signal_set, SIGTERM);
    sigaddset(&signal_set, SIGUSR1);
    int stat = pthread_sigmask(SIG_BLOCK, &signal_set, NULL);
    if (stat != 0) {
        E2LOGGER_error("Error setting sigmask");
        return 1;
    }

    if (e2logger.isEnabled(LoggerSource::accesslog)) {
        std::thread log_thread(log_listener, o.log.log_Q, false);
        log_thread.detach();
    }
    if (e2logger.isEnabled(LoggerSource::requestlog)) {
        std::thread RQlog_thread(log_listener, o.log.RQlog_Q, true);
        RQlog_thread.detach();
    }

    while (failurecount < 30 && !ttg && !reloadconfig) {
        int rc = sigtimedwait(&signal_set, NULL, &timeout);
        if (rc == SIGUSR1) {
            rotate_access = true;
            rotate_request = true;
            rotate_dstat = true;
        }
    }
}

void log_listener(Queue<std::string> *log_Q, bool is_RQlog) {
    while (!e2logger_ttg) {
        std::string loglines = log_Q->pop();
        if (e2logger_ttg) break;
        if (is_RQlog && rotate_request) {
            e2logger.rotate(LoggerSource::requestlog);
            rotate_request = false;
        } else if (!is_RQlog && rotate_access) {
            e2logger.rotate(LoggerSource::accesslog);
            rotate_access = false;
        }
        // ... processamento de log ...
    }
}
