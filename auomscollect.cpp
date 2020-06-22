/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
#include "StdoutWriter.h"
#include "StdinReader.h"
#include "UnixDomainWriter.h"
#include "Signals.h"
#include "Queue.h"
#include "Config.h"
#include "Logger.h"
#include "EventQueue.h"
#include "Output.h"
#include "RawEventRecord.h"
#include "RawEventAccumulator.h"
#include "Netlink.h"
#include "FileWatcher.h"
#include "Defer.h"
#include "Gate.h"
#include "FileUtils.h"
#include "Metrics.h"
#include "ProcMetrics.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <thread>
#include <system_error>
#include <csignal>

#include <unistd.h>
#include <syslog.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#include "env_config.h"
#include "LockFile.h"

void usage()
{
    std::cerr <<
              "Usage:\n"
              "auomscollect [-c <config>]\n"
              "\n"
              "-c <config>   - The path to the config file.\n"
            ;
    exit(1);
}

bool parsePath(std::vector<std::string>& dirs, const std::string& path_str) {
    std::string str = path_str;
    while (!str.empty()) {
        auto idx = str.find_first_of(':', 0);
        std::string dir;
        if (idx == std::string::npos) {
            dir = str;
            str.clear();
        } else {
            dir = str.substr(0, idx);
            str = str.substr(idx+1);
        }
        if (dir.length() < 2 || dir[0] != '/') {
            Logger::Error("Config parameter 'allowed_socket_dirs' has invalid value");
            return false;
        }
        if (dir[dir.length()-1] != '/') {
            dir += '/';
        }
        dirs.push_back(dir);
    }
    return true;
}


void DoStdinCollection(RawEventAccumulator& accumulator) {
    StdinReader reader;

    try {
        std::unique_ptr<RawEventRecord> record = std::make_unique<RawEventRecord>();

        for (;;) {
            ssize_t nr = reader.ReadLine(record->Data(), RawEventRecord::MAX_RECORD_SIZE, 100, [] {
                return Signals::IsExit();
            });
            if (nr > 0) {
                if (record->Parse(RecordType::UNKNOWN, nr)) {
                    accumulator.AddRecord(std::move(record));
                    record = std::make_unique<RawEventRecord>();
                } else {
                    Logger::Warn("Received unparsable event data: '%s'", std::string(record->Data(), nr).c_str());
                }
            } else if (nr == StdinReader::TIMEOUT) {
                if (Signals::IsExit()) {
                    Logger::Info("Exiting input loop");
                    break;
                }
                accumulator.Flush(200);
            } else { // nr == StdinReader::CLOSED, StdinReader::FAILED or StdinReader::INTERRUPTED
                if (nr == StdinReader::CLOSED) {
                    Logger::Info("STDIN closed, exiting input loop");
                } else if (nr == StdinReader::FAILED) {
                    Logger::Error("Encountered an error while reading STDIN, exiting input loop");
                }
                break;
            }
        }
    } catch (const std::exception &ex) {
        Logger::Error("Unexpected exception in input loop: %s", ex.what());
        exit(1);
    } catch (...) {
        Logger::Error("Unexpected exception in input loop");
        exit(1);
    }
}

bool DoNetlinkCollection(RawEventAccumulator& accumulator) {
    // Request that that this process receive a SIGTERM if the parent process (thread in parent) dies/exits.
    auto ret = prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (ret != 0) {
        Logger::Warn("prctl(PR_SET_PDEATHSIG, SIGTERM) failed: %s", std::strerror(errno));
    }

    Netlink data_netlink;
    Netlink netlink;
    Gate _stop_gate;

    FileWatcher::notify_fn_t fn = [&_stop_gate](const std::string& dir, const std::string& name, uint32_t mask) {
        if (name == "auditd" && (mask & (IN_CREATE|IN_MOVED_TO)) != 0) {
            Logger::Info("/sbin/auditd found on the system, exiting.");
            _stop_gate.Open();
        }
    };

    FileWatcher watcher(std::move(fn), {
            {"/sbin", IN_CREATE|IN_MOVED_TO},
    });

    std::function handler = [&accumulator](uint16_t type, uint16_t flags, const void* data, size_t len) -> bool {
        // Ignore AUDIT_REPLACE for now since replying to it doesn't actually do anything.
        if (type >= AUDIT_FIRST_USER_MSG && type != static_cast<uint16_t>(RecordType::REPLACE)) {
            std::unique_ptr<RawEventRecord> record = std::make_unique<RawEventRecord>();
            std::memcpy(record->Data(), data, len);
            if (record->Parse(static_cast<RecordType>(type), len)) {
                accumulator.AddRecord(std::move(record));
            } else {
                char cdata[len+1];
                ::memcpy(cdata, data, len);
                cdata[len] = 0;
                Logger::Warn("Received unparsable event data (type = %d, flags = 0x%X, size=%ld:\n%s)", type, flags, len, cdata);
            }
        }
        return false;
    };

    Logger::Info("Connecting to AUDIT NETLINK socket");
    ret = data_netlink.Open(std::move(handler));
    if (ret != 0) {
        Logger::Error("Failed to open AUDIT NETLINK connection: %s", std::strerror(-ret));
        return false;
    }
    Defer _close_data_netlink([&data_netlink]() { data_netlink.Close(); });

    ret = netlink.Open(nullptr);
    if (ret != 0) {
        Logger::Error("Failed to open AUDIT NETLINK connection: %s", std::strerror(-ret));
        return false;
    }
    Defer _close_netlink([&netlink]() { netlink.Close(); });

    watcher.Start();
    Defer _stop_watcher([&watcher]() { watcher.Stop(); });

    uint32_t our_pid = getpid();

    Logger::Info("Checking assigned audit pid");
    audit_status status;
    ret = NetlinkRetry([&netlink,&status]() { return netlink.AuditGet(status); } );
    if (ret != 0) {
        Logger::Error("Failed to get audit status: %s", std::strerror(-ret));
        return false;
    }
    uint32_t pid = status.pid;
    uint32_t enabled = status.enabled;

    if (pid != 0 && PathExists("/proc/" + std::to_string(pid))) {
        Logger::Error("There is another process (pid = %d) already assigned as the audit collector", pid);
        return false;
    }

    Logger::Info("Enabling AUDIT event collection");
    int retry_count = 0;
    do {
        if (retry_count > 5) {
            Logger::Error("Failed to set audit pid: Max retried exceeded");
        }
        ret = data_netlink.AuditSetPid(our_pid);
        if (ret == -ETIMEDOUT) {
            // If setpid timedout, it may have still succeeded, so re-fetch pid
            ret = NetlinkRetry([&]() { return netlink.AuditGetPid(pid); });
            if (ret != 0) {
                Logger::Error("Failed to get audit pid: %s", std::strerror(-ret));
                return false;
            }
        } else if (ret != 0) {
            Logger::Error("Failed to set audit pid: %s", std::strerror(-ret));
            return false;
        } else {
            break;
        }
        retry_count += 1;
    } while (pid != our_pid);
    if (enabled == 0) {
        ret = NetlinkRetry([&netlink,&status]() { return netlink.AuditSetEnabled(1); });
        if (ret != 0) {
            Logger::Error("Failed to enable auditing: %s", std::strerror(-ret));
            return false;
        }
    }

    Defer _revert_enabled([&netlink,enabled]() {
        if (enabled == 0) {
            int ret;
            ret = NetlinkRetry([&netlink]() { return netlink.AuditSetEnabled(1); });
            if (ret != 0) {
                Logger::Error("Failed to enable auditing: %s", std::strerror(-ret));
            }
        }
    });

    Signals::SetExitHandler([&_stop_gate]() { _stop_gate.Open(); });

    auto _last_pid_check = std::chrono::steady_clock::now();
    while(!Signals::IsExit()) {
        if (_stop_gate.Wait(Gate::OPEN, 100)) {
            return false;
        }

        try {
            accumulator.Flush(200);
        } catch (const std::exception &ex) {
            Logger::Error("Unexpected exception while flushing input: %s", ex.what());
            exit(1);
        } catch (...) {
            Logger::Error("Unexpected exception while flushing input");
            exit(1);
        }

        auto now = std::chrono::steady_clock::now();
        if (_last_pid_check < now - std::chrono::seconds(10)) {
            _last_pid_check = now;
            pid = 0;
            int ret;
            ret = NetlinkRetry([&netlink,&pid]() { return netlink.AuditGetPid(pid); });
            if (ret != 0) {
                if (ret == -ECANCELED || ret == -ENOTCONN) {
                    if (!Signals::IsExit()) {
                        Logger::Error("AUDIT NETLINK connection has closed unexpectedly");
                    }
                } else {
                    Logger::Error("Failed to get audit pid: %s", std::strerror(-ret));
                }
                return false;
            } else {
                if (pid != our_pid) {
                    if (pid != 0) {
                        Logger::Warn("Another process (pid = %d) has taken over AUDIT NETLINK event collection.", pid);
                        return false;
                    } else {
                        Logger::Warn("Audit pid was unexpectedly set to 0, restarting...");
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

int main(int argc, char**argv) {
    // Enable core dumps
    struct rlimit limits;
    limits.rlim_cur = RLIM_INFINITY;
    limits.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &limits);

    std::string config_file = AUOMSCOLLECT_CONF;
    int stop_delay = 0; // seconds
    bool netlink_mode = false;

    int opt;
    while ((opt = getopt(argc, argv, "c:ns:")) != -1) {
        switch (opt) {
            case 'c':
                config_file = optarg;
                break;
            case 's':
                stop_delay = atoi(optarg);
                break;
            case 'n':
                netlink_mode = true;
                break;
            default:
                usage();
        }
    }

    auto user_db = std::make_shared<UserDB>();

    try {
        user_db->Start();
    } catch (const std::exception& ex) {
        Logger::Error("Unexpected exception during user_db startup: %s", ex.what());
        exit(1);
    } catch (...) {
        Logger::Error("Unexpected exception during user_db startup");
        exit(1);
    }

    Config config;

    if (!config_file.empty()) {
        try {
            config.Load(config_file);
        } catch (std::runtime_error& ex) {
            Logger::Error("%s", ex.what());
            exit(1);
        }
    }

    std::string data_dir = AUOMS_DATA_DIR;
    std::string run_dir = AUOMS_RUN_DIR;

    if (config.HasKey("data_dir")) {
        data_dir = config.GetString("data_dir");
    }

    if (config.HasKey("run_dir")) {
        run_dir = config.GetString("run_dir");
    }

    std::string socket_path = run_dir + "/input.socket";

    std::string cursor_path = data_dir + "/collect.cursor";
    std::string queue_file = data_dir + "/collect_queue.dat";

    if (config.HasKey("socket_path")) {
        socket_path = config.GetString("socket_path");
    }

    if (config.HasKey("cursor_path")) {
        cursor_path = config.GetString("cursor_path");
    }

    size_t queue_size = 10*1024*1024;

    if (config.HasKey("queue_file")) {
        queue_file = config.GetString("queue_file");
    }

    if (queue_file.empty()) {
        Logger::Error("Invalid 'queue_file' value");
        exit(1);
    }

    if (config.HasKey("queue_size")) {
        try {
            queue_size = config.GetUint64("queue_size");
        } catch(std::exception& ex) {
            Logger::Error("Invalid 'queue_size' value: %s", config.GetString("queue_size").c_str());
            exit(1);
        }
    }

    std::string lock_file = data_dir + "/auomscollect.lock";

    if (config.HasKey("lock_file")) {
        lock_file = config.GetString("lock_file");
    }

    if (queue_size < Queue::MIN_QUEUE_SIZE) {
        Logger::Warn("Value for 'queue_size' (%ld) is smaller than minimum allowed. Using minimum (%ld).", queue_size, Queue::MIN_QUEUE_SIZE);
        exit(1);
    }

    bool use_syslog = true;
    if (config.HasKey("use_syslog")) {
        use_syslog = config.GetBool("use_syslog");
    }

    if (use_syslog) {
        Logger::OpenSyslog("auomscollect", LOG_DAEMON);
    }

    bool reset_queue = false;
    bool reset_flagged = false;

    Logger::Info("Trying to acquire singleton lock");
    LockFile singleton_lock(lock_file);
    switch(singleton_lock.Lock()) {
        case LockFile::FAILED:
            Logger::Error("Failed to acquire singleton lock (%s): %s", lock_file.c_str(), std::strerror(errno));
            exit(1);
            break;
        case LockFile::FLAGGED:
            reset_flagged = true;
        case LockFile::PREVIOUSLY_ABANDONED:
            reset_queue = true;
            break;
        case LockFile::INTERRUPTED:
            Logger::Error("Failed to acquire singleton lock (%s): Interrupted", lock_file.c_str());
            exit(1);
            break;
    }
    Logger::Info("Acquire singleton lock");

    // This will block signals like SIGINT and SIGTERM
    // They will be handled once Signals::Start() is called.
    Signals::Init();

    if (reset_queue) {
        if (reset_flagged) {
            Logger::Info("Resetting queue due to upgrade.");
        } else {
            Logger::Warn("Previous instance may have crashed, resetting queue as a precaution.");
        }
        if (PathExists(queue_file)) {
            try {
                RemoveFile(queue_file, true);
            } catch (std::system_error& ex) {
                Logger::Error("Failed to remove queue file: %s", ex.what());
            }
        }
        if (PathExists(cursor_path)) {
            try {
                RemoveFile(cursor_path, true);
            } catch (std::system_error& ex) {
                Logger::Error("Failed to remove queue cursor: %s", ex.what());
            }
        }
    }


    auto queue = std::make_shared<Queue>(queue_file, queue_size);
    try {
        Logger::Info("Opening queue: %s", queue_file.c_str());
        queue->Open();
    } catch (std::runtime_error& ex) {
        Logger::Error("Failed to open queue file '%s': %s", queue_file.c_str(), ex.what());
        exit(1);
    }

    auto event_queue = std::make_shared<EventQueue>(queue);
    auto builder = std::make_shared<EventBuilder>(event_queue);

    auto metrics = std::make_shared<Metrics>(queue);
    metrics->Start();

    auto proc_metrics = std::make_shared<ProcMetrics>("auomscollect", metrics);
    proc_metrics->Start();

    RawEventAccumulator accumulator (builder, metrics);

    auto output_config = std::make_unique<Config>(std::unordered_map<std::string, std::string>({
        {"output_format","raw"},
        {"output_socket", socket_path},
        {"enable_ack_mode", "true"},
        {"ack_queue_size", "10"}
    }));
    auto writer_factory = std::shared_ptr<IEventWriterFactory>(static_cast<IEventWriterFactory*>(new RawOnlyEventWriterFactory()));
    Output output("output", cursor_path, queue, writer_factory, nullptr);
    output.Load(output_config);

    std::thread autosave_thread([&]() {
        Signals::InitThread();
        try {
            queue->Autosave(128*1024, 250);
        } catch (const std::exception& ex) {
            Logger::Error("Unexpected exception in autosave thread: %s", ex.what());
            exit(1);
        }
    });

    // Start signal handling thread
    Signals::Start();
    output.Start();

    if (netlink_mode) {
        bool restart;
        do {
            restart = DoNetlinkCollection(accumulator);
        } while (restart);
    } else {
        DoStdinCollection(accumulator);
    }

    Logger::Info("Exiting");

    try {
        proc_metrics->Stop();
        metrics->Stop();
        accumulator.Flush(0);
        if (stop_delay > 0) {
            Logger::Info("Waiting %d seconds for output to flush", stop_delay);
            sleep(stop_delay);
        }
        output.Stop();
        queue->Close(); // Close queue, this will trigger exit of autosave thread
        autosave_thread.join(); // Wait for autosave thread to exit
    } catch (const std::exception& ex) {
        Logger::Error("Unexpected exception during exit: %s", ex.what());
        exit(1);
    } catch (...) {
        Logger::Error("Unexpected exception during exit");
        exit(1);
    }

    singleton_lock.Unlock();

    exit(0);
}
