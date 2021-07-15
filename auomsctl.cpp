/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "auoms_version.h"

#include "Netlink.h"
#include "Logger.h"
#include "Signals.h"
#include "AuditRules.h"
#include "StringUtils.h"
#include "UnixDomainWriter.h"
#include "ExecUtil.h"
#include "FileUtils.h"
#include "Defer.h"
#include "Gate.h"
#include "Translate.h"
#include "UnixDomainListener.h"
#include "Event.h"
#include "AuditStatus.h"

#include <iostream>

#include <unistd.h>
#include <cstring>
#include <sys/stat.h>
#include <sstream>

#include "env_config.h"
#include "KernelInfo.h"
#include "CmdlineRedactor.h"

#define AUOMS_SERVICE_NAME "auoms"
#define AUDITD_SERVICE_NAME "auditd"
#define AUOMS_COMM "auoms"
#define AUOMSCOLLECT_COMM "auomscollect"
#define AUDITD_COMM "auditd"

#define ETC_AUDIT_PLUGINS_DIR "/etc/audit/plugins.d"
#define ETC_AUDISP_PLUGINS_DIR "/etc/audisp/plugins.d"

#define ETC_AUDIT_PLUGINS_AUOMS_CONF "/etc/audit/plugins.d/auoms.conf"
#define ETC_AUDISP_PLUGINS_AUOMS_CONF "/etc/audisp/plugins.d/auoms.conf"

#define PROC_WAIT_TIME 10

void usage()
{
    std::cerr <<
              "Usage:\n"
              "auomsctl [options]\n"
              "\n"
              "-l [<key>]            - List kernel audit rules.\n"
              "-s                    - List kernel audit settings.\n"
              "-D [<key>]            - Delete kernel audit rules.\n"
              "-R <rules file>       - Set kernel audit rules from files.\n"
              "-v                    - Print auoms version.\n"
              "merge <rules files>   - Merge then print rules files.\n"
              "diff <rules file>     - Diff then print two rules files.\n"
              "desired [-c <config>] - List desired rules as understood by auoms\n"
              "is-enabled            - Report enabled/disabled status ot auoms service\n"
              "enable                - Enable the auoms service (will start auoms if it is not running)\n"
              "disable               - Disable the auoms service (will stop auoms if it is running)\n"
              "status                - Show auoms status\n"
            ;
}

bool check_permissions() {
    if (geteuid() != 0) {
        std::cerr << "Must be root to perform this operation" << std::endl;
        return false;
    }
    return true;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int show_audit_status() {
    if (!check_permissions()) {
        return 1;
    }

    Netlink netlink;
    netlink.SetQuite();

    auto ret = netlink.Open(nullptr);
    if (ret != 0) {
        Logger::Error("Failed to open Netlink socket");
        return 1;
    }

    AuditStatus status;
    ret = NetlinkRetry([&netlink,&status]() { return status.GetStatus(netlink); });

    netlink.Close();

    if (ret != 0) {
        Logger::Error("Failed to retrieve audit status: %s\n", strerror(-ret));
        return 1;
    }

    std::cout << "enabled " << status.GetEnabled() << std::endl;
    std::cout << "failure " << status.GetFailure() << std::endl;
    std::cout << "pid " << status.GetPid() << std::endl;
    std::cout << "rate_limit " << status.GetRateLimit() << std::endl;
    std::cout << "backlog_limit " << status.GetBacklogLimit() << std::endl;
    std::cout << "lost " << status.GetLost() << std::endl;
    std::cout << "backlog " << status.GetBacklog() << std::endl;
    if (status.HasFeature(AuditStatus::Feature::BacklogWaitTime)) {
        std::cout << "backlog_wait_time " << status.GetBacklogWaitTime() << std::endl;
    }

    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int set_backlog_limit(const std::string& str) {
    if (!check_permissions()) {
        return 1;
    }

    uint32_t backlog_limit = 0;
    try {
        backlog_limit = std::stoul(str);
    } catch(std::exception&) {
        std::cerr << "Invalid backlog limit (" << str << ")" << std::endl;
    }

    Netlink netlink;
    netlink.SetQuite();
    Defer([&netlink]() {netlink.Close();});

    auto ret = netlink.Open(nullptr);
    if (ret != 0) {
        Logger::Error("Failed to open Netlink socket");
        return 1;
    }

    AuditStatus status;
    ret = NetlinkRetry([&netlink,&status]() { return status.GetStatus(netlink); });
    if (ret != 0) {
        Logger::Error("Failed to retrieve audit status: %s\n", strerror(-ret));
        return 1;
    }

    if (status.GetBacklogLimit() != backlog_limit) {
        AuditStatus new_status;
        new_status.SetBacklogLimit(backlog_limit);
        ret = NetlinkRetry([&netlink,&new_status]() { return new_status.UpdateStatus(netlink); });
        if (ret != 0) {
            Logger::Error("Failed to set backlog limit: %s\n", strerror(-ret));
            return 1;
        }
    } else {
        std::cerr << "The backlog limit is already set to (" << str << ")" << std::endl;
    }

    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int set_backlog_wait_time(const std::string& str) {
    if (!check_permissions()) {
        return 1;
    }

    uint32_t backlog_wait_time = 0;
    try {
        backlog_wait_time = std::stoul(str);
    } catch(std::exception&) {
        std::cerr << "Invalid backlog limit (" << str << ")" << std::endl;
    }

    Netlink netlink;
    netlink.SetQuite();
    Defer([&netlink]() {netlink.Close();});

    auto ret = netlink.Open(nullptr);
    if (ret != 0) {
        Logger::Error("Failed to open Netlink socket");
        return 1;
    }

    AuditStatus status;
    ret = NetlinkRetry([&netlink,&status]() { return status.GetStatus(netlink); });
    if (ret != 0) {
        Logger::Error("Failed to retrieve audit status: %s\n", strerror(-ret));
        return 1;
    }

    if (status.GetBacklogWaitTime() != backlog_wait_time) {
        AuditStatus new_status;
        new_status.SetBacklogWaitTime(backlog_wait_time);
        ret = NetlinkRetry([&netlink,&new_status]() { return new_status.UpdateStatus(netlink); });
        if (ret != 0) {
            Logger::Error("Failed to set backlog wait time: %s\n", strerror(-ret));
            return 1;
        }
    } else {
        std::cerr << "The backlog wait time is already set to (" << str << ")" << std::endl;
    }

    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int list_rules(bool raw_fmt, const std::string& key) {
    if (!check_permissions()) {
        return 1;
    }

    Netlink netlink;
    netlink.SetQuite();

    auto ret = netlink.Open(nullptr);
    if (ret != 0) {
        Logger::Error("Failed to open Netlink socket: %s", strerror(-ret));
        return 1;
    }

    std::vector<AuditRule> rules;
    ret = NetlinkRetry([&netlink,&rules]() {
        rules.clear();
        return netlink.AuditListRules(rules);
    });
    netlink.Close();

    if (ret != 0) {
        Logger::Error("Failed to retrieve audit rules: %s\n", strerror(-ret));
        return 1;
    }

    if (rules.empty()) {
        std::cout << "No rules" << std::endl;
    }

    for (auto& rule: rules) {
        if (key.empty() || rule.GetKeys().count(key) > 0) {
            if (raw_fmt) {
                std::cout << rule.RawText() << std::endl;
            } else {
                std::cout << rule.CanonicalText() << std::endl;
            }
        }
    }

    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int delete_rules(const std::string& key) {
    if (!check_permissions()) {
        return 1;
    }

    Netlink netlink;
    netlink.SetQuite();

    auto ret = netlink.Open(nullptr);
    if (ret != 0) {
        Logger::Error("Failed to open Netlink socket");
        return 1;
    }

    uint32_t enabled = 0;
    ret = NetlinkRetry([&netlink,&enabled]() { return netlink.AuditGetEnabled(enabled); });
    if (ret != 0) {
        Logger::Error("Failed to get audit status");
        return 1;
    }

    if (enabled == 2) {
        Logger::Error("Audit rules are locked");
        return 2;
    }

    std::vector<AuditRule> rules;
    ret = NetlinkRetry([&netlink,&rules]() {
        rules.clear();
        return netlink.AuditListRules(rules);
    });
    if (ret != 0) {
        Logger::Error("Failed to retrieve audit rules: %s\n", strerror(errno));
        return 1;
    }

    int exit_code = 0;
    for (auto& rule: rules) {
        if (key.empty() || rule.GetKeys().count(key) > 0) {
            ret = netlink.AuditDelRule(rule);
            if (ret != 0) {
                Logger::Error("Failed to delete audit rule (%s): %s\n", rule.CanonicalText().c_str(), strerror(-ret));
                exit_code = 1;
            }
        }
    }

    netlink.Close();

    return exit_code;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int load_rules(const std::string& path) {
    if (!check_permissions()) {
        return 1;
    }

    int exit_code = 0;
    try {
        auto lines = ReadFile(path);
        auto rules = ParseRules(lines, nullptr);

        Netlink netlink;
        netlink.SetQuite();

        auto ret = netlink.Open(nullptr);
        if (ret != 0) {
            Logger::Error("Failed to open Netlink socket");
            return 1;
        }

        uint32_t enabled = 0;
        ret = NetlinkRetry([&netlink,&enabled]() { return netlink.AuditGetEnabled(enabled); });
        if (ret != 0) {
            Logger::Error("Failed to get audit status");
            return 1;
        }

        if (enabled == 2) {
            Logger::Error("Audit rules are locked");
            return 2;
        }

        for (auto& rule: rules) {
            ret = netlink.AuditAddRule(rule);
            if (ret != 0) {
                Logger::Error("Failed to add audit rule (%s): %s\n", rule.CanonicalText().c_str(), strerror(-ret));
                exit_code = 1;
            }
        }

        netlink.Close();
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }

    return exit_code;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int print_rules(const std::string& path) {
    try {
        auto lines = ReadFile(path);
        std::vector<AuditRule> rules;
        for (int i = 0; i < lines.size(); ++i) {
            AuditRule rule;
            std::string error;
            if (rule.Parse(lines[i], error)) {
                std::cout << rule.CanonicalText() << std::endl;
            } else if (!error.empty()) {
                std::cout << "Failed to parse line " << i+1 << ": " << error << std::endl;
                std::cout << "    " << lines[i] << std::endl;
            }
        }
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }

    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int merge_rules(const std::string& file1, const std::string& file2) {
    try {
        auto rules1 = ParseRules(ReadFile(file1), nullptr);
        auto rules2 = ParseRules(ReadFile(file2), nullptr);
        auto merged_rules = MergeRules(rules1, rules2);
        for (auto& rule: merged_rules) {
            std::cout << rule.CanonicalText() << std::endl;
        }
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }

    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int diff_rules(const std::string& file1, const std::string& file2) {
    try {
        auto rules1 = MergeRules(ParseRules(ReadFile(file1), nullptr));
        auto rules2 = MergeRules(ParseRules(ReadFile(file2), nullptr));
        auto diffed_rules = DiffRules(rules1, rules2, "");
        for (auto& rule: diffed_rules) {
            std::cout << rule.CanonicalText() << std::endl;
        }
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }

    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int show_auoms_status() {
    if (!check_permissions()) {
        return 1;
    }

    UnixDomainWriter io("/var/run/auoms/status.socket");
    if (!io.Open()) {
        std::cout << "auoms is not running" << std::endl;
        return 1;
    }

    char buf[1024];
    while(true) {
        auto nr = io.Read(buf, sizeof(buf), 100, []() { return !Signals::IsExit(); });
        if (nr <= 0) {
            break;
        }
        std::cout << std::string(buf, nr);
    }
    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/

enum AuditdPluginConfigState:int {
    AUDITD_PLUGIN_ENABLED=1,
    AUDITD_PLUGIN_DISABLED=2,
    AUDITD_PLUGIN_MIXED=3,
    AUDITD_PLUGIN_MISSING=4,
};

AuditdPluginConfigState get_auditd_plugin_state_in_file(const std::string& path) {
    if (!PathExists(Dirname(path))) {
        return AUDITD_PLUGIN_MISSING;
    }
    if (!PathExists(path)) {
        return AUDITD_PLUGIN_DISABLED;
    }
    auto lines = ReadFile(path);
    for (auto& line: lines) {
        auto parts = split(line, '=');
        if (parts.size() == 2) {
            if (trim_whitespace(parts[0]) == "active" && trim_whitespace(parts[1]) == "yes") {
                return AUDITD_PLUGIN_ENABLED;
            }
        }
    }

    return AUDITD_PLUGIN_DISABLED;
}

AuditdPluginConfigState get_auditd_plugin_state() {
    AuditdPluginConfigState audit_state = get_auditd_plugin_state_in_file(ETC_AUDIT_PLUGINS_AUOMS_CONF);
    AuditdPluginConfigState audisp_state = get_auditd_plugin_state_in_file(ETC_AUDISP_PLUGINS_AUOMS_CONF);

    if (audit_state == AUDITD_PLUGIN_MISSING) {
        return audisp_state;
    } else if (audisp_state == AUDITD_PLUGIN_MISSING) {
        return audit_state;
    } else if (audit_state != audisp_state) {
        return AUDITD_PLUGIN_MIXED;
    } else {
        return audit_state;
    }
}

void set_auditd_plugin_status(bool enabled) {
    std::vector<std::string> lines;
    lines.emplace_back("# This file controls the auoms plugin.");
    lines.emplace_back("");
    if (enabled) {
        lines.emplace_back("active = yes");
    } else {
        lines.emplace_back("active = no");
    }
    lines.emplace_back("direction = out");
    lines.emplace_back(std::string("path = ") + AUOMSCOLLECT_EXE);
    lines.emplace_back("type = always");
    lines.emplace_back("#args =");
    lines.emplace_back("format = string");

    if (PathExists(ETC_AUDIT_PLUGINS_DIR)) {
        WriteFile(ETC_AUDIT_PLUGINS_AUOMS_CONF, lines);
        chmod(ETC_AUDIT_PLUGINS_AUOMS_CONF, 0640);
    }

    if (PathExists(ETC_AUDISP_PLUGINS_DIR)) {
        WriteFile(ETC_AUDISP_PLUGINS_AUOMS_CONF, lines);
        chmod(ETC_AUDISP_PLUGINS_AUOMS_CONF, 0640);
    }
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
bool is_service_sysv_enabled() {
    std::string service_name(AUOMS_SERVICE_NAME);
    int count = 0;
    for (auto& dir: GetDirList("/etc")) {
        if (dir.size() == 5 && starts_with(dir, "rc") && ends_with(dir, ".d")) {
            for (auto& file: GetDirList("/etc/" + dir)) {
                if (file.size() == 3+service_name.size() && file[0] == 'S' && ends_with(file, service_name)) {
                    count += 1;
                }
            }
        }
    }
    return count > 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
bool is_service_enabled() {
    std::string service_name(AUOMS_SERVICE_NAME);
    std::string path = SYSTEMCTL_PATH;
    if (!PathExists(path)) {
        return is_service_sysv_enabled();
    } else {
        // On some systemd systems the presence of /etc/init.d/auoms will cause "systemctl is-enabled" to return invalid service status
        // We attempt to remove the file before checking service status
        if (unlink("/etc/init.d/auoms") != 0) {
            if (errno != ENOENT) {
                throw std::system_error(errno, std::system_category(), "Failed to remove /etc/init.d/auoms: ");
            }
        }
    }

    std::vector<std::string> args;
    args.emplace_back("is-enabled");
    args.emplace_back(service_name);

    Cmd cmd(path, args, Cmd::NULL_STDIN|Cmd::PIPE_STDOUT|Cmd::COMBINE_OUTPUT);
    std::string out;
    auto ret = cmd.Run(out);
    if (ret < 0) {
        throw std::runtime_error("Failed to execute '" + path + " is-enabled " + service_name + "': " + out);
    } else if (ret != 0) {
        return false;
    }
    return true;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
void enable_service() {
    std::string path;
    std::vector<std::string> args;

    if (PathExists(SYSTEMCTL_PATH)) {
        path = SYSTEMCTL_PATH;
        args.emplace_back("enable");
        args.emplace_back(SYSTEMD_SERVICE_FILE);
    } else if (PathExists(CHKCONFIG_PATH)) {
        path = CHKCONFIG_PATH;
        args.emplace_back("--add");
        args.emplace_back(AUOMS_SERVICE_NAME);
    } else if (PathExists(UPDATE_RC_PATH)) {
        path = UPDATE_RC_PATH;
        args.emplace_back(AUOMS_SERVICE_NAME);
        args.emplace_back("defaults");
    } else {
        throw std::runtime_error("Failed to locate service control utility");
    }

    std::string cmd_str = path;
    for (auto& arg: args) {
        cmd_str.push_back(' ');
        cmd_str.append(arg);
    }

    Cmd cmd(path, args, Cmd::NULL_STDIN|Cmd::PIPE_STDOUT|Cmd::COMBINE_OUTPUT);
    std::string out;
    auto ret = cmd.Run(out);
    if (ret < 0) {
        throw std::runtime_error("Failed to execute '" + cmd_str + "': " + out);
    } else if (ret != 0) {
        throw std::runtime_error("Failed to enable service with command '" + cmd_str + "': " + out);
    }
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
void disable_service() {
    std::string path;
    std::vector<std::string> args;

    if (PathExists(SYSTEMCTL_PATH)) {
        path = SYSTEMCTL_PATH;
        args.emplace_back("disable");
        args.emplace_back(AUOMS_SERVICE_NAME);
    } else if (PathExists(CHKCONFIG_PATH)) {
        path = CHKCONFIG_PATH;
        args.emplace_back("--del");
        args.emplace_back(AUOMS_SERVICE_NAME);
    } else if (PathExists(UPDATE_RC_PATH)) {
        path = UPDATE_RC_PATH;
        args.emplace_back("-f");
        args.emplace_back(AUOMS_SERVICE_NAME);
        args.emplace_back("remove");
    } else {
        throw std::runtime_error("Failed to locate service control utility");
    }

    std::string cmd_str = path;
    for (auto& arg: args) {
        cmd_str.push_back(' ');
        cmd_str.append(arg);
    }

    Cmd cmd(path, args, Cmd::NULL_STDIN|Cmd::PIPE_STDOUT|Cmd::COMBINE_OUTPUT);
    std::string out;
    auto ret = cmd.Run(out);
    if (ret < 0) {
        throw std::runtime_error("Failed to execute '" + cmd_str + "': " + out);
    } else if (ret != 0) {
        throw std::runtime_error("Failed to disable service with command '" + cmd_str + "': " + out);
    }
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
bool is_service_proc_running(const std::string& comm) {
    std::string path = "/usr/bin/pgrep";
    std::vector<std::string> args;
    args.emplace_back("-x");
    args.emplace_back("-U");
    args.emplace_back("0");
    args.emplace_back(comm);

    std::string cmd_str = path;
    for (auto& arg: args) {
        cmd_str.push_back(' ');
        cmd_str.append(arg);
    }

    Cmd cmd(path, args, Cmd::NULL_STDIN|Cmd::PIPE_STDOUT|Cmd::COMBINE_OUTPUT);
    std::string out;
    auto ret = cmd.Run(out);
    if (ret < 0) {
        throw std::runtime_error("Failed to execute '" + cmd_str + "': " + out);
    } else if (ret != 0) {
        return false;
    }
    return true;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
void kill_service_proc(const std::string& comm) {
    std::string path = "/usr/bin/pkill";
    std::vector<std::string> args;
    args.emplace_back("-KILL");
    args.emplace_back("-x");
    args.emplace_back("-U");
    args.emplace_back("0");
    args.emplace_back(comm);

    std::string cmd_str = path;
    for (auto& arg: args) {
        cmd_str.push_back(' ');
        cmd_str.append(arg);
    }

    Cmd cmd(path, args, Cmd::NULL_STDIN|Cmd::PIPE_STDOUT|Cmd::COMBINE_OUTPUT);
    std::string out;
    auto ret = cmd.Run(out);
    if (ret < 0 || ret > 1) {
        throw std::runtime_error("Failed to execute '" + cmd_str + "': " + out);
    }
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/

std::string get_service_util_path() {
    std::string path = "/sbin/service";
    if (!PathExists(path)) {
        path = "/usr/sbin/service";
        if (!PathExists(path)) {
            return "";
        }
    }
    return path;
}

void service_cmd(const std::string& svc_cmd, const std::string& name) {
    std::vector<std::string> args;
    std::string path = get_service_util_path();

    if (!path.empty()) {
        args.emplace_back(name);
        args.emplace_back(svc_cmd);
    } else if (PathExists(SYSTEMCTL_PATH)) {
        // On some system the 'service' utility is not present, so use systemctl directly.
        path = SYSTEMCTL_PATH;
        args.emplace_back(svc_cmd);
        args.emplace_back(name);
    } else {
        throw std::runtime_error("Failed locate service utility");
    }

    std::string cmd_str = path;
    for (auto& arg: args) {
        cmd_str.push_back(' ');
        cmd_str.append(arg);
    }

    Cmd cmd(path, args, Cmd::NULL_STDIN|Cmd::PIPE_STDOUT|Cmd::COMBINE_OUTPUT);
    std::string out;
    auto ret = cmd.Run(out);
    if (ret < 0) {
        throw std::runtime_error("Failed to execute '" + cmd_str + "': " + out);
    } else if (ret != 0) {
        throw std::runtime_error("Failed to " + svc_cmd + " service with command '" + cmd_str + "': " + out);
    }
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
bool start_service() {
    if (is_service_proc_running(AUOMS_COMM)) {
        return true;
    }

    service_cmd("start", AUOMS_SERVICE_NAME);

    for (int i = 0; i < PROC_WAIT_TIME; ++i) {
        if (is_service_proc_running(AUOMS_COMM)) {
            return true;
        }
        sleep(1);
    }
    return false;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
void stop_service() {
    if (is_service_proc_running(AUOMS_COMM)) {
        try {
            service_cmd("stop", AUOMS_SERVICE_NAME);
        } catch (std::exception&) {
            // Ignore errors, the process will get killed anyway
        }

        // Wait for auoms to stop
        bool kill_it = true;
        for (int i = 0; i < PROC_WAIT_TIME; ++i) {
            if (!is_service_proc_running(AUOMS_COMM)) {
                kill_it = false;
                break;
            }
            sleep(1);
        }

        if (kill_it) {
            // auoms didn't exit after PROC_WAIT_TIME seconds, kill it.
            kill_service_proc(AUOMS_COMM);
        }
    }

    if (!PathExists(AUDITD_BIN)) {
        for (int i = 0; i < PROC_WAIT_TIME; ++i) {
            if (!is_service_proc_running(AUOMSCOLLECT_COMM)) {
                return;
            }
            sleep(1);
        }
        // auomscollect didn't exit after auoms stoppped, kill it.
        kill_service_proc(AUOMSCOLLECT_COMM);
    }
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
bool restart_service() {
    stop_service();

    return start_service();
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
bool start_auditd_service() {
    if (is_service_proc_running(AUDITD_COMM)) {
        return true;
    }
    service_cmd("start", AUDITD_SERVICE_NAME);

    for (int i = 0; i < PROC_WAIT_TIME; ++i) {
        if (is_service_proc_running(AUDITD_COMM)) {
            return true;
        }
        sleep(1);
    }
    return false;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
void stop_auditd_service() {
    service_cmd("stop", AUDITD_SERVICE_NAME);

    // Wait for auditd to stop
    for (int i = 0; i < PROC_WAIT_TIME; ++i) {
        if (!is_service_proc_running(AUDITD_COMM)) {
            break;
        }
        sleep(1);
    }

    // Wait for auomscollect to stop
    for (int i = 0; i < PROC_WAIT_TIME; ++i) {
        if (!is_service_proc_running(AUOMSCOLLECT_COMM)) {
            return;
        }
        sleep(1);
    }

    // auomscollect didn't exit after PROC_WAIT_TIME seconds, kill it.
    kill_service_proc(AUOMSCOLLECT_COMM);
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
bool restart_auditd_service() {
    stop_auditd_service();

    service_cmd("start", AUDITD_SERVICE_NAME);

    // Wait for auditd to start
    sleep(1);

    return is_service_proc_running(AUDITD_COMM);
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int enable_auoms() {
    if (!check_permissions()) {
        return 1;
    }

    // Return
    //      0 on success
    //      1 if service could not be enabled
    //      2 if auoms service did not start
    //      3 if auditd service did not start
    //      4 if auomscollect didn't start
    try {
        if (!is_service_enabled()) {
            enable_service();
        }

        if (!is_service_proc_running(AUOMS_COMM)) {
            if (!start_service()) {
                return 2;
            }
        }

        auto plugin_state = get_auditd_plugin_state();
        if (plugin_state == AUDITD_PLUGIN_DISABLED || plugin_state == AUDITD_PLUGIN_MIXED) {
            set_auditd_plugin_status(true);
            if (PathExists(AUDITD_BIN)) {
                if (!restart_auditd_service()) {
                    return 3;
                }
            }
        }
        for (int i = 0; i < PROC_WAIT_TIME; ++i) {
            if(is_service_proc_running(AUOMSCOLLECT_COMM)) {
                return 0;
            }
            sleep(1);
        }
        return 4;
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int remove_rules_from_audit_files() {
    if (RemoveAuomsRulesAuditdFiles()) {
        Cmd cmd(AUGENRULES_BIN, {}, Cmd::NULL_STDIN|Cmd::COMBINE_OUTPUT);
        std::string output;
        auto ret = cmd.Run(output);
        if (ret != 0) {
            std::cerr << "augenrules failed: " << cmd.FailMsg() << std::endl;
            std::cerr << "augenrules output: " << output << std::endl;
            return 1;
        }
    }
    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int disable_auoms() {
    if (!check_permissions()) {
        return 1;
    }

    // Return
    //      0 on success
    //      1 if service could not be disabled

    try {
        stop_service(); // Will also kill auomscollect if it didn't stop normally

        if (is_service_enabled()) {
            disable_service();
        }

        auto plugin_state = get_auditd_plugin_state();
        if (plugin_state == AUDITD_PLUGIN_ENABLED || plugin_state == AUDITD_PLUGIN_MIXED) {
            set_auditd_plugin_status(false);
            if (PathExists(AUDITD_BIN)) {
                restart_auditd_service(); // Will also kill auomscollect if it didn't stop normally
            }
        }

        auto dret = delete_rules(AUOMS_RULE_KEY);
        auto fret = remove_rules_from_audit_files();
        // If delete_rules returns 2, then that means "-e 2" is set and rules cannot be changed.
        // Treat dret == 2 as a non-error
        if ((dret != 0 && dret != 2) || fret != 0) {
            return 1;
        }
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int start_auoms(bool all) {
    int ret = 0;
    try {
        if (!is_service_proc_running(AUOMS_COMM)) {
            if (!start_service()) {
                std::cerr << "Failed to start auoms service" << std::endl;
                ret = 1;
            }
        }
        if (all && PathExists(AUDITD_BIN) && !is_service_proc_running(AUDITD_COMM)) {
            if (!start_auditd_service()) {
                std::cerr << "Failed to start auditd service or auomscollect has crashed" << std::endl;
                ret = 1;
            }
        }
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
    return ret;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int stop_auoms(bool all) {
    try {
        if (all && PathExists(AUDITD_BIN)) {
            stop_auditd_service();
        }
        if (is_service_proc_running(AUOMS_COMM)) {
            stop_service();
        }
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int restart_auoms(bool all) {
    int ret = 0;
    try {
        if (!restart_service()) {
            std::cerr << "Failed to restart auoms service" << std::endl;
            ret = 1;
        }
        if (all && PathExists(AUDITD_BIN)) {
            if (!restart_auditd_service()) {
                std::cerr << "Failed to restart auditd service or auomscollect has crashed" << std::endl;
                ret = 1;
            }
        }
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
    return ret;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
/*
 * Return:
 *  0 = running
 *  1 = enabled
 *  2 = disabled
 *  3 = partially-disabled
 *  4 = partially-enabled
 *  5 = error
 */
int show_auoms_state() {
    try {
        auto plugin_state = get_auditd_plugin_state();
        if (!is_service_enabled()) {
            if (plugin_state == AUDITD_PLUGIN_ENABLED || plugin_state == AUDITD_PLUGIN_MIXED || is_service_proc_running(AUOMS_COMM)) {
                std::cout << "partially-disabled" << std::endl;
                return 3;
            } else {
                std::cout << "disabled" << std::endl;
                return 2;
            }
        } else {
            if (plugin_state == AUDITD_PLUGIN_DISABLED || plugin_state == AUDITD_PLUGIN_MIXED) {
                std::cout << "partially-enabled" << std::endl;
                return 4;
            } else if (!is_service_proc_running(AUOMS_COMM)) {
                std::cout << "enabled" << std::endl;
                return 2;
            } else {
                std::cout << "running" << std::endl;
                return 0;
            }
        }
    } catch (std::exception& ex) {
        std::cout << "error" << std::endl;
        std::cerr << ex.what() << std::endl;
        return 5;
    }
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int tap_audit() {
    if (!check_permissions()) {
        return 1;
    }

    Netlink netlink;
    Gate _stop_gate;

    std::function handler = [](uint16_t type, uint16_t flags, const void* data, size_t len) -> bool {
        if (type >= AUDIT_FIRST_USER_MSG) {
            std::cout << "type=" << RecordTypeToName(static_cast<RecordType>(type)) << " " << std::string_view(reinterpret_cast<const char*>(data), len) << std::endl;
        }
        return false;
    };

    Logger::Info("Connecting to AUDIT NETLINK socket");
    auto ret = netlink.Open(std::move(handler));
    if (ret != 0) {
        Logger::Error("Failed to open AUDIT NETLINK connection: %s", std::strerror(-ret));
        return 1;
    }
    Defer _close_netlink([&netlink]() { netlink.Close(); });

    uint32_t our_pid = getpid();

    Logger::Info("Checking assigned audit pid");
    audit_status status;
    ret = NetlinkRetry([&netlink,&status]() { return netlink.AuditGet(status); } );
    if (ret != 0) {
        Logger::Error("Failed to get audit status: %s", std::strerror(-ret));
        return 1;
    }
    uint32_t pid = status.pid;
    uint32_t enabled = status.enabled;

    if (pid != 0 && PathExists("/proc/" + std::to_string(pid))) {
        Logger::Error("There is another process (pid = %d) already assigned as the audit collector", pid);
        return 1;
    }

    Logger::Info("Enabling AUDIT event collection");
    int retry_count = 0;
    do {
        if (retry_count > 5) {
            Logger::Error("Failed to set audit pid: Max retried exceeded");
        }
        ret = netlink.AuditSetPid(our_pid);
        if (ret == -ETIMEDOUT) {
            // If setpid timedout, it may have still succeeded, so re-fetch pid
            ret = NetlinkRetry([&netlink,&status,&pid]() { return netlink.AuditGetPid(pid); });
            if (ret != 0) {
                Logger::Error("Failed to get audit pid: %s", std::strerror(-ret));
                return 1;
            }
        } else if (ret != 0) {
            Logger::Error("Failed to set audit pid: %s", std::strerror(-ret));
            return 1;
        } else {
            break;
        }
        retry_count += 1;
    } while (pid != our_pid);
    if (enabled == 0) {
        ret = NetlinkRetry([&netlink,&status]() { return netlink.AuditSetEnabled(1); });
        if (ret != 0) {
            Logger::Error("Failed to enable auditing: %s", std::strerror(-ret));
            return 1;
        }
    }

    Defer _revert_enabled([&netlink,enabled]() {
        if (enabled == 0) {
            int ret;
            ret = NetlinkRetry([&netlink]() { return netlink.AuditSetEnabled(1); });
            if (ret != 0) {
                Logger::Error("Failed to enable auditing: %s", std::strerror(-ret));
                return;
            }
        }
    });

    Signals::SetExitHandler([&_stop_gate]() { _stop_gate.Open(); });

    while(!Signals::IsExit()) {
        if (_stop_gate.Wait(Gate::OPEN, 1000)) {
            return 0;
        }

        pid = 0;
        auto ret = NetlinkRetry([&netlink,&pid]() { return netlink.AuditGetPid(pid); });
        if (ret != 0) {
            Logger::Error("Failed to get audit pid: %s", std::strerror(-ret));
            return 1;
        } else {
            if (pid != our_pid) {
                Logger::Warn("Another process (pid = %d) has taken over AUDIT NETLINK event collection.", pid);
                return 1;
            }
        }
    }
    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/

int tap_audit_multicast() {
    if (!check_permissions()) {
        return 1;
    }

    try {
        auto ki = KernelInfo::GetKernelInfo();
        if (!ki.HasAuditMulticast()) {
            Logger::Error("Audit multicast not supported in kernel version %s", ki.KernelVersion().c_str());
            return 1;
        }
    } catch (std::exception &ex) {
        Logger::Error("Failed to determine if audit multicast is supported: %s", ex.what());
    }

    Netlink netlink;
    Gate _stop_gate;

    std::function handler = [](uint16_t type, uint16_t flags, const void* data, size_t len) -> bool {
        if (type >= AUDIT_FIRST_USER_MSG) {
            std::cout << "type=" << RecordTypeToName(static_cast<RecordType>(type)) << " " << std::string_view(reinterpret_cast<const char*>(data), len) << std::endl;
        }
        return false;
    };

    Logger::Info("Connecting to AUDIT NETLINK socket");
    auto ret = netlink.Open(std::move(handler), true);
    if (ret != 0) {
        Logger::Error("Failed to open AUDIT NETLINK connection: %s", std::strerror(-ret));
        return 1;
    }
    Defer _close_netlink([&netlink]() { netlink.Close(); });

    Signals::SetExitHandler([&_stop_gate]() { _stop_gate.Open(); });

    _stop_gate.Wait(Gate::OPEN, -1);

    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
void handle_raw_connection(int fd) {
    std::array<uint8_t, 1024*256> data;

    for (;;) {
        auto nread = 0;
        auto nleft = 4;
        while (nleft > 0) {
            auto nr = read(fd, data.data() + nread, nleft);
            if (nr <= 0) {
                if (nr < 0) {
                    Logger::Error("Failed to read frame size: %s", std::strerror(errno));
                    return;
                } else {
                    return;
                }
            }
            nleft -= nr;
            nread += nr;
        }
        auto size = *reinterpret_cast<uint32_t *>(data.data()) & 0x00FFFFFF;
        if (size <= 4 || size > 1024 * 256) {
            Logger::Error("Invalid frame size");
        }
        nread = 4;
        nleft = size - 4;
        while (nleft > 0) {
            auto nr = read(fd, data.data() + nread, nleft);
            if (nr <= 0) {
                if (nr < 0) {
                    Logger::Error("Failed to read frame: %s", std::strerror(errno));
                    return;
                } else {
                    return;
                }
            }
            nleft -= nr;
            nread += nr;
        }

        Event event(data.data(), size);
        std::cout << EventToRawText(event, true);

        std::array<uint8_t, 8+8+4> ack_data;
        *reinterpret_cast<uint64_t*>(ack_data.data()) = event.Seconds();
        *reinterpret_cast<uint32_t*>(ack_data.data()+8) = event.Milliseconds();
        *reinterpret_cast<uint64_t*>(ack_data.data()+12) = event.Serial();
        auto nw = write(fd, ack_data.data(), ack_data.size());
        if (nw != ack_data.size()) {
            if (nw < 0) {
                Logger::Error("Failed to write ack: %s", std::strerror(errno));
            } else {
                Logger::Error("Failed to write ack: no enough bytes written");
            }
            return;
        }
    }
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
bool reload_auoms() {
    std::string path = "/usr/bin/pkill";
    std::vector<std::string> args;
    args.emplace_back("-HUP");
    args.emplace_back("-x");
    args.emplace_back("-U");
    args.emplace_back("0");
    args.emplace_back(AUOMS_COMM);

    std::string cmd_str = path;
    for (auto& arg: args) {
        cmd_str.push_back(' ');
        cmd_str.append(arg);
    }

    Cmd cmd(path, args, Cmd::NULL_STDIN|Cmd::PIPE_STDOUT|Cmd::COMBINE_OUTPUT);
    std::string out;
    auto ret = cmd.Run(out);
    if (ret < 0) {
        throw std::runtime_error("Failed to execute '" + cmd_str + "': " + out);
    } else if (ret != 0) {
        return false;
    }
    return true;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int monitor_auoms_events() {
    if (!check_permissions()) {
        return 1;
    }

    std::string sock_path = std::string(AUOMS_RUN_DIR) + "/auomsctl.socket";
    std::string config_path = std::string(AUOMS_OUTCONF_DIR) + "/auomsctl.conf";

    UnixDomainListener listener(sock_path, 0666);
    if (!listener.Open()) {
        return -1;
    }

    Signals::SetExitHandler([&listener]() { listener.Close(); });

    std::vector<std::string> lines({
        "output_format = raw",
        "output_socket = " + sock_path,
        "enable_ack_mode = true",
    });

    WriteFile(config_path, lines);
    reload_auoms();

    int retcode = 0;
    std::cerr << "Waiting for connection" << std::endl;
    int fd = listener.Accept();
    if (fd < 0) {
        retcode = 1;
    } else {
        std::cerr << "Connected" << std::endl;
        handle_raw_connection(fd);
        close(fd);
    }

    listener.Close();
    unlink(config_path.c_str());
    reload_auoms();

    return retcode;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int set_rules() {
    auto rules = ReadAuditRulesFromDir(AUOMS_RULES_DIR, nullptr);
    std::vector<AuditRule> desired_rules;
    for (auto& rule: rules) {
        // Only include the rule in the desired rules if it is supported on the host system
        if (rule.IsLoadable()) {
            rule.AddKey(AUOMS_RULE_KEY);
            desired_rules.emplace_back(rule);
        }
    }

    try {
        std::vector<std::string> errors;
        auto rules = ReadActualAuditdRules(false, &errors);
        if (!errors.empty()) {
            std::cout << " Encountered parse errors: " << std::endl;
            for (auto& err : errors) {
                std::cout << "    " << err << std::endl;
            }
            return -1;
        }
        auto merged_rules = MergeRules(rules);
        auto diff = DiffRules(merged_rules, desired_rules, "");
        if (diff.empty()) {
            return 0;
        }
        Logger::Info("AuditRulesMonitor: Found desired audit rules not currently present in auditd rules files(s), adding new rules");

        // Re-read rules but exclude auoms rules
        errors.clear();
        rules = ReadActualAuditdRules(true, &errors);
        if (!errors.empty()) {
            std::cout << " Encountered parse errors: " << std::endl;
            for (auto& err : errors) {
                std::cout << "    " << err << std::endl;
            }
            return -1;
        }
        merged_rules = MergeRules(rules);
        // Re-calculate diff
        diff = DiffRules(merged_rules, desired_rules, "");
        if (WriteAuditdRules(diff)) {
            Logger::Info("AuditRulesMonitor: augenrules appears to be in-use, running augenrules after updating auoms rules in /etc/audit/rules.d");
            Cmd cmd(AUGENRULES_BIN, {}, Cmd::NULL_STDIN|Cmd::COMBINE_OUTPUT);
            std::string output;
            auto ret = cmd.Run(output);
            if (ret != 0) {
                Logger::Warn("AuditRulesMonitor: augenrules failed: %s", cmd.FailMsg().c_str());
                Logger::Warn("AuditRulesMonitor: augenrules output: %s", output.c_str());
                return -1;
            } else {
                Logger::Warn("AuditRulesMonitor: augenrules succeeded");
            }
        }
    } catch (std::exception& ex) {
        Logger::Error("AuditRulesMonitor: Failed to check/update auditd rules: %s", ex.what());
        return -1;
    }
    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
template<typename T>
bool is_set_intersect(T a, T b) {
    for (auto& e: b) {
        if (a.find(e) == a.end()) {
            return false;
        }
    }
    return true;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int load_rules() {
    auto rules = ReadAuditRulesFromDir(AUOMS_RULES_DIR, nullptr);
    std::vector<AuditRule> desired_rules;
    for (auto& rule: rules) {
        // Only include the rule in the desired rules if it is supported on the host system
        if (rule.IsLoadable()) {
            rule.AddKey(AUOMS_RULE_KEY);
            desired_rules.emplace_back(rule);
        }
    }

    Netlink netlink;

    Logger::Info("Connecting to AUDIT NETLINK socket");
    auto ret = netlink.Open(nullptr);
    if (ret != 0) {
        Logger::Error("Failed to open AUDIT NETLINK connection: %s", std::strerror(-ret));
        return 1;
    }
    Defer _close_netlink([&netlink]() { netlink.Close(); });

    ret = NetlinkRetry([&netlink,&rules]() {
        rules.clear();
        return netlink.AuditListRules(rules);
    });
    if (ret != 0) {
        Logger::Error("AuditRulesMonitor: Unable to fetch audit rules from kernel: %s", std::strerror(-ret));
        return 1;
    }

    auto merged_rules = MergeRules(rules);

    auto diff = DiffRules(merged_rules, desired_rules, "");
    if (diff.empty()) {
        return 0;
    }

    uint32_t enabled = 0;
    ret = NetlinkRetry([&netlink,&enabled]() { return netlink.AuditGetEnabled(enabled); });
    if (ret != 0) {
        Logger::Error("AuditRulesMonitor: Unable to get audit status from kernel: %s", std::strerror(-ret));
        return false;
    }

    bool rules_immutable = false;
    if (enabled == 2) {
        if (!rules_immutable) {
            Logger::Error("AuditRulesMonitor: Unable to add desired rules because audit rules are set to immutable");
        }
        return 0;
    } else {
        rules_immutable = false;
    }

    Logger::Info("AuditRulesMonitor: Found desired audit rules not currently loaded, loading new rules");

    std::unordered_map<std::string, AuditRule> _dmap;
    for (auto& rule: desired_rules) {
        _dmap.emplace(rule.CanonicalMergeKey(), rule);
    }

    // Delete all old auoms rules
    for (auto& rule: rules) {
        // Delete rule if it has AUOMS_RULE_KEY or matches any of the desired rules.
        bool delete_it = rule.GetKeys().count(AUOMS_RULE_KEY) > 0;
        if (!delete_it) {
            auto itr = _dmap.find(rule.CanonicalMergeKey());
            if (itr != _dmap.end()) {
                if (rule.IsWatch()) {
                    // Check to see if the rule's perms is a subset of the desired rule's perms
                    auto dset = itr->second.GetPerms();
                    auto aset = rule.GetPerms();
                    if (is_set_intersect(dset, aset)) {
                        delete_it = true;
                    }
                } else {
                    // Check to see if the rule's syscalls is a subset of the desired rule's syscalls
                    auto dset = itr->second.GetSyscalls();
                    auto aset = rule.GetSyscalls();
                    if (is_set_intersect(dset, aset)) {
                        delete_it = true;
                    }
                }
            }
        }
        if (delete_it) {
            ret = netlink.AuditDelRule(rule);
            if (ret != 0) {
                Logger::Warn("AuditRulesMonitor: Failed to delete audit rule (%s): %s\n", rule.CanonicalText().c_str(), strerror(-ret));
            }
        }
    }

    // refresh rules list
    ret = NetlinkRetry([&netlink,&rules]() {
        rules.clear();
        return netlink.AuditListRules(rules);
    });
    if (ret != 0) {
        Logger::Error("AuditRulesMonitor: Unable to fetch audit rules from kernel: %s", std::strerror(-ret));
        return false;
    }

    merged_rules = MergeRules(rules);

    // re-diff rules
    diff = DiffRules(merged_rules, desired_rules, "");
    if (diff.empty()) {
        return true;
    }

    // Add diff rules
    for (auto& rule: diff) {
        ret = netlink.AuditAddRule(rule);
        if (ret != 0) {
            Logger::Warn("AuditRulesMonitor: Failed to load audit rule (%s): %s\n", rule.CanonicalText().c_str(), strerror(-ret));
        }
    }
    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/

int flag_reset(const std::string& path) {
    try {
        unlink(path.c_str());
        WriteFile(path, {{"flag"}});
        return 0;
    } catch (std::exception&) {
        Logger::Error("Failed write flag to %s", path.c_str());
    }
    return 1;
}

int upgrade() {
    if (!check_permissions()) {
        return 1;
    }

    try {
        // Use auditd plugin file to determine if auoms should be enabled
        auto plugin_state = get_auditd_plugin_state();
        if (is_service_enabled() || plugin_state == AUDITD_PLUGIN_ENABLED || plugin_state == AUDITD_PLUGIN_MIXED) {
            // Stop services
            if (PathExists(AUDITD_BIN)) {
                stop_auditd_service();
            }

            stop_service();

            // Make sure all processes have exited
            bool kill_it = true;
            for (int i = 0; i < PROC_WAIT_TIME; ++i) {
                if (!is_service_proc_running(AUOMS_COMM)) {
                    kill_it = false;
                    break;
                }
                sleep(1);
            }

            if (kill_it) {
                // auoms didn't exit after PROC_WAIT_TIME seconds, kill it.
                kill_service_proc(AUOMS_COMM);
            }

            kill_it = true;
            for (int i = 0; i < PROC_WAIT_TIME; ++i) {
                if (!is_service_proc_running(AUOMSCOLLECT_COMM)) {
                    kill_it = false;
                    break;
                }
                sleep(1);
            }

            if (kill_it) {
                // auomscollect didn't exit after PROC_WAIT_TIME seconds, kill it.
                kill_service_proc(AUOMSCOLLECT_COMM);
            }

            // Trigger queue reset
            flag_reset(std::string(AUOMS_DATA_DIR) + "/auoms.lock");
            flag_reset(std::string(AUOMS_DATA_DIR) + "/auomscollect.lock");

            // Enable and start auoms service
            enable_service();
            start_service();

            // Force reset of file to ensure all parameters are correct
            set_auditd_plugin_status(true);
            if (PathExists(AUDITD_BIN)) {
                start_auditd_service();
            }
        } else {
            // Force reset of file to ensure all parameters are correct
            set_auditd_plugin_status(false);

            // Trigger queue reset (just in case)
            flag_reset(std::string(AUOMS_DATA_DIR) + "/auoms.lock");
            flag_reset(std::string(AUOMS_DATA_DIR) + "/auomscollect.lock");
        }
    } catch (std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        return 1;
    }
    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int spam_netlink(const std::string& dur_str, const std::string& num_str) {
    if (geteuid() != 0) {
        std::cerr << "Must be root to request audit rules" << std::endl;
        return 1;
    }

    auto dur = stol(dur_str);
    auto num_threads = stol(num_str);

    std::vector<std::thread> threads;

    auto fn = [&]() -> void {
        Logger::Info("Thread started");
        Netlink netlink;

        auto ret = netlink.Open(nullptr);
        if (ret != 0) {
            Logger::Error("Failed to open Netlink socket: %s", strerror(-ret));
            return;
        }

        auto end_time = std::chrono::steady_clock::now() + std::chrono::seconds(dur);
        while (end_time > std::chrono::steady_clock::now()) {
            auto ret = netlink.Send(AUDIT_LIST_RULES, nullptr, 0, [](uint16_t type, uint16_t flags, const void* data, size_t len) -> bool {
                if (type == AUDIT_LIST_RULES) {
                    if (!AuditRule::IsDataValid(data, len)) {
                        Logger::Warn("Received invalid audit rule");
                    }
                }
                return true;
            });
            if (ret != 0) {
                Logger::Error("AuditListRules failed: %s", std::strerror(-ret));
            }
        }
        netlink.Close();
    };

    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(fn);
    }

    for (int i = 0; i < num_threads; i++) {
        threads[i].join();
    }

    return 0;
}


/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int test_redaction(std::string& dir) {
    CmdlineRedactor cr;

    cr.LoadFromDir(dir, false);

    std::string cmdline;
    std::string rule_names;

    for (; std::getline(std::cin, cmdline); ) {
        if (cr.ApplyRules(cmdline, rule_names)) {
            std::cout << "Redacted("<< rule_names <<"): " << cmdline << "\n";
        } else {
            std::cout << "Not Redacted: " << cmdline << "\n";
        }
    }

    return 0;
}

/**********************************************************************************************************************
 **
 *********************************************************************************************************************/
int main(int argc, char**argv) {
    if (argc < 2 || strlen(argv[1]) < 2) {
        usage();
        exit(1);
    }

    Signals::Init();
    Signals::Start();
    Signals::SetExitHandler([](){ exit(1); });

    if (strcmp(argv[1], "-v") == 0) {
        std::cout << std::string(AUOMS_VERSION) << std::endl;
        return 0;
    } else if (strcmp(argv[1], "-s") == 0) {
        return show_audit_status();
    } else if (strcmp(argv[1], "-bl") == 0) {
        if (argc < 3) {
            usage();
            exit(1);
        }
        return set_backlog_limit(argv[2]);
    } else if (strcmp(argv[1], "-bwt") == 0) {
        if (argc < 3) {
            usage();
            exit(1);
        }
        return set_backlog_wait_time(argv[2]);
    } else if (strcmp(argv[1], "-l") == 0) {
        std::string key;
        if (argc > 2) {
            key = argv[2];
        }
        return list_rules(false, key);
    } else if (strcmp(argv[1], "-rl") == 0) {
        std::string key;
        if (argc > 2) {
            key = argv[2];
        }
        return list_rules(true, key);
    } else if (strcmp(argv[1], "-D") == 0) {
        std::string key;
        if (argc > 2) {
            key = argv[2];
        }
        return delete_rules(key);
    } else if (strcmp(argv[1], "-R") == 0) {
        if (argc < 3) {
            usage();
            exit(1);
        }
        return load_rules(argv[2]);
    } else if (strcmp(argv[1], "-p") == 0) {
        if (argc < 3) {
            usage();
            exit(1);
        }
        return print_rules(argv[2]);
    } else if (strcmp(argv[1], "-m") == 0) {
        if (argc < 4) {
            usage();
            exit(1);
        }
        return merge_rules(argv[2], argv[3]);
    } else if (strcmp(argv[1], "-d") == 0) {
        if (argc < 4) {
            usage();
            exit(1);
        }
        return diff_rules(argv[2], argv[3]);
    } else if (strcmp(argv[1], "state") == 0) {
        return show_auoms_state();
    } else if (strcmp(argv[1], "status") == 0) {
        return show_auoms_status();
    } else if (strcmp(argv[1], "is-enabled") == 0) {
        try {
            if (is_service_enabled()) {
                std::cout << "enabled" << std::endl;
                return 0;
            } else {
                std::cout << "disabled" << std::endl;
                return 1;
            }
        } catch (std::exception& ex) {
            std::cerr << ex.what() << std::endl;
            return 2;
        }
    } else if (strcmp(argv[1], "enable") == 0) {
        return enable_auoms();
    } else if (strcmp(argv[1], "disable") == 0) {
        return disable_auoms();
    } else if (strcmp(argv[1], "start") == 0) {
        bool all = false;
        if (argc > 2 && strcmp(argv[2], "all") == 0) {
            all = true;
        }
        return start_auoms(all);
    } else if (strcmp(argv[1], "restart") == 0) {
        bool all = false;
        if (argc > 2 && strcmp(argv[2], "all") == 0) {
            all = true;
        }
        return restart_auoms(all);
    } else if (strcmp(argv[1], "stop") == 0) {
        bool all = false;
        if (argc > 2 && strcmp(argv[2], "all") == 0) {
            all = true;
        }
        return stop_auoms(all);
    } else if (strcmp(argv[1], "tap") == 0) {
        if (argc > 2 && strcmp(argv[2], "multicast") == 0) {
            return tap_audit_multicast();
        }
        return tap_audit();
    } else if (strcmp(argv[1], "monitor") == 0) {
        return monitor_auoms_events();
    } else if (strcmp(argv[1], "reload") == 0) {
        return reload_auoms();
    } else if (strcmp(argv[1], "setrules") == 0) {
        return set_rules();
    } else if (strcmp(argv[1], "loadrules") == 0) {
        return load_rules();
    } else if (strcmp(argv[1], "upgrade") == 0) {
        return upgrade();
    } else if (strcmp(argv[1], "spam_netlink") == 0) {
        if (argc < 4) {
            usage();
            exit(1);
        }
        return spam_netlink(argv[2], argv[3]);
    } else if (strcmp(argv[1], "test_redaction") == 0) {
        if (argc < 3) {
            usage();
            exit(1);
        }
        std::string dir;
        dir = argv[2];
        return test_redaction(dir);
    }

    usage();
    exit(1);
}
