/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "CmdlineRedactor.h"

#include "Config.h"
#include "FileUtils.h"
#include "Logger.h"
#include "StringUtils.h"

#define CONFIG_SUFFIX ".conf"
#define REQUIRES_SUFFIX ".requires"

std::shared_ptr<CmdlineRedactionRule> CmdlineRedactionRule::LoadFromFile(const std::string& path) {
    using namespace std::string_literals;

    static auto invalid_name_chars = R"inv(,/"'`$%&<>?{}[]|\)inv"s;

    Config config;
    try {
        config.Load(path);

        std::string name = Basename(path, CONFIG_SUFFIX);
        std::string file_name = name + CONFIG_SUFFIX;
        if (config.HasKey("name")) {
            name = config.GetString("name");
        }

        if (name.find_first_of(invalid_name_chars) != std::string::npos) {
            Logger::Error("CmdlineRedactionRule::LoadFromFile(%s): Name (%s) contains invalid characters (%s)", path.c_str(), name.c_str(), invalid_name_chars.c_str());
            return nullptr;
        }

        std::string replacement_char = "*";
        if (config.HasKey("replacement_char")) {
            replacement_char = config.GetString("replacement_char");
            if (replacement_char.length() > 1) {
                replacement_char.resize(1);
                Logger::Warn("CmdlineRedactionRule::LoadFromFile(%s): Configured replacement_char (%s) is too long, truncating to 1 char", path.c_str(), replacement_char.c_str());
            }
        }

        if (!config.HasKey("regex")) {
            Logger::Error("CmdlineRedactionRule::LoadFromFile(%s): Config is missing the 'regex' value", path.c_str());
            return nullptr;
        }
        std::string regex = config.GetString("regex");

        auto ret = std::make_shared<CmdlineRedactionRule>(file_name, name, regex, replacement_char[0]);
        if (!ret->CompiledOK()) {
            Logger::Error("CmdlineRedactionRule::LoadFromFile(%s): Failed to load: Invalid regex: %s", path.c_str(), ret->CompileError().c_str());
            return nullptr;
        }
        return ret;
    } catch (std::exception& ex) {
        Logger::Error("CmdlineRedactionRule::LoadFromFile(%s): Failed to load: %s", path.c_str(), ex.what());
    }

    return nullptr;
}

bool CmdlineRedactionRule::Apply(std::string& cmdline) const {
    if (cmdline.empty()) {
        return false;
    }
    auto res = false;
    size_t num_groups = _regex.NumberOfCapturingGroups() + 1;
    re2::StringPiece groups[num_groups];
    re2::StringPiece text(cmdline);
    size_t idx = 0;
    size_t end = text.size();
    while (idx < end) {
        if (!_regex.Match(text, idx, end, re2::RE2::UNANCHORED, &groups[0], num_groups)) {
            break;
        }
        for (int i = 1; i < num_groups; ++i) {
            if (groups[i].data() != nullptr) {
                char * start = cmdline.data() + (groups[i].data() - text.data());
                std::fill(start, start + groups[i].size(), _replacement_char);
            }
        }
        res = true;
        idx += groups[0].size();
    }
    return res;
}

void CmdlineRedactor::AddRule(std::shared_ptr<const CmdlineRedactionRule>& rule) {
    std::lock_guard<std::mutex> _lock(_mutex);

    _rule_names.emplace(rule->Name());
    _rules.emplace_back(rule);
}

bool CmdlineRedactor::LoadFromDir(const std::string& dir, bool require_only_root) {
    std::unordered_set<std::string> new_rule_names;
    std::unordered_set<std::string> new_required_rule_files;
    std::unordered_set<std::string> new_missing_rule_files;
    std::vector<std::shared_ptr<const CmdlineRedactionRule>> new_rules;

    if (!PathExists(dir)) {
        return true;
    }

    if (require_only_root && !IsOnlyRootWritable(dir)) {
        Logger::Error("CmdlineRedactor::LoadFromDir(%s): Dir is not secure, it is writable by non-root users. Redaction rules will not be loaded.", dir.c_str());
        return true;
    }

    std::vector<std::string> files;
    try {
        files = GetDirList(dir);
    } catch (std::exception& ex) {
        Logger::Error("CmdlineRedactor::LoadFromDir(%s): Failed to read dir: %s", dir.c_str(), ex.what());
        return true;
    }

    std::unordered_set<std::string> loaded_rule_files;

    std::sort(files.begin(), files.end());
    for (auto& name: files) {
        std::string path = dir + "/" + name;
        if (require_only_root && !IsOnlyRootWritable(path)) {
            Logger::Error("CmdlineRedactor::LoadFromDir(%s): File (%s) is not secure, it is writable by non-root users. It will not be loaded.", dir.c_str(), name.c_str());
            continue;
        }

        if (ends_with(name, CONFIG_SUFFIX)) {
            auto rule = CmdlineRedactionRule::LoadFromFile(dir + "/" + name);
            if (!rule) {
                Logger::Warn("Excluding (%s/%s) due to errors", dir.c_str(), name.c_str());
                continue;
            }

            // Make sure rule names are unique
            auto base_name = rule->Name();
            int rnum = 1;
            while (new_rule_names.count(rule->Name())) {
                rule->SetName(base_name+std::to_string(rnum));
                rnum += 1;
            }

            if (rule) {
                new_rules.emplace_back(rule);
            }
            loaded_rule_files.emplace(name);
        } else if (ends_with(name, REQUIRES_SUFFIX)) {
            std::vector<std::string> lines;
            try {
                lines = ReadFile(dir+"/"+name);
            } catch (std::exception& ex) {
                Logger::Error("Encountered error while trying to read %s/%s: %s", dir.c_str(), name.c_str(), ex.what());
            }
            for (auto& line : lines) {
                auto name = trim_whitespace(line);
                if (!starts_with(line, "#")) {
                    if (!ends_with(name, CONFIG_SUFFIX)) {
                        name = name + CONFIG_SUFFIX;
                    }
                    new_required_rule_files.emplace(name);
                }
            }
        }
    }

    for (auto& name : new_required_rule_files) {
        if (loaded_rule_files.count(name) == 0) {
            new_missing_rule_files.emplace(name);
            Logger::Error("Required redaction rule file %s is missing", name.c_str());
        }
    }

    std::lock_guard<std::mutex> _lock(_mutex);
    _rule_names = new_rule_names;
    _required_rule_files = new_required_rule_files;
    _missing_rule_files = new_missing_rule_files;
    _rules = new_rules;

    return _missing_rule_files.empty();
}

std::vector<std::string> CmdlineRedactor::GetMissingRules() {
    std::lock_guard<std::mutex> _lock(_mutex);

    std::vector<std::string> missing;
    for (auto& name : _missing_rule_files) {
        missing.emplace_back(name);
    }
    std::sort(missing.begin(), missing.end());
    return missing;
}

std::vector<std::shared_ptr<const CmdlineRedactionRule>> CmdlineRedactor::GetRules() {
    std::lock_guard<std::mutex> _lock(_mutex);
    return _rules;
}

const std::string CmdlineRedactor::REDACT_RULE_MISSING_NAME = "*Missing Required*";
const std::string CmdlineRedactor::REDACT_RULE_MISSING_TEXT = "**** Entire cmdline redacted due to missing required redaction rules ****";

bool CmdlineRedactor::ApplyRules(std::string& cmdline, std::string& rule_names) {
    std::lock_guard<std::mutex> _lock(_mutex);

    rule_names.resize(0);

    if (!_missing_rule_files.empty()) {
        cmdline = REDACT_RULE_MISSING_TEXT;
        rule_names = REDACT_RULE_MISSING_NAME;
        return true;
    }

    auto res = false;
    for (auto& rule: _rules) {
        if (rule->Apply(cmdline)) {
            if (!rule_names.empty()) {
                rule_names.push_back(',');
            }
            rule_names.append(rule->Name());
            res = true;
        }
    }
    return res;
}
