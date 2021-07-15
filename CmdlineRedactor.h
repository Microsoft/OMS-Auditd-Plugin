/*
    microsoft-oms-auditd-plugin

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef AUOMS_CMDLINEREDACTOR_H
#define AUOMS_CMDLINEREDACTOR_H

#include <string>
#include <regex>
#include <unordered_set>
#include <re2/re2.h>

class CmdlineRedactionRule {
public:
    static std::shared_ptr<CmdlineRedactionRule> LoadFromFile(const std::string& path);

    CmdlineRedactionRule(const std::string& file_name, const std::string& name, const std::string& regex, char replacement_char):
            _name(name), _regex_str(regex), _regex(regex), _replacement_char(replacement_char) {}

    // Returns false if the compile failed
    bool CompiledOK() { return _regex.ok(); }

    inline RE2::ErrorCode CompileErrorCode() const { return _regex.error_code(); }
    inline std::string CompileError() const { return _regex.error(); }

    inline std::string FileName() const { return _file_name; }
    inline std::string Name() const { return _name; }
    inline void SetName(const std::string& name) { _name = name; }
    inline std::string Regex() const { return _regex_str; }
    inline char ReplacementChar() const { return _replacement_char; }

    // Return true if redaction applied
    bool Apply(std::string& cmdline) const;

private:
    std::string _file_name;
    std::string _name;
    std::string _regex_str;
    re2::RE2 _regex;
    char _replacement_char;
};

class CmdlineRedactor {
public:
    static const std::string REDACT_RULE_MISSING_NAME;
    static const std::string REDACT_RULE_MISSING_TEXT;

    CmdlineRedactor() = default;

    // Used only for tests
    void AddRule(std::shared_ptr<const CmdlineRedactionRule>& rule);

    // Return true if no furthor action is needed (or possible)
    // Return false, if required rules are missing and another load attempt should be made
    bool LoadFromDir(const std::string& dir, bool require_only_root);

    std::vector<std::string> GetMissingRules();

    std::vector<std::shared_ptr<const CmdlineRedactionRule>> GetRules();

    bool ApplyRules(std::string& cmdline, std::string& rule_names);

private:
    std::mutex _mutex;
    std::unordered_set<std::string> _rule_names;
    std::unordered_set<std::string> _required_rule_files;
    std::unordered_set<std::string> _missing_rule_files;
    std::vector<std::shared_ptr<const CmdlineRedactionRule>> _rules;
};


#endif //AUOMS_CMDLINEREDACTOR_H
