/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule email {
    meta:
        author = "smile . <alchemist_clb@163.com>"
        date = "2023-11-24"
        description = "匹配邮箱"
    
    strings:
        $email_regex = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}/ wide ascii
    
    condition:
        $email_regex
}