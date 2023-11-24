/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule phone {

    meta:
        author = "smile . <alchemist_clb@163.com"
        date = "2023-11-24"
        description = "电话匹配"
    
    strings:
        $phone_regex_chinese_andline_number = /\d{3,4}-\d{7,8}$/
        $phone_regex_chinese_mobile_number = /1[3456789]\d{9}/

    condition:
        any of them
}