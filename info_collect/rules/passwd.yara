rule shadow_file : usernames hashed_passwords linux passwords
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find shadow files"
    strings:
        $rootline = /root:.:\d+?:\d+?:\d+?:\d+?:/ nocase
        $hashline = /:\$\d\$/
        $hashtype_md5 = ":$1$"
        $hashtype_blowfish = ":$2a$"
        $hashtype_blowfish2 = ":$2y$"
        $hashtype_sha256 = ":$5$"
        $hashtype_sha512 = ":$6$"
    condition:
        $rootline and $hashline and (1 of ($hashtype_*))
}