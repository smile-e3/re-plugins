rule InterestingStr {
    meta:
        author = "smile"
        date = "2023-11-22"
        description = "有意思的字符串"

    strings:
        // 后期逐渐添加
        $a = "Buildroot" nocase

    condition:
        $a
}