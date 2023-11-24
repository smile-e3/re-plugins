rule unencrypted_private_key : plain_privatekey privatekey
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find unencrypted private keys"
    strings:
        $content = "-----BEGIN RSA PRIVATE KEY-----" nocase
        $content2 = "encrypted" nocase
    condition:
        $content at 0 and not $content2
}

rule encrypted_private_key : encrypted_privatekey privatekey keycontainer
{
    meta:
        author = "DiabloHorn https://diablohorn.com"
        description = "find encrypted private keys"
    strings:
        $content = "-----BEGIN RSA PRIVATE KEY-----" nocase
        $content2 = "encrypted" nocase
    condition:
        $content at 0 and $content2
}