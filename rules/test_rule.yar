rule SentinelTriage_Test_String
{
    meta:
        description = "Aturan uji lokal SentinelTriage"
        purpose = "Validasi fungsi pemindaian YARA"

    strings:
        $marker = "File uji SentinelTriage" ascii

    condition:
        $marker
}
