rule SentinelTriage_Synthetic_Test
{
    meta:
        description = "Aturan uji teks sintetis SentinelTriage"
        author = "Irfan Maulana"

    strings:
        $marker = "SIMULATED_TRIAGE_MARKER_12345"

    condition:
        $marker
}
