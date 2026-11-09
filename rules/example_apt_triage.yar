rule Example_Suspicious_Test_Pattern
{
    meta:
        description = "Demonstration-only placeholder pattern; not a real APT signature"
        author = "SentinelTriage training example"
        confidence = "low"
    strings:
        $marker = "SENTINELTRIAGE_DEMO_MARKER" ascii wide
    condition:
        $marker
}
