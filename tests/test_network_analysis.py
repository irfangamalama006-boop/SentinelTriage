from sentineltriage.network_analysis import analyze_network


def test_public_ip_is_information_not_automatic_threat():
    result = analyze_network({
        "source": "test",
        "items": [{
            "process": "browser",
            "pid": 123,
            "local_address": "192.168.1.10:50000",
            "remote_address": "8.8.8.8:443",
            "status": "ESTABLISHED",
        }],
    })

    assert result["total_items"] == 1
    assert result["review_count"] == 0
    assert result["items"][0]["remote_scope"] == "public"
    assert result["items"][0]["assessment"] == "informational"


def test_wildcard_listener_is_marked_for_review():
    result = analyze_network({
        "items": [{
            "process": "service",
            "pid": 456,
            "local_address": "*:7000",
            "remote_address": None,
            "status": "LISTEN",
        }],
    })

    assert result["review_count"] == 1
    assert result["review_items"][0]["assessment"] == "review"
    assert "semua interface" in result["review_items"][0]["reasons"][0]


def test_loopback_is_classified_as_local():
    result = analyze_network({
        "items": [{
            "process": "python",
            "pid": 789,
            "local_address": "127.0.0.1:8501",
            "remote_address": "127.0.0.1:50000",
            "status": "ESTABLISHED",
        }],
    })

    assert result["items"][0]["remote_scope"] == "loopback"
    assert result["review_count"] == 0


def test_unknown_remote_address_needs_review():
    result = analyze_network({
        "items": [{
            "process": "unknown-process",
            "pid": 999,
            "local_address": "10.0.0.2:40000",
            "remote_address": "unparsed-endpoint",
            "status": "ESTABLISHED",
        }],
    })

    assert result["review_count"] == 1
    assert result["items"][0]["remote_scope"] == "unknown"


def test_empty_network_data_is_safe():
    result = analyze_network({})

    assert result["total_items"] == 0
    assert result["review_count"] == 0
    assert result["informational_count"] == 0


def test_duplicate_review_sockets_are_grouped():
    socket = {
        "process": "TestService",
        "pid": 700,
        "type": "TCP",
        "family": "TCP",
        "local_address": "*:7000",
        "remote_address": None,
        "status": "LISTEN",
    }

    result = analyze_network({
        "items": [socket, dict(socket)],
    })

    assert result["total_items"] == 2
    assert result["unique_count"] == 1
    assert result["duplicate_count"] == 1
    assert result["raw_review_count"] == 2
    assert result["review_count"] == 1
    assert result["duplicate_review_count"] == 1
    assert len(result["items"]) == 2
    assert len(result["review_items"]) == 1
