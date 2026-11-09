from sentineltriage.process_analysis import analyze_processes


def test_normal_process_is_informational():
    result = analyze_processes({
        "items": [{
            "pid": 100,
            "name": "Example",
            "exe": "/Applications/Example.app/Contents/MacOS/Example",
            "status": "running",
        }],
        "errors": [],
    })
    assert result["total_items"] == 1
    assert result["review_count"] == 0
    assert result["informational_count"] == 1


def test_temporary_executable_needs_review():
    result = analyze_processes({
        "items": [{
            "pid": 101,
            "name": "UnknownTool",
            "exe": "/private/tmp/unknown-tool",
            "status": "running",
        }],
    })
    assert result["review_count"] == 1
    assert "lokasi sementara" in result["review_items"][0]["reasons"][0]


def test_missing_executable_needs_review():
    result = analyze_processes({
        "items": [{"pid": 102, "name": "UnknownTool", "exe": None}],
    })
    assert result["review_count"] == 1


def test_missing_name_and_executable_are_reported():
    result = analyze_processes({
        "items": [{"pid": 103}],
    })
    assert result["review_count"] == 1
    assert len(result["review_items"][0]["reasons"]) == 2


def test_empty_process_data_is_safe():
    result = analyze_processes({})
    assert result["total_items"] == 0
    assert result["review_count"] == 0


def test_kernel_task_pid_zero_missing_executable_is_informational():
    result = analyze_processes({
        "items": [{
            "pid": 0,
            "name": "kernel_task",
            "exe": None,
            "status": "idle",
        }],
    })

    assert result["total_items"] == 1
    assert result["review_count"] == 0
    assert result["informational_count"] == 1
