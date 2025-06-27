from linotp.model.migrate import Migration_4_0_0_0


def test_standard_case():
    input_policies = [
        ("webprovisionGOOGLE", True),
        ("enrollMOTP", True),
        ("enrollOCRA2", True),
        ("footer_text", "test, test"),
        ("webprovisionGOOGLEtime", True),
        ("max_count_hotp", 10),
    ]

    expected_output = (
        'enrollHMAC, enrollMOTP, enrollOCRA2, footer_text="test, test", enrollTOTP, max_count_hotp=10',
        True,
    )

    assert (
        Migration_4_0_0_0.rename_webprovision_google_policies(input_policies)
        == expected_output
    )


def test_avoid_duplicates_when_enroll_policies_exist():
    input_policies = [
        ("enrollMOTP", True),
        ("enrollOCRA2", True),
        ("enrollHMAC", True),
        ("webprovisionGOOGLE", True),
        ("footer_text", "test, test"),
        ("max_count_hotp", 10),
        ("webprovisionGOOGLEtime", True),
        ("enrollTOTP", False),
    ]

    expected_output = (
        'enrollMOTP, enrollOCRA2, enrollHMAC, footer_text="test, test", max_count_hotp=10, enrollTOTP',
        True,
    )

    assert (
        Migration_4_0_0_0.rename_webprovision_google_policies(input_policies)
        == expected_output
    )


def test_no_webprovision_entries():
    input_policies = [
        ("enrollMOTP", True),
        ("footer_text", "abc"),
    ]

    expected_output = (None, False)

    assert (
        Migration_4_0_0_0.rename_webprovision_google_policies(input_policies)
        == expected_output
    )


def test_duplicate_mapped_policies():
    input_policies = [
        ("webprovisionGOOGLE", True),
        ("webprovisionGOOGLE", True),
        ("webprovisionGOOGLEtime", True),
        ("webprovisionGOOGLEtime", True),
    ]

    expected_output = ("enrollHMAC, enrollTOTP", True)

    assert (
        Migration_4_0_0_0.rename_webprovision_google_policies(input_policies)
        == expected_output
    )
