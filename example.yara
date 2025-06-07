rule Email_iCal_Spoof_Detection {
    meta:
        author = "Nate Subra"
        date = "2025-05-27"
        description = "Detects emails with iCal attachments where ORGANIZER is a target domain but sender is not."
        severity = "MEDIUM"
        version = "1.2"
	reference = "https://gist.github.com/natesubra/0577178177ef64adce0866ee71ada41a"

    strings:
        // String to identify an iCal attachment by its Content-Type header
        $ical_content_type = "Content-Type: text/calendar" nocase ascii

        // String to identify the beginning of iCal content
        $ical_begin = "BEGIN:VCALENDAR" nocase ascii

        // Regex to find 'ORGANIZER' field with the specific domains within iCal content
        // This accounts for various formats of the ORGANIZER field, including common CN (Common Name)
        $ical_organizer_domain = /ORGANIZER;(CN=[^:]+)?:mailto:[^@]+@(natesubra|example)\.com/ nocase ascii

        // Regex to find the 'From' header with the specific domains
        // We use the $target_domains_regex variable here
        $from_header_domain = /From:.*<[^@]+@(natesubra|example)\.com>/ nocase ascii

    condition:
        // Ensure it's likely an iCal attachment by checking content type or begin tag
        ($ical_content_type or $ical_begin) and
        // The iCal content must contain the specific organizer domain
        $ical_organizer_domain and
        // The email's From header must NOT contain the specific domain
        not $from_header_domain
}
