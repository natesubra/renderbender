rule Email_iCal_Spoof_Detection {
    meta:
        author = "Nate Subra"
        date = "2025-05-27"
        description = "Detects emails with iCal attachments where ORGANIZER is a target domain but sender is not."
        severity = "MEDIUM"
        version = "1.3"

    strings:
        // String to identify an iCal attachment by its Content-Type header
        $ical_content_type = "Content-Type: text/calendar" nocase ascii wide

        // String to identify the beginning of iCal content
        $ical_begin = "BEGIN:VCALENDAR" nocase ascii wide

        // Regex to find 'ORGANIZER' field with the specific domains within iCal content
        // Domains are directly specified in the regex pattern
		// It's also possibl to include an external variable for the domains
        $ical_organizer_domain = /ORGANIZER(?:;CN=[^:]+)?:mailto:[^@]+@(natesubra|example)\.com/ nocase ascii wide

        // Regex to find the 'From' header with the specific domains
        // Domains are directly specified in the regex pattern
        $from_header_domain = /From:.*<[^@]+@(natesubra|example)\.com>/ nocase ascii wide

    condition:
        // Ensure it's likely an iCal attachment by checking content type or begin tag
        ($ical_content_type or $ical_begin) and
        // The iCal content must contain the specific organizer domain
        $ical_organizer_domain and
        // The email's From header must NOT contain the specific domain
        not $from_header_domain
}
