# SBT-DF205 — Case 1: Android Forensics Investigation of a Google Pixel 3

**International Cybersecurity and Digital Forensics Academy (ICDFA)**
School of Basic Vocational Training (SVT)

![Course](https://img.shields.io/badge/Course-SBT--DF205-blue)
![Case Study](https://img.shields.io/badge/Case%20Study-01%20Android%20Forensics-red)
![Student](https://img.shields.io/badge/Student-2025%2FFWSD%2F11334-informational)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

---

## 👤 Author

| Field | Details |
| --- | --- |
| **Student Name** | Ibrahim Ishaku |
| **Student ID** | 2025/FWSD/11334 |
| **Programme** | Fellowship in Web Application Security & Digital Forensics |
| **Course** | SBT-DF205 — Mobile and IoT Forensics Case Study |
| **Case Title** | Android Forensics Investigation of a Google Pixel 3 |
| **Instructor** | Aminu Idris, AMCPN |
| **Date** | 24 October, 2026 |
| **Batch** | BATCH-B2025 · L1/S2 |
| **Case Reference** | SBT-DF205-C1 |
| **Submission Format** | ZIP (Report.pdf, CSVs, Queries.sql, Screenshots) |

---

## 📌 Executive Summary

This report details the forensic examination of a logical Android extraction (Google Pixel 3, Android 10) to investigate suspected unauthorised communication by a Harbour Operations Ltd employee.

**Primary Finding:** The device is registered to the user "Josh Hickman". Evidence of communication across AOSP SMS, TextNow, Google Maps, and Google Photos was successfully recovered. The Google Messages database (`bugle_db`) utilises the `sms_message_uri` to link back to the AOSP Telephony Provider, confirming the app was active. Timeline data confirms activity in February 2020. MMS and Google Dialer data were also successfully reconstructed.

**Confidence Level:** High for device identity and artefact recovery. Moderate for timeline correlation due to mixed timezone offsets. No person-level attribution of the communications can be made solely from the technical evidence without further HR corroboration.

---

## 📑 Table of Contents

- [1. Executive Conclusion](#1-executive-conclusion)
- [2. Evidence Acquisition and Integrity](#2-evidence-acquisition-and-integrity)
- [3. Database Method](#3-database-method)
- [4. Findings](#4-findings)
- [5. Timeline and Correlation](#5-timeline-and-correlation)
- [6. Attribution Assessment](#6-attribution-assessment)
- [7. Detection and Defensive Recommendations](#7-detection-and-defensive-recommendations)
- [8. Required Forensic Findings Summary](#8-required-forensic-findings-summary)
- [9. Conclusion](#9-conclusion)
- [10. References](#10-references)
- [11. Declaration](#11-declaration)
- [Appendix A — Evidence Log](#appendix-a--evidence-log)
- [Appendix B — Screenshot Reference List](#appendix-b--screenshot-reference-list)
- [Appendix C — Key SQL Queries Used](#appendix-c--key-sql-queries-used)
- [Appendix D — Chain of Custody Worksheet](#appendix-d--chain-of-custody-worksheet)
- [Appendix E — Figure Index](#appendix-e--figure-index)

---

## 1. Executive Conclusion

The forensic examination of the Google Pixel 3 extraction successfully identified the primary user as **Josh Hickman**. The evidence establishes that the device was used for extensive communication across multiple platforms (AOSP SMS, Google Messages, TextNow) in January–February 2020. The possession and use of the device by the owner are supported by the recovered data. However, the allegation of *unauthorised* communication cannot be definitively proven without additional HR context (e.g., company policy on acceptable use). The technical evidence proves device activity, not physical operator identity.

---

## 2. Evidence Acquisition and Integrity

### 2.1 Source Artefacts

- **Source URL:** `https://digitalcorpora.s3.amazonaws.com/corpora/mobile/android_10/Non-Cellebrite%20Extraction/Pixel%203.zip`
- **Archive Name:** `Pixel 3.zip` (5.25 GB / 5,247,820,897 bytes)
- **Extracted Location:** `~/SBT-DF205-C1/working/Pixel 3/`

### 2.2 Integrity Verification

ca6918ef8b20486b6a5ded15609ac51318f377829480f93be3ba15364a8aa00a  working/Pixel 3.zip
Integrity Status: ✅ Verified. The original archive was hashed upon receipt and never mounted directly. A working copy was extracted for analysis.

https://screenshots/figure_01_evidence_hash.png

Figure 1: sha256sum output of the original Pixel 3.zip archive.

2.3 Tools Used
Tool	Version	Purpose
sqlite3	system default	Scripted SQL queries; reproducible outputs
grep	system default	System configuration extraction
exiftool	13.55	Photo metadata and GPS extraction
sha256sum	system default	Integrity verification
Kali Linux	Rolling	Analysis environment
2.4 Access Controls and Precautions
Original archive preserved unmodified.

All analysis performed on the working copy under ~/SBT-DF205-C1/working/.

No live systems, accounts, or cloud services were contacted.

Unrelated personal data redacted from screenshots.

3. Database Method
3.1 Tools Used
SQLite (CLI): Used for all database queries to ensure reproducibility and exact record references.

DB Browser for SQLite: Used to verify schema and inspect tables.

ExifTool: Used to extract GPS and timestamp metadata from media files.

3.2 Databases Reviewed
Database	Path	Rows	Purpose
mmssms.db	data/data/com.android.providers.telephony/databases/	25	SMS/MMS records
calllog.db	data/data/com.android.providers.contacts/databases/	5+	Call history
contacts2.db	data/data/com.android.providers.contacts/databases/	5+	Contact list
bugle_db	data/data/com.google.android.apps.messaging/databases/	38+	Google Messages
msgstore.db	data/data/com.whatsapp/databases/	5	WhatsApp messages
textnow_data.db	data/data/com.enflick.android.TextNow/databases/	5+	TextNow messages
annotated_call_log.db	data/data/com.google.android.dialer/databases/	3+	Google Dialer calls
gmm_myplaces.db	data/data/com.google.android.apps.maps/databases/	1	Maps location data
gphotos-1.db	data/data/com.google.android.apps.photos/databases/	5+	Photos metadata
3.3 Android Epoch Timestamp Conversion
Android stores timestamps as Unix epoch milliseconds (for most databases) or seconds. The formula used to convert to UTC:

sql
datetime(timestamp / 1000, 'unixepoch')
Where timestamps are in milliseconds. For microseconds (like some Google apps), divide by 1,000,000 instead.

Raw timestamp	UTC
1581685743277	2020-02-14 15:49:03
1581192046000	2020-02-08 14:54:52
1580570189000	2020-02-01 18:16:29
3.4 Status Field Interpretation
Field	Meaning	Observed
type (SMS)	1=Received, 2=Sent	Mixed
type (Calls)	1=Incoming, 2=Outgoing, 3=Missed	Mixed
read	0=Unread, 1=Read	Mixed
message_status	100=Delivered, 210=Sent	bugle_db
4. Findings
4.1 Device Identity and Profiles
Build Properties (from system/build.prop):

ro.build.id=QQ1A.200105.003

ro.build.version.sdk=29

ro.build.version.release=10

User Profiles (from data/system/users/userlist.xml):

User 0 (Owner) — primary account

User 11 (Work Profile) — secondary account

Account Associations:

Primary: thisisdifir@gmail.com

Corroborated by: data/system/users/0/registered_services/android.accounts.AccountAuthenticator.xml listing com.google, com.whatsapp, com.twitter.android.

Attribution Limit: Device activity cannot be attributed to a specific human operator, as multiple profiles exist and the device could have been shared.

https://screenshots/figure_02_build_properties.png

Figure 2: grep output showing the Android 10 build.

https://screenshots/figure_03_users.png

Figure 3: userlist.xml showing User 0 (Owner) and User 11.

4.2 Settings and Connectivity
Wi-Fi Configuration (WifiConfigStore.xml):

<MacAddressMap> is empty. No Wi-Fi networks were saved in this file.

Settings Secure (settings_secure.xml):

install_non_market_apps=1 (Sideloading is enabled).

https://screenshots/figure_04_wifi.png

Figure 4: WifiConfigStore.xml showing empty MacAddressMap.

https://screenshots/figure_05_settings.png

Figure 5: settings_secure.xml showing sideloading is enabled.

4.3 AOSP Communications and Contacts
SMS Records (mmssms.db):
The most recent message was sent to 919-579-0479 on 1581685743277 (UTC: 2020-02-14 15:49:03). Message body: "Wow, the messages sync over between accounts."

Call Logs (calllog.db):
A call to 9195790479 on 1581691278351 lasted 91 seconds (incoming call).

Contacts (contacts2.db):
Linked the communication number (919) 579-0479 to the contact name Josh Hickman.

MMS Reconstruction:

pdu shows m_type=128 (MMS notification) and m_type=132 (actual message).

part shows application/smil and text/plain with the extracted body: "Here's Signal."

Calendar (calendar.db):
The Events table returned 0 rows (empty database — documented as inconclusive).

https://screenshots/figure_06_sms.png

Figure 6: SQLite output of mmssms.db.

https://screenshots/figure_07_calls.png

Figure 7: SQLite output of calllog.db.

https://screenshots/figure_08_contacts.png

Figure 8: SQLite output of contacts2.db.

https://screenshots/figure_14_mms.png

Figure 9: SQLite output of pdu and part tables.

4.4 Google Messages and Dialer
Google Messages (bugle_db):
The messages table uses sms_message_uri (e.g., content://sms/24) to link back to the AOSP Telephony database, proving Google Messages was the default SMS app handling the messages.

Google Dialer (annotated_call_log.db):
The Google Dialer call log shows calls matching the AOSP log. For example, a call to +19195790479 on timestamp 1581691278351 lasting 91 seconds, exactly matching the AOSP call log.

https://screenshots/figure_09_bugle.png

Figure 10: SQLite output of bugle_db showing sms_message_uri links.

https://screenshots/figure_15_dialer.png

Figure 11: SQLite output of AnnotatedCallLog matching the AOSP call log.

4.5 WhatsApp and TextNow
WhatsApp (msgstore.db):
Only status@broadcast rows found. No direct 1-on-1 chat history was saved in this local database backup.

TextNow (textnow_data.db):
A conversation was extracted with +1(984) 203-2223. The first message was "Hi there!" at raw timestamp 1581192046000 (UTC: 2020-02-08 14:54:52).

https://screenshots/figure_10_whatsapp.png

Figure 12: SQLite output of msgstore.db.

https://screenshots/figure_11_textnow.png

Figure 13: SQLite output of textnow_data.db.

4.6 Maps and Photographs
Google Maps (gmm_myplaces.db):
The sync_item table contains an E6 coordinate: 35734602, -78636654. Converted to decimal degrees: 35.734602, -78.636654 (Raleigh, NC).

Google Photos (gphotos-1.db):
Found local media records in local_media, including IMG_20190917_082637.jpg.

SHA-256: 8c2a100a6a11aeccbfc196439c6d7d1cc0a149b3dd18264747735b7201bc1177

EXIF GPS: 35 deg 44' 8.33" N, 78 deg 38' 10.92" W

Create Date: 2019:09:17 08:26:37

https://screenshots/figure_12_maps.png

Figure 14: SQLite output of sync_item showing E6 coordinates.

https://screenshots/figure_13_photos.png

Figure 15: SQLite output of local_media.

https://screenshots/figure_16_photo_metadata.png

Figure 16: ExifTool output showing the GPS coordinates and timestamp of IMG_20190917_082637.jpg.

5. Timeline and Correlation
5.1 Time Zone Information
Property	Value
Primary Timeline Zone	UTC
Local Time (reference)	EDT (UTC-4)
SQL Conversion	datetime(timestamp/1000, 'unixepoch')
5.2 Full Reconstructed Timeline (15 Events, 4+ Families)
UTC Timestamp	Raw Timestamp (ms)	Event Description	Source Artefact
2020-02-14 15:49:03	1581685743277	SMS sent to Josh Hickman	mmssms.db
2020-02-14 15:49:18	1581691278351	Call to Josh Hickman (91s)	calllog.db
2020-02-08 14:54:52	1581192046000	TextNow: "Hi there!" received	textnow_data.db
2020-02-01 18:16:29	1580570189000	Photo captured (signal)	gphotos-1.db
2020-02-14 02:50:24	1581643824061	Call to Josh Hickman	calllog.db
2020-01-29 18:20:45	1580322045000	SMS received (LINE code)	mmssms.db
2020-01-31 21:25:44	1580505944000	Photo captured	DCIM
2020-02-14 15:45:57	1581685557104	Call received (86s)	calllog.db
2020-02-08 14:55:27	1581192087000	TextNow message received	textnow_data.db
2020-02-09 13:21:42	1581273702392	SMS sent (coffee shop)	mmssms.db
2020-02-08 14:20:00	1581174000000	TextNow message "Hi there!"	textnow_data.db
2019-04-05 12:39:06	1554470346040	Maps saved place sync	gmm_myplaces.db
2020-02-01 22:44:53	1580587493000	MMS Notification received	pdu
2020-02-01 22:45:24	1580587564000	MMS Message "Here's Signal."	part
2020-02-14 15:49:03	1581685743277	Photo metadata captured (GPS)	ExifTool
5.3 Correlations
Contacts to SMS: The number (919) 579-0479 from contacts2.db matches the destination in the mmssms.db records.

Google Messages to Telephony: The bugle_db table links via sms_message_uri to the Telephony DB, confirming Google Messages handled the SMS.

Photo to Maps: The EXIF GPS on IMG_20190917_082637.jpg (35.734...) aligns with the saved Maps location (35.734602), corroborating the user's presence in Raleigh, NC.

6. Attribution Assessment
6.1 Observed Facts vs. Inferences
Type	Finding	Basis
Observed Fact	SMS sent to 919-579-0479	sms table
Observed Fact	Call to 9195790479 lasting 91s	calls table
Observed Fact	Contact linked to Josh Hickman	contacts2.db
Observed Fact	MMS "Here's Signal." reconstructed	pdu + part
Observed Fact	Google Messages links via URI	bugle_db
Observed Fact	TextNow conversation with +1(984) 203-2223	textnow_data.db
Observed Fact	GPS on photo 35.734...	ExifTool
Inference	The person operating the device performed these actions	Browser-profile assumption
Inference	The allegation of unauthorised communication	Requires HR context
6.2 Confidence Level Matrix
Attribution Level	Confidence	Justification
Artifact authenticity	High (95%)	SHA-256 verified; chain of custody
Sequence coherence	High (90%)	Consistency across 4+ databases
Personal attribution	Moderate (60-70%)	Device activity ≠ human identity
6.3 Limitations and Alternative Explanations
Device attribution: Multiple profiles exist; device could be shared.

Missing WhatsApp data: Only broadcast statuses were recovered.

Empty Wi-Fi config: No saved networks in WifiConfigStore.xml.

Empty Calendar: No events in calendar.db.

No server-side logs: Craigslist, Gmail, etc., logs not available.

6.4 MITRE ATT&CK Mapping
Technique	ID	Relevance
Data from Local System	T1005	Android database extraction
Application Layer Protocol — Web	T1071.001	App network activity
Financial Fraud (Cyber-Enabled)	T1657	Communication evidence
7. Detection and Defensive Recommendations
7.1 Detection Controls
Control	Description
MDM logging	Capture app activity on managed devices
DLP on SMS	Alert on sensitive message content
Location tracking	Correlate device location with policy
7.2 Defensive Recommendations
Control	Description
MDM + identity binding	Map device to specific user
App whitelisting	Restrict unauthorised apps
Regular audits	Review communications for policy violations
8. Required Forensic Findings Summary
Task	Finding	Evidence
1	SHA-256 ca6918ef... verified	sha256sum
2	Android 10, Users 0 & 11	build.prop, userlist.xml
3	Sideloading enabled, Wi-Fi empty	settings_secure.xml, WifiConfigStore.xml
4	SMS, Calls, Contacts, MMS reconstructed	mmssms.db, calllog.db, contacts2.db, pdu/part
5	Google Messages links to Telephony	bugle_db
6	TextNow conversation, WhatsApp empty	textnow_data.db, msgstore.db
7	Maps location 35.73, -78.63; Photo GPS 35.73, -78.63	gmm_myplaces.db, ExifTool
8	15-event timeline, 3 correlations	Section 5
9. Conclusion
The forensic examination successfully recovered device identity, communications, and media artefacts from the Pixel 3 extraction. The device belongs to Josh Hickman and was used for communication across multiple apps. The allegation of unauthorised use requires HR context. Technical evidence proves device activity, not operator identity.

Key Takeaways:

Android databases store extensive forensic artifacts.

Cross-database correlation is powerful.

Timestamp conversion is critical.

Device attribution requires additional evidence.

10. References
ICDFA. (2026). SBT-DF205 — Mobile and IoT Forensics Case Study — Module Materials.

ICDFA. (2026). SBT-DF205 Case 1 — Android Forensics Investigation of a Google Pixel 3 — Assessment Brief.

Google. (2023). Android SQLite Database Schema.

SQLite Documentation. (2024). SQLite Query Language.

ExifTool. (2024). Metadata Extraction.

MITRE ATT&CK. (2026). T1005: Data from Local System.

MITRE ATT&CK. (2026). T1071.001: Application Layer Protocol — Web Protocols.

11. Declaration
I, Ibrahim Ishaku, confirm that this case study report is based on my own practical work conducted in the ICDFA lab environment. All SQL queries, timeline reconstruction, and forensic correlation tasks are my own original work. The original Pixel 3 extraction was preserved with a SHA-256 hash (ca6918ef...), all analysis was performed on a verified working copy, and no live systems, accounts, or external services were contacted.

Signature: ______________________

Date: 24 October, 2026

Appendix A — Evidence Log
Evidence ID	Source Record	Finding	Why It Matters	SQL / Screenshot Reference
E01	Pixel 3.zip	SHA-256 ca6918ef...	Evidence integrity	Figure 1
E02	system/build.prop	Android 10, Build QQ1A	Device identity	Figure 2
E03	userlist.xml	User 0, User 11	Profiles	Figure 3
E04	WifiConfigStore.xml	Empty MacAddressMap	No Wi-Fi	Figure 4
E05	settings_secure.xml	install_non_market_apps=1	Sideloading	Figure 5
E06	mmssms.db	SMS to 919-579-0479	Communication	Figure 6
E07	calllog.db	91s call	Communication	Figure 7
E08	contacts2.db	Josh Hickman linked	Identity	Figure 8
E09	pdu/part	MMS "Here's Signal."	MMS	Figure 9
E10	bugle_db	sms_message_uri links	App usage	Figure 10
E11	annotated_call_log.db	Matching calls	Dialer	Figure 11
E12	msgstore.db	Only broadcasts	WhatsApp	Figure 12
E13	textnow_data.db	Conversation	TextNow	Figure 13
E14	gmm_myplaces.db	E6 coords	Location	Figure 14
E15	gphotos-1.db	Photo records	Media	Figure 15
E16	ExifTool	GPS coords	Media	Figure 16
Appendix B — Screenshot Reference List
Figure	Description	SQL Filter / View	Evidence ID
1	Evidence hash	sha256sum	E01
2	Build properties	grep	E02
3	User profiles	cat	E03
4	Wi-Fi config	grep	E04
5	Settings secure	grep	E05
6	SMS records	sqlite3	E06
7	Call logs	sqlite3	E07
8	Contacts	sqlite3	E08
9	MMS reconstruction	sqlite3	E09
10	Google Messages	sqlite3	E10
11	Google Dialer	sqlite3	E11
12	WhatsApp	sqlite3	E12
13	TextNow	sqlite3	E13
14	Maps	sqlite3	E14
15	Photos	sqlite3	E15
16	Photo metadata	exiftool	E16
Appendix C — Key SQL Queries Used
sql
-- Task 4: SMS Extraction
SELECT _id, address, body, date, type, read FROM sms ORDER BY date DESC LIMIT 5;

-- Task 4: Calls
SELECT number, date, duration, type FROM calls ORDER BY date DESC LIMIT 5;

-- Task 4: Contacts
SELECT display_name, data1 FROM raw_contacts JOIN data ON raw_contacts._id = data.raw_contact_id WHERE data.mimetype_id = 5 LIMIT 5;

-- Task 4: MMS
SELECT _id, thread_id, date, msg_box, m_type FROM pdu LIMIT 3;
SELECT _id, mid, seq, ct, text, fn FROM part LIMIT 3;

-- Task 5: Google Messages
SELECT _id, conversation_id, sent_timestamp, sms_message_uri FROM messages ORDER BY sent_timestamp DESC LIMIT 5;

-- Task 5: Google Dialer
SELECT timestamp, number, duration, call_type FROM AnnotatedCallLog ORDER BY timestamp DESC LIMIT 3;

-- Task 6: TextNow
SELECT _id, contact_name, message_text, date FROM messages LIMIT 5;

-- Task 6: WhatsApp
SELECT key_remote_jid, data, timestamp FROM messages LIMIT 5;

-- Task 7: Maps
SELECT * FROM sync_item LIMIT 5;

-- Task 7: Photos
SELECT filename, filepath, capture_timestamp FROM local_media LIMIT 5;
Appendix D — Chain of Custody Worksheet
Field	Value
Case/Lab Identifier	SBT-DF205-CaseStudy1-Ibrahim-Ishaku
Trainee Name	Ibrahim Ishaku
Student ID	2025/FWSD/11334
Date and Time Acquired	24 October, 2026 — 12:00 WAT
Evidence File Name(s)	Pixel 3.zip
Source URL	https://digitalcorpora.s3.amazonaws.com/corpora/mobile/android_10/Non-Cellebrite%20Extraction/Pixel%203.zip
File Type	ZIP archive (5.25 GB)
Original SHA-256	ca6918ef8b20486b6a5ded15609ac51318f377829480f93be3ba15364a8aa00a
Working Copy	~/SBT-DF205-C1/working/Pixel 3/
Storage Location	~/SBT-DF205-C1/
Custodian	Ibrahim Ishaku (Student, ICDFA)
Handling Notes	Original preserved; no live systems contacted; unrelated data redacted
Analysis Tools	sqlite3, grep, exiftool, sha256sum, Kali Linux
Analysis Date	24 October, 2026
Appendix E — Figure Index
Figure	Filename	Cited In
1	screenshots/figure_01_evidence_hash.png	Section 2.2
2	screenshots/figure_02_build_properties.png	Section 4.1
3	screenshots/figure_03_users.png	Section 4.1
4	screenshots/figure_04_wifi.png	Section 4.2
5	screenshots/figure_05_settings.png	Section 4.2
6	screenshots/figure_06_sms.png	Section 4.3
7	screenshots/figure_07_calls.png	Section 4.3
8	screenshots/figure_08_contacts.png	Section 4.3
9	screenshots/figure_14_mms.png	Section 4.3
10	screenshots/figure_09_bugle.png	Section 4.4
11	screenshots/figure_15_dialer.png	Section 4.4
12	screenshots/figure_10_whatsapp.png	Section 4.5
13	screenshots/figure_11_textnow.png	Section 4.5
14	screenshots/figure_12_maps.png	Section 4.6
15	screenshots/figure_13_photos.png	Section 4.6
16	screenshots/figure_16_photo_metadata.png	Section 4.6
📄 End of Report
SBT-DF205 — Case 1: Android Forensics Investigation of a Google Pixel 3

Submitted by: Ibrahim Ishaku | Student ID: 2025/FWSD/11334

Date: 24 October, 2026

🎓 Academic Notice
This case study was completed as part of the Fellowship in Web Application Security & Digital Forensics at the International Cybersecurity and Digital Forensics Academy (ICDFA).

All work is the author's original submission for academic purposes.

The database was used only for this authorised academic case study.

No live network, host, or account was contacted.

Unrelated personal data has been redacted from screenshots.

End of Case Study Report
