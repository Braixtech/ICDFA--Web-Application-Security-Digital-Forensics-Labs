-- TARGET: data/data/com.android.providers.telephony/databases/mmssms.db
SELECT _id, address, body, date, type, read FROM sms ORDER BY date DESC LIMIT 5;

-- TARGET: data/data/com.android.providers.contacts/databases/calllog.db
SELECT number, date, duration, type FROM calls ORDER BY date DESC LIMIT 5;

-- TARGET: data/data/com.google.android.apps.messaging/databases/bugle_db
SELECT _id, conversation_id, sent_timestamp, sms_message_uri FROM messages ORDER BY sent_timestamp DESC LIMIT 5;

-- TARGET: data/data/com.enflick.android.TextNow/databases/textnow_data.db
SELECT _id, contact_name, message_text, date FROM messages LIMIT 5;

-- TARGET: data/data/com.google.android.apps.maps/databases/gmm_myplaces.db
SELECT * FROM sync_item LIMIT 5;

-- TARGET: data/data/com.android.providers.telephony/databases/mmssms.db
-- PURPOSE: MMS Reconstruction
SELECT _id, thread_id, date, msg_box, m_type FROM pdu LIMIT 3;
SELECT _id, mid, seq, ct, text, fn FROM part LIMIT 3;

-- TARGET: data/data/com.google.android.dialer/databases/annotated_call_log.db
-- PURPOSE: Google Dialer Call Log
SELECT timestamp, number, duration, call_type FROM AnnotatedCallLog ORDER BY timestamp DESC LIMIT 3;
