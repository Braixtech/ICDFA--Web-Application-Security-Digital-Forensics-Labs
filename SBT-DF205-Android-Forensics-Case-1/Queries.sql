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
