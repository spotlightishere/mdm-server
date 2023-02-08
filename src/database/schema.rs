// @generated automatically by Diesel CLI.

diesel::table! {
    devices (udid) {
        udid -> Text,
        device_version -> Text,
        product -> Text,
        serial_number -> Text,
        imei -> Nullable<Text>,
        // TODO: For now, we need to manually change
        // `Timestamp` to `TimestamptzSqlite` due to
        // https://github.com/diesel-rs/diesel/issues/3320
        last_contact -> TimestamptzSqlite,
    }
}

diesel::table! {
    pending_enrollments (challenge) {
        challenge -> Text,
        creation_date -> TimestamptzSqlite,
    }
}

diesel::allow_tables_to_appear_in_same_query!(devices, pending_enrollments,);
