// @generated automatically by Diesel CLI.

diesel::table! {
    devices (udid) {
        udid -> Text,
        device_version -> Text,
        product -> Text,
        serial_number -> Text,
        imei -> Nullable<Text>,
        last_contact -> Timestamp,
    }
}
