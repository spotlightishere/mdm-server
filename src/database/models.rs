use diesel::prelude::*;
use time::OffsetDateTime;

#[derive(Queryable)]
pub struct Device {
    pub udid: String,
    pub device_version: String,
    pub product: String,
    pub serial_number: String,
    pub imei: Option<String>,
    pub last_contact: OffsetDateTime,
}
