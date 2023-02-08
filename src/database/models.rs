use super::schema::pending_enrollments;
use diesel::prelude::*;
use time::OffsetDateTime;

#[derive(Queryable, Insertable)]
pub struct PendingEnrollment {
    pub challenge: String,
    pub creation_date: OffsetDateTime,
}

#[derive(Queryable)]
pub struct Device {
    pub udid: String,
    pub device_version: String,
    pub product: String,
    pub serial_number: String,
    pub imei: Option<String>,
    pub last_contact: OffsetDateTime,
}
