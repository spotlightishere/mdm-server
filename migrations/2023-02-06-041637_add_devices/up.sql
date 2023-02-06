CREATE TABLE devices (
  -- We identify devices by their UDID.
  --
  -- Note that there is no documented format for device UDIDs:
  -- some may be the legacy 41 characters, where newer devices
  -- are documented to be lesser or greater.
  udid VARCHAR PRIMARY KEY NOT NULL,
  device_version VARCHAR NOT NULL,
  product VARCHAR NOT NULL,
  serial_number VARCHAR NOT NULL,
  imei VARCHAR,
  last_contact DATETIME NOT NULL
);