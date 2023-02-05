use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Used to work around Serde's handling of serializing Option::Some values within a map.
/// See optional_value's README.md for further information.
pub fn serialize_option_some<S, T>(value: &Option<T>, ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    value
        .as_ref()
        .expect("serde should skip serialization if None")
        .serialize(ser)
}

/// Used to work around Serde's handling of deserializing Option::Some values within a map.
/// See optional_value's README.md for further information.
pub fn deserialize_option_some<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(de).map(Some)
}
