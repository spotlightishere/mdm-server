# optional_value

This macro is a hack - it exists to work around serde's flattening [providing a map](https://github.com/serde-rs/serde/issues/1346), which has different semantics for Option than struct with [plist](https://docs.rs/plist/latest/plist/). It is meant to only be used within the `payloads` module.

As a brief example, consider the following scenario:
```rust
#[derive(Serialize)]
pub struct OuterConfig {
    enabled: bool,
    config: InnerConfig,
}

#[derive(Serialize)]
pub struct InnerConfig {
    first_value: Option<&'static str>,
    second_value: Option<i64>,
}

let example = OuterConfig {
    enabled: true,
    config: InnerConfig {
        first_value: Some("Hello, world!"),
        second_value: None,
    },
};
```
With this alone, the following output can be expected:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
		<key>enabled</key>
		<true/>
		<key>config</key>
		<dict>
			<key>first_value</key>
			<string>Hello, world!</string>
		</dict>
	</dict>
</plist>
```

However, if we add `#[serde(flatten)]` to our `config` field in OuterConfig, the following occurs:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
		<key>enabled</key>
		<true/>
		<key>first_value</key>
		<dict>
			<key>Some</key>
			<string>Hello, world!</string>
		</dict>
		<key>second_value</key>
		<dict>
			<key>None</key>
			<string></string>
		</dict>
	</dict>
</plist>
```

For more information regarding the plist crate in specific, refer to [this issue](https://github.com/ebarnard/rust-plist/pull/55#issuecomment-771113306).

---

As a result, we must manually perform deserialization and serialization. In order to avoid manually specifying
```rust
#[serde(
    deserialize_with = "deserialize_some",
    serialize_with = "serialize_some",
    skip_serializing_if = "Option::is_none",
)]
```
on all optional attributes, this macro exists to apply it on your behalf.
