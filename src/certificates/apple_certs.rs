use openssl::{
    error::ErrorStack,
    stack::Stack,
    x509::{store::X509Store, store::X509StoreBuilder, verify::X509VerifyFlags, X509},
};

// Apple writes:
// "Validate that the device certificate is issued from “Apple iPhone Device CA”, which has the following Base64 encoded PEM data:"
// https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/iPhoneOTAConfiguration/profile-service/profile-service.html#//apple_ref/doc/uid/TP40009505-CH2-SW4
pub const APPLE_IPHONE_DEVICE_CA: &[u8; 1244] = b"-----BEGIN CERTIFICATE-----
MIIDaTCCAlGgAwIBAgIBATANBgkqhkiG9w0BAQUFADB5MQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxLTArBgNVBAMTJEFwcGxlIGlQaG9uZSBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTAeFw0wNzA0MTYyMjU0NDZaFw0xNDA0MTYyMjU0NDZaMFoxCzAJ
BgNVBAYTAlVTMRMwEQYDVQQKEwpBcHBsZSBJbmMuMRUwEwYDVQQLEwxBcHBsZSBp
UGhvbmUxHzAdBgNVBAMTFkFwcGxlIGlQaG9uZSBEZXZpY2UgQ0EwgZ8wDQYJKoZI
hvcNAQEBBQADgY0AMIGJAoGBAPGUSsnquloYYK3Lok1NTlQZaRdZB2bLl+hmmkdf
Rq5nerVKc1SxywT2vTa4DFU4ioSDMVJl+TPhl3ecK0wmsCU/6TKqewh0lOzBSzgd
Z04IUpRai1mjXNeT9KD+VYW7TEaXXm6yd0UvZ1y8Cxi/WblshvcqdXbSGXH0KWO5
JQuvAgMBAAGjgZ4wgZswDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8w
HQYDVR0OBBYEFLL+ISNEhpVqedWBJo5zENinTI50MB8GA1UdIwQYMBaAFOc0Ki4i
3jlga7SUzneDYS8xoHw1MDgGA1UdHwQxMC8wLaAroCmGJ2h0dHA6Ly93d3cuYXBw
bGUuY29tL2FwcGxlY2EvaXBob25lLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAd13P
Z3pMViukVHe9WUg8Hum+0I/0kHKvjhwVd/IMwGlXyU7DhUYWdja2X/zqj7W24Aq5
7dEKm3fqqxK5XCFVGY5HI0cRsdENyTP7lxSiiTRYj2mlPedheCn+k6T5y0U4Xr40
FXwWb2nWqCF1AgIudhgvVbxlvqcxUm8Zz7yDeJ0JFovXQhyO5fLUHRLCQFssAbf8
B4i8rYYsBUhYTspVJcxVpIIltkYpdIRSIARA49HNvKK4hzjzMS/OhKQpVKw+OCEZ
xptCVeN2pjbdt9uzi175oVo/u6B2ArKAW17u6XEHIdDMOe7cb33peVI6TD15W4MI
pyQPbp8orlXe+tA8JA==
-----END CERTIFICATE-----";

// "Apple iPhone Device CA" is issued by "Apple iPhone Certification Authority".
pub const APPLE_IPHONE_CA: &[u8; 1431] = b"-----BEGIN CERTIFICATE-----
MIID8zCCAtugAwIBAgIBFzANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDcwNDEyMTc0
MzI4WhcNMjIwNDEyMTc0MzI4WjB5MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
LTArBgNVBAMTJEFwcGxlIGlQaG9uZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMevvBHwLSeEFtGpLghuE+G
IXAoRWBcHMPICmRjiPv8ae74VPzpW7cGTgQvw2szr0RM6kuACbSH9lu0/WTds3Lg
E7P9F9m856jtwoxhwir57M6lXtZp62QLjQiPuKBQRgncGeTlsJRtu/eZmMTom0FO
1PFl4xtSetzoA9luHdoQVYakKVhJDOpH1xU0M/bAoERKcL4stSowN4wuFevR5GyX
OFVWsTUrWOpEoyaF7shmSuTPifA9Y60p3q26WrPcpaOapwlOgBY1ZaSFDWN7PmOK
2n1KRuyjORg0ucYoZRi8E2Ccf1esFMmJ7aG2h2hStoROuMiD7PmeGauzwQuGx58C
AwEAAaOBnDCBmTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQU5zQqLiLeOWBrtJTOd4NhLzGgfDUwHwYDVR0jBBgwFoAUK9BpR5R2Cf70
a40uQKb3R01/CF4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL3d3dy5hcHBsZS5j
b20vYXBwbGVjYS9yb290LmNybDANBgkqhkiG9w0BAQUFAAOCAQEAHdHVe910TtcX
/IItDJmbXkJy8mnc1WteDQxrSz57FCXes5TooPoPgInyFz0AAqKRkb50V9yvmp+h
Cn0wvgAqzCFZ6/1JrG51GeiaegPRhvbn9rAOS0n6o7dButfR41ahfYOrl674UUom
wYVCEyaNA1RmEF5ghAUSMStrVMCgyEG8VB7nVK0TANJKx7vBiq+BCI7wRgq/J6a+
3M85OoBwGSMyo2tmXZ5NqEdJsntFtVEzp3RnCU62bG9I9yy5MwVEa0W+dEtvsoaR
tD4lKCWes8JRhvxP5a87qrtELAFJ4nSzNPpE7xTCEfItGRpRidMISkFsWFbemzrh
BVflYs/SDw==
-----END CERTIFICATE-----";

// "Apple iPhone Certification Authority" is issued by "Apple Root CA".
pub const APPLE_ROOT_CA: &[u8; 1699] = b"-----BEGIN CERTIFICATE-----
MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0
MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w
tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW
q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM
aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3
R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE
ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93
d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl
IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc
NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP
y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7
R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg
xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP
IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX
UKqK1drk/NAJBzewdXUh
-----END CERTIFICATE-----";

pub struct AppleCerts;

impl AppleCerts {
    pub fn iphone_device_ca() -> X509 {
        X509::from_pem(APPLE_IPHONE_DEVICE_CA).expect("Apple iPhone Device CA should be valid")
    }

    pub fn iphone_ca() -> X509 {
        X509::from_pem(APPLE_IPHONE_CA)
            .expect("Apple iPhone Certification Authority should be valid")
    }

    pub fn root_ca() -> X509 {
        X509::from_pem(APPLE_ROOT_CA).expect("Apple iPhone Certification Authority should be valid")
    }

    /// Creates a certificate stack with Apple's iPhone Device CA.
    /// Any envelope signed by Apple should only be signed by their "Apple iPhone Device CA".
    pub fn cert_stack() -> Result<Stack<X509>, ErrorStack> {
        let mut ca_stack = Stack::new().expect("should be able to create X509 stack");
        ca_stack.push(AppleCerts::iphone_device_ca())?;
        Ok(ca_stack)
    }

    /// Creates a certificate store with Apple's three CAs.
    pub fn cert_store() -> Result<X509Store, ErrorStack> {
        let mut ca_store = X509StoreBuilder::new()?;
        ca_store.add_cert(AppleCerts::iphone_device_ca())?;
        ca_store.add_cert(AppleCerts::iphone_ca())?;
        ca_store.add_cert(AppleCerts::root_ca())?;

        // Then, we must disable its certificate date validity.
        //
        // Apple writes within "Creating a Profile Server for Over-The-Air Enrollment and Configuration":
        // "WARNING: When device certificates signed 'Apple iPhone Device CA' are evaluated
        // their validity dates should be ignored."
        ca_store.set_flags(X509VerifyFlags::NO_CHECK_TIME)?;

        let ca_store = ca_store.build();
        Ok(ca_store)
    }
}
