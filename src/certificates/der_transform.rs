use cms::{cert::CertificateChoices, content_info::ContentInfo, signed_data::SignedData};
use der::{Decode, Encode, ErrorKind, asn1::SetOfVec};

// Various lengths of tags and objects we use.
const TAG_LENGTH_INDETERMINATE: usize = 2;
const TAG_LENGTH: usize = 4;
const ECONTENTTYPE_LENGTH: usize = 11;

// Offsets to various objects from their original, indeterminate position.
const INNER_STRING_OFFSET: usize = 50;
const OUTER_OCTET_OFFSET: usize = 48;
const ECONTENT_OFFSET: usize = 46;
const ENCAP_OFFSET: usize = 33;
const SIGNED_OFFSET: usize = 15;
const CONTENT_ELEM_OFFSET: usize = 13;
const CONTENT_INFO_OFFSET: usize = 0;

/// Given a current two-byte indeterminate object tag,
/// transform it into a four-byte determinate tag (with two-byte length).
fn insert_object_len(contents: &mut Vec<u8>, object_offset: usize, new_length: u16) {
    // First, convert our length to insertable bytes.
    let length_bytes = new_length.to_be_bytes();
    let first_length = length_bytes[0];
    let second_length = length_bytes[1];

    // Change from infinite length (0x80) to a finite length represented by two bytes (0x82).
    contents[object_offset + 1] = 0x82;
    // Insert our two length bytes.
    contents.insert(object_offset + 2, first_length);
    contents.insert(object_offset + 3, second_length);
}

/// Reads the length of the object at the specified offset.
fn read_object_len(der_contents: &[u8], object_offset: usize) -> usize {
    u16::from_be_bytes([
        der_contents[object_offset + 2],
        der_contents[object_offset + 3],
    ]) as usize
}

/// A hack to permit decoding via the [`cms`] crate.
///
/// Apple devices produce PKCS#7 data with mixed
/// BER and DER encoding, BER permits indefinite lengths,
/// which [`cms`] currently does not have complete support for.
///
/// This is horribly inefficient and would be even more so
/// on large payloads. Use at your own risk.
fn encode_as_der(ber_contents: Vec<u8>) -> Option<Vec<u8>> {
    let mut result = ber_contents.clone();
    // For our intents and purposes, our PKCS#7 payload matches this format:
    //   ContentInfo (SEQENCE) -> content {
    //     contentType (OBJECT IDENTIFIER)
    //     SignedData (SEQUENCE) {
    //       version (INTEGER)
    //       digestAlgorithms (SET)
    //       encapContentInfo (SEQUENCE) {
    //         eContentType (OBJECT IDENTIFIER)
    //         eContent {
    //           payload (OCTET STRING)
    //         }
    //       [...]
    //     }
    //   }
    //
    // (Please refer to https://datatracker.ietf.org/doc/html/rfc5652#section-5.1
    // for the full PKCS#7 SignedData format/specification.)
    //
    // On Apple platforms, all parent elements to encapContentInfo
    // lack any specified length. The eContent octet string
    // additionally lacks a length - however, it has
    // another octet string within, which _does_ have a length.
    //
    // We can use this to identify our inner octet string:
    // element tag 0x04, length 0x8 of two bytes 0x2.
    // We will make an assumption of only one specified digest algorithm.
    //
    // Following the format above, this would mean that the
    // inner string is at an offset 50 of bytes.
    // TODO(spotlightishere): We perform zero sanity checks.
    const STRING_EXPECTED_TAG: [u8; 2] = [0x04, 0x82];
    let string_read_tag = [
        ber_contents[INNER_STRING_OFFSET],
        ber_contents[INNER_STRING_OFFSET + 1],
    ];

    if string_read_tag != STRING_EXPECTED_TAG {
        // This likely means that we do not need to fix up
        // our encoding. Return this envelope as-is.
        return Some(result);
    }

    // Good, it is. We'll now parse it as such.
    // The length of our octet string is in the following two bytes.
    let string_length = read_object_len(&result, INNER_STRING_OFFSET);

    // Our total inner string object size is its contents length
    // and its determinate tag.
    let inner_octet_length = string_length + TAG_LENGTH;

    // Due to the nature of BER, each indefinite object ends with two nulls.
    // Prior to our inner octet string, we had three objects:
    //  - the outer octet string
    //  - eContent
    //  - encapContentInfo
    // We'll remove these six null bytes following our string.
    let string_end_offset = INNER_STRING_OFFSET + inner_octet_length;
    result.drain(string_end_offset..string_end_offset + 6);

    // Additionally, our three outer objects create similar:
    //  - SignedData
    //  - content
    //  - ContentInfo
    // We'll remove the six null bytes at the end of our vector.
    result.truncate(result.len() - 6);

    // Remove our outer octet as it's no longer necessary.
    result.remove(OUTER_OCTET_OFFSET);
    result.remove(OUTER_OCTET_OFFSET);

    // Regretfully, we're not done quite yet.
    // macOS versions (as of at least 15.0, possibly older)
    // include duplicate certificates within their certificate sets.
    // This is against specification, and the Rust `der` crate
    // (rightfully) fails to parse such.
    // We'll need to manually de-duplicate certificates.
    //
    // Our certificate set immediately follows our eContent.
    // We'll need to go back 2 bytes to adjust to the changes above.
    let certificate_set_offset = string_end_offset - 2;
    let certificate_set_length = 4 + read_object_len(&result, certificate_set_offset);

    // Our raw set additionally includes the tag and length, adding another 4 bytes.
    let certificate_set_end = certificate_set_offset + certificate_set_length;
    let certificate_set_bytes = &result[certificate_set_offset..certificate_set_end].to_vec();

    // Loop through all certificates and manually read them all.
    // We initially begin reading 4 bytes in due to the set's tag and length.
    let mut certificate_set: Vec<&[u8]> = vec![];
    let mut certificate_loop_offset = 4;
    while certificate_set_bytes.len() > certificate_loop_offset {
        // We track the current certificate's length, alongside its tag/length (4 bytes).
        let current_certificate_len =
            4 + read_object_len(certificate_set_bytes, certificate_loop_offset);

        // Track for later de-duplication.
        let current_certificate_end = certificate_loop_offset + current_certificate_len;
        let current_certificate_bytes =
            &certificate_set_bytes[certificate_loop_offset..current_certificate_end];
        certificate_set.push(current_certificate_bytes);

        certificate_loop_offset += current_certificate_len;
    }

    // We should only have exactly as many bytes as parsed.
    if certificate_loop_offset > certificate_set_bytes.len() {
        return None;
    }

    // Attempt to recreate our CertificateSet.
    let mut rebuilt_set: SetOfVec<CertificateChoices> = SetOfVec::new();
    for possible_bytes in certificate_set {
        let possible_certificate = CertificateChoices::from_der(possible_bytes).ok()?;
        match rebuilt_set.insert_ordered(possible_certificate) {
            Ok(()) => continue,
            Err(e) => match e.kind() {
                // If this was a duplicate, we've already done our job.
                ErrorKind::SetDuplicate => continue,
                // This is not for us to handle.
                _ => return None,
            },
        }
    }

    // Replace our existing CertificateSet.
    let mut rebuilt_certificate_set = rebuilt_set.to_der().ok()?;
    // This is context-specific - this will not be a valid CertificateSet otherwise.
    if rebuilt_certificate_set[0] == 0x31 {
        rebuilt_certificate_set[0] = 0xA0;
    }
    result.splice(
        certificate_set_offset..certificate_set_end,
        rebuilt_certificate_set,
    );

    // We can now work backwards to resize outer objects.
    // First, resize eContent, starting at 46.
    insert_object_len(&mut result, ECONTENT_OFFSET, inner_octet_length as u16);
    let econtent_length = inner_octet_length + TAG_LENGTH;

    // Second, encapContentInfo, starting at offset 33.
    // encapContentInfo includes eContent and eContentType,
    // whose length is 11 bytes in total.
    let encap_contents_length = econtent_length + ECONTENTTYPE_LENGTH;
    insert_object_len(&mut result, ENCAP_OFFSET, encap_contents_length as u16);

    // Third, SignedData, starting at offset 15.
    // Given this is effectively our parent object,
    // its length is the entire DER minus its offset and current indeterminate tag, three bytes.
    let signed_contents_length = result.len() - SIGNED_OFFSET - TAG_LENGTH_INDETERMINATE;
    insert_object_len(&mut result, SIGNED_OFFSET, signed_contents_length as u16);

    // Fourth, our overarching content object from ContentInfo at offset 13.
    // Its contents length is the same as SignedData, plus its 4-byte tag.
    let content_length = signed_contents_length + TAG_LENGTH;
    insert_object_len(&mut result, CONTENT_ELEM_OFFSET, content_length as u16);

    // Lastly, fifth, our ContentInfo, starting at the very beginning.
    // Its contents length is the entire object offset by its 4-byte tag.
    let content_info_length = result.len() - TAG_LENGTH_INDETERMINATE;
    insert_object_len(&mut result, CONTENT_INFO_OFFSET, content_info_length as u16);

    Some(result)
}

/// Parses the given BER-encoded certificate as a CMS/PKCS#7 signed body,
/// returning its contents and certificates.
pub fn parse_der(ber_contents: Vec<u8>) -> Option<SignedData> {
    // For macOS purposes, we may need to re-encode this
    // to have finite DER-style lengths.
    // (The Rust [`der`] crate currently does not support such.)
    let result = encode_as_der(ber_contents)?;

    // We're done hacking together a fully DER-encoded object.
    // We can finally use the Rust cms crate to extract its contents.
    let parsed_content =
        ContentInfo::from_der(&result).expect("should be able to parse body as ContentInfo");

    // Our contents should be pkcs7-data.
    let envelope = parsed_content
        .content
        .decode_as::<SignedData>()
        .expect("should be able to parse contents as SignedData");

    Some(envelope)
}
