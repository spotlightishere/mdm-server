use proc_macro::TokenStream;
use syn::{parse_quote, Attribute};

#[proc_macro_attribute]
/// Given a struct, adds Clone and serde's Serialize/Deserialize.
/// It then tacks on our custom serde serializers to every field with a type of Option<T>.
/// For more information on why this is necessary, refer to README.md.
pub fn payload(_metadata: TokenStream, item: TokenStream) -> TokenStream {
    let mut ast: syn::DeriveInput = syn::parse(item).unwrap();

    // We only want to handle having CustomOptional on structs.
    let syn::Data::Struct(ref old_struct) = ast.data else {
        panic!("CustomOptional should only be applied on structs.")
    };

    let mut current_struct = old_struct.clone();

    // Now, we need to operate on fields within this
    // structure that have any Option<T>-like value.
    for field in current_struct.fields.iter_mut() {
        let syn::Type::Path(field_path) = &field.ty else {
            continue;
        };

        // As long as the field's last path segment is "Option", we will assume
        // that this is an Option type.
        let Some(last_segment) = field_path.path.segments.last() else {
            // It's possible that the user is still writing code,
            // or we've run into another scenario we're not familiar with.
            // Silently ignore.
            continue;
        };

        if last_segment.ident != "Option" {
            continue;
        }

        // Good - we have an optional value.
        // Let's tack on our own serde attributes.
        let serialize_attr: Attribute = parse_quote!(
            #[serde(
                deserialize_with = "crate::payloads::ser::deserialize_option_some",
                serialize_with = "crate::payloads::ser::serialize_option_some",
                skip_serializing_if = "Option::is_none"
            )]
        );
        field.attrs.push(serialize_attr);
    }

    ast.data = syn::Data::Struct(current_struct);

    // Lastly, add Clone, and serde's Serialize/Deserialize macros.
    let output: proc_macro2::TokenStream = parse_quote! {
        #[derive(Clone, serde::Serialize, serde::Deserialize)]
        #ast
    };
    output.into()
}
