#![doc = include_str!("../README.md")]

use convert_case::{Case, Casing};
use syn::spanned::Spanned;

/// Performs an LDAP search and converts the result into suitable Rust types
///
/// the first few parameters are the same as in the function version of ldap_search
/// from the ldap-utils crate (and indeed they are just passed through to that)
///
/// Where this starts to differ is the attribute list, each attribute name has
/// a Rust type, either a Vec (for multi-valued attributes), an Option
/// (for optional single-valued attributes) or a bare type implementing the
/// `ldap_types::conversion::FromStringLdapType` trait for values converting
/// from the string attributes or each of those wrapped in
/// `ldap_types::conversion::Binary` and implementing
/// `ldap_types::conversion::FromBinaryLdapType` for values converting from
/// binary attributes.
///
/// Unwrapping the Binary part needs to happen manually for now.
///
/// The attribute names are converted to snake case for variable names and under
/// the hood an async function is generated with the specified return type and
/// body. In addition to the attributes the function also gets a parameter dn
/// for the entry DN as a `ldap_types::basic::DistinguishedName`
///
///
/// ```
/// #[tokio::main]
/// pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let (mut ldap, base_dn) = ldap_utils::connect().await?;
///     ldap_macros::ldap_search!(
///         &mut ldap,
///         &base_dn,
///         ldap3::Scope::Subtree,
///         "(objectclass=fooBar)",
///         [ "fooAttribute as usize", "barAttribute as Option<bool>", "bazAttribute as Vec<String>", "quuxAttribute as ldap_types::conversion::Binary<Vec<u8>>" ],
///         "Result<(), Box<dyn std::error::Error>>",
///         {
///             let ldap_types::conversion::Binary(quux_attribute) = quux_attribute;
///             println!("DN: {}, foo: {}, bar: {:?}, baz: {:?}, quux: {:?}", dn, foo_attribute, bar_attribute, baz_attribute, quux_attribute);
///             Ok(())
///         }
///     );
///     Ok(())
/// }
/// ```
#[proc_macro]
pub fn ldap_search(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let args = syn::parse_macro_input!(input with syn::punctuated::Punctuated<syn::Expr, syn::Token![,]>::parse_terminated);

    if args.len() != 7 {
        return quote::quote! { compile_error!("Expected 7 arguments (ldap client handle, base dn, scope, filter, attributes, return type, body)") }.into();
    }

    let ldap_client_handle = &args[0];
    let base_dn = &args[1];
    let scope = &args[2];
    let filter = &args[3];
    let attributes = &args[4];
    let return_type = &args[5];
    let body = &args[6];

    let syn::Expr::Array(attributes) = attributes else {
        return quote::quote! { compile_error!("Expected fifth argument to be an array of attribute specifiers (attribute name as Rust type)") }.into();
    };

    let syn::Expr::Lit(syn::ExprLit {
        attrs: _,
        lit: syn::Lit::Str(return_type),
    }) = return_type
    else {
        return quote::quote! { compile_error!("Expected sixth argument to be a literal String containing a Rust type") }.into();
    };

    let Ok(return_type): Result<syn::Type, syn::Error> = syn::parse_str(&return_type.value())
    else {
        return quote::quote! { compile_error!("Expected sixth argument to be a literal String containing a Rust type") }.into();
    };

    let mut attribute_names = Vec::new();
    let mut attribute_handlers = Vec::new();
    let mut attribute_definition_parameters = Vec::new();
    let mut attribute_call_parameters = Vec::new();
    attribute_definition_parameters.push(quote::quote! {
        dn: ldap_types::basic::DistinguishedName
    });
    attribute_call_parameters.push(quote::quote! {
        dn
    });
    for elem in &attributes.elems {
        let span = elem.span();
        let syn::Expr::Lit(syn::ExprLit {
            attrs: _,
            lit: syn::Lit::Str(attribute_specifier),
        }) = elem
        else {
            return quote::quote! { compile_error!("Expected attribute specifier to be literal string") }.into();
        };
        let Ok(attribute_cast): Result<syn::ExprCast, syn::Error> =
            syn::parse_str(&attribute_specifier.value())
        else {
            return quote::quote! { compile_error!("Expected attribute specifier to be cast expression") }.into();
        };
        let syn::Expr::Path(syn::ExprPath {
            attrs: _,
            qself: _,
            path:
                syn::Path {
                    leading_colon: None,
                    segments,
                },
        }) = *attribute_cast.expr
        else {
            return quote::quote! { compile_error!("Expected attribute name to be identifier (within the literal string for the cast expression)") }.into();
        };
        if segments.len() != 1 {
            return quote::quote! { compile_error!("Expected attribute name to be identifier with a path length of 1") }.into();
        }
        let Some(attribute_name) = segments.first().map(|s| s.ident.to_string()) else {
            return quote::quote! { compile_error!("Expected attribute name to be identifier with a path length of 1") }.into();
        };
        let attribute_rust_type = *attribute_cast.ty;
        let attribute_rust_variable = syn::Ident::new(&attribute_name.to_case(Case::Snake), span);
        attribute_names.push(quote::quote! {
            #attribute_name
        });
        attribute_handlers.push(quote::quote! {
            let #attribute_rust_variable: #attribute_rust_type =
                <#attribute_rust_type as ldap_types::conversion::FromLdapType>::parse(<ldap3::SearchEntry as ldap_types::conversion::SearchEntryExt>::attribute_results(&entry, #attribute_name))?;
        });
        attribute_definition_parameters.push(quote::quote! {
            #attribute_rust_variable: #attribute_rust_type
        });
        attribute_call_parameters.push(quote::quote! {
            #attribute_rust_variable
        });
    }

    let output = quote::quote! {
        let it = ldap_utils::ldap_search(
            #ldap_client_handle,
            #base_dn,
            #scope,
            #filter,
            vec![#(#attribute_names),*],
        ).await?;

        let mut generated_ldap_search_entry_handler = async |#(#attribute_definition_parameters),*| -> #return_type #body;

        for entry in it {
            let dn : ldap_types::basic::DistinguishedName = entry.dn.clone().try_into()?;
            #(#attribute_handlers)*
            generated_ldap_search_entry_handler(#(#attribute_call_parameters),*).await?;
        }
    };

    //println!("Macro output:\n{}", output);

    proc_macro::TokenStream::from(output)
}
