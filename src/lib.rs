#![doc = include_str!("../README.md")]

use convert_case::{Case, Casing};
use syn::spanned::Spanned;

/// Performs an LDAP search and converts the result into suitable Rust types
#[proc_macro]
pub fn ldap_search(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let args = syn::parse_macro_input!(input with syn::punctuated::Punctuated<syn::Expr, syn::Token![,]>::parse_terminated);

    if args.len() != 5 {
        return quote::quote! { compile_error!("Expected 5 arguments (ldap client handle, base dn, scope, filter, attributes)") }.into();
    }

    let ldap_client_handle = &args[0];
    let base_dn = &args[1];
    let scope = &args[2];
    let filter = &args[3];
    let attributes = &args[4];

    let syn::Expr::Array(attributes) = attributes else {
        return quote::quote! { compile_error!("Expected fifth argument to be an array of attribute specifiers (attribute name as Rust type)") }.into();
    };

    let mut attribute_handlers = Vec::new();
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
        attribute_handlers.push(quote::quote! {
            let #attribute_rust_variable: #attribute_rust_type =
                <#attribute_rust_type as ldap_types::conversion::FromLdapType>::parse(<ldap3::SearchEntry as ldap_types::conversion::SearchEntryExt>::attribute_results(&entry, #attribute_name))?;
        });
    }

    let output = quote::quote! {
        let it = ldap_utils::ldap_search(
            #ldap_client_handle,
            #base_dn,
            #scope,
            #filter,
            vec!#attributes
        ).await?;

        for entry in it {
            #(#attribute_handlers)*
        }
    };

    println!("Macro output:\n{}", output);

    proc_macro::TokenStream::from(output)
}
