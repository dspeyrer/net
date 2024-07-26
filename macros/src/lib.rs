use proc_macro2::{Ident, Spacing, Span, TokenStream, TokenTree};
use quote::quote;
use syn::punctuated::Punctuated;
use syn::token::Plus;
use syn::{
	parse_macro_input, Data, DataEnum, DataUnion, DeriveInput, Error, Meta, MetaList, Path, PathSegment, PredicateType, TraitBound, TypeParamBound,
};

fn trait_bound(path: &[&str]) -> TypeParamBound {
	let mut bound = TraitBound {
		lifetimes: None,
		paren_token: None,
		modifier: syn::TraitBoundModifier::None,
		path: Path {
			leading_colon: Some(Default::default()),
			segments: Punctuated::new(),
		},
	};

	for ident in path {
		bound.path.segments.push(PathSegment {
			ident: Ident::new(ident, Span::call_site()),
			arguments: syn::PathArguments::None,
		})
	}

	bound.into()
}

#[proc_macro_derive(Cast)]
pub fn bytes(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
	let DeriveInput { attrs, ident: name, mut generics, data, .. } = parse_macro_input!(item as DeriveInput);

	// Whether either "C" or "transparent" have been seen
	let mut base = false;
	// One of "C", "packed", or "transparent"
	let mut repr = "C";

	for attr in attrs {
		if let Meta::List(MetaList { path, tokens, .. }) = attr.meta {
			if path.is_ident("repr") {
				let mut last_was_delim = true;

				for token in tokens.into_iter() {
					match token {
						TokenTree::Punct(punct) if !last_was_delim && punct.as_char() == ',' && punct.spacing() == Spacing::Alone => {
							last_was_delim = true;
							continue;
						}
						TokenTree::Ident(ident) if last_was_delim && ident == "C" => base = true,
						TokenTree::Ident(ident) if last_was_delim && ident == "transparent" => {
							base = true;
							repr = "transparent";
						}
						TokenTree::Ident(ident) if last_was_delim && ident == "packed" => repr = "packed",
						_ => return Error::new(token.span(), "Unexpected token").to_compile_error().into(),
					}

					last_was_delim = false;
				}
			}
		}
	}

	if !base {
		return Error::new(Span::call_site(), "Struct needs explicit repr(C) or repr(transparent)")
			.to_compile_error()
			.into();
	};

	/*

	repr        generics | needs_size_check needs_unaligned unconditional_unaligned
	C           0        | 1                0               1
	C           1        | 0                1               1
	C, packed   0        | 0                0               0
	C, packed   1        | 0                1               0
	transparent 0        | 0                0               1
	transparent 1        | 0                0               1

	 */

	let has_generics = !generics.params.is_empty();

	// Whether Cast needs a size check.
	let needs_size_check = !has_generics && repr == "C";
	// Whether Cast needs Unaligned.
	let needs_unaligned = has_generics && repr != "packed";
	// Whether Unaligned needs all of its fields to implement Unaligned.
	let unconditional_unaligned = repr == "packed";

	let mut cast_predicates = generics.where_clause.take().map(|x| x.predicates).unwrap_or_default();
	let mut unaligned_predicates = cast_predicates.clone();

	let (impl_generics, ty_generics, _) = generics.split_for_impl();

	let mut fields_size = Punctuated::<TokenStream, Plus>::new();

	match data {
		Data::Struct(obj) => {
			for field in obj.fields.into_iter() {
				let ty = field.ty;

				let mut cast_predicate = PredicateType {
					bounded_ty: ty.clone(),
					lifetimes: None,
					colon_token: Default::default(),
					bounds: Punctuated::new(),
				};

				// Cast may need to verify that the structure has no padding.
				if needs_size_check {
					fields_size.push(quote! { ::core::mem::size_of::<#ty>() });
				}

				// Unaligned may require all of the fields to be unaligned.
				if !unconditional_unaligned {
					let mut unaligned_predicate = cast_predicate.clone();
					unaligned_predicate.bounds.push(trait_bound(&["utils", "bytes", "Unaligned"]));
					unaligned_predicates.push(unaligned_predicate.into());
				}

				// Cast always needs all of its fields to implement Cast.
				cast_predicate.bounds.push(trait_bound(&["utils", "bytes", "Cast"]));

				cast_predicates.push(cast_predicate.into());
			}
		}
		Data::Enum(DataEnum { enum_token, .. }) => return Error::new_spanned(enum_token, "Enums are not supported.").to_compile_error().into(),
		Data::Union(DataUnion { union_token, .. }) => return Error::new_spanned(union_token, "Unions are not supported.").to_compile_error().into(),
	};

	if needs_unaligned {
		let mut cast_unaligned_req = PredicateType {
			bounded_ty: syn::Type::Verbatim(TokenTree::Ident(Ident::new("Self", Span::call_site())).into()),
			lifetimes: None,
			colon_token: Default::default(),
			bounds: Punctuated::new(),
		};

		cast_unaligned_req.bounds.push(trait_bound(&["utils", "bytes", "Unaligned"]));

		cast_predicates.push(cast_unaligned_req.into());
	}

	let no_padding = if !fields_size.is_empty() {
		quote! { ::utils::bytes::cast::V<{ #fields_size }>: ::utils::bytes::cast::Eq<{ ::std::mem::size_of::<#name #ty_generics>() }>, }
	} else {
		TokenStream::new()
	};

	quote! {
		unsafe impl #impl_generics ::utils::bytes::Cast for #name #ty_generics where
			#no_padding
			#cast_predicates
		{}

		unsafe impl #impl_generics ::utils::bytes::Unaligned for #name #ty_generics where
			#unaligned_predicates
		{}
	}
	.into()
}
