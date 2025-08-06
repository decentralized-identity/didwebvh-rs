/*!
*   Resolver trait methods for webvh derived from the SpruiceID SSI Library
*
*   NOTE: This is a niave implementation that will download the DID information on every resolve
*
*   If you want greater control and caching then please use the DIDWebVHState.resolve() method directly
*/

use crate::{DIDWebVHError, DIDWebVHState, log_entry::LogEntryMethods, resolve::DIDWebVH};
use ssi::dids::{
    DIDMethod, DIDMethodResolver, Document,
    document::{
        self,
        representation::{self, MediaType},
    },
    resolution::{self, Error, Options},
};
use tracing::{Instrument, Level, span};

impl DIDMethodResolver for DIDWebVH {
    /// Resolves a webvh DID using the SSI Crate Traits
    /// This is a niave imnplementation and will fully load the DID from source each resolve
    ///
    /// Does make use of Optional parameters
    /// parameters("network_timeout") (defaults to 10 seconds): Time in seconds before timing out
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: Options,
    ) -> Result<ssi::dids::resolution::Output<Vec<u8>>, Error> {
        let _span = span!(
            Level::DEBUG,
            "DIDWebVH::resolve_method_representation",
            method_specific_id = method_specific_id
        );
        async move {
            let mut state = DIDWebVHState::default();
            match state.resolve(method_specific_id, None).await {
                Ok((log_entry, _)) => {
                    let document: Document = serde_json::from_value(log_entry.get_state().clone())
                        .map_err(|e| {
                            Error::internal(format!("Failed to parse DID Document: {e}"))
                        })?;

                    let content_type = options.accept.unwrap_or(MediaType::Json);
                    let represented = document.into_representation(representation::Options::Json);

                    Ok(resolution::Output::new(
                        represented.to_bytes(),
                        document::Metadata::default(),
                        resolution::Metadata::from_content_type(Some(content_type.to_string())),
                    ))
                }
                Err(DIDWebVHError::NotFound) => Err(Error::NotFound),
                Err(e) => Err(Error::Internal(e.to_string())),
            }
        }
        .instrument(_span)
        .await
    }
}

impl DIDMethod for DIDWebVH {
    const DID_METHOD_NAME: &'static str = "webvh";
}
