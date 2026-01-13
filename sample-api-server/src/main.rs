use axum::extract::{Path, Request};
use axum::http::StatusCode;
use axum::http::header::HeaderMap;
use axum::middleware::{self, AddExtension, Next};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Extension, Json, Router};
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use futures_util::future::BoxFuture;
use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SubjectAccessReview, SubjectAccessReviewSpec,
};
use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{APIResource, APIResourceList, ListMeta};
use kube::api::{Api, PostParams};
use kube::{Client, CustomResource};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ServerConfig, WebPkiClientVerifier};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::signal::unix::{self, SignalKind};
use tokio_rustls::server::TlsStream;
use tower::Layer;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

const FQDN: &str = "sample-api-server.sample-system.svc.cluster.local";
const GROUP: &str = "sample-api-server";
const VERSION: &str = "v1alpha1";
const RESOURCE_SINGLE: &str = "sample";
const RESOURCE_PLURAL: &str = "samples";

static ALLOWED_NAMES: OnceLock<Vec<String>> = OnceLock::new();
static GROUP_HEADERS: OnceLock<Vec<String>> = OnceLock::new();
static USERNAME_HEADERS: OnceLock<Vec<String>> = OnceLock::new();

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();

    let mut sigterm = unix::signal(SignalKind::terminate())?;

    let auth = extension_apiserver_authentication().await?;

    let acceptor = TrustedAcceptor::new(RustlsAcceptor::new(config(&auth)?));

    let app = router_api()
        .layer(middleware::from_fn(authentication))
        .layer(Extension(auth));

    log::info!("Starting server.");
    let addr = SocketAddr::from_str("0.0.0.0:3000")?;
    let server = axum_server::bind(addr)
        .acceptor(acceptor)
        .serve(app.into_make_service());

    tokio::select! {
        _ = sigterm.recv() => {},
        _ = server => {},
    }

    Ok(())
}

async fn extension_apiserver_authentication() -> Result<ConfigMap, Box<dyn Error>> {
    let client = Client::try_default().await?;

    let cm: Api<ConfigMap> = Api::namespaced(client, "kube-system");
    let auth = cm.get("extension-apiserver-authentication").await?;

    Ok(auth)
}

fn router_api() -> Router {
    Router::new()
        .route(&format!("/apis/{GROUP}/{VERSION}"), get(api_resources))
        .nest(
            &format!("/apis/{GROUP}/{VERSION}/namespaces/{{namespace}}/{RESOURCE_PLURAL}"),
            router_custom_resource(),
        )
}

fn router_custom_resource() -> Router {
    Router::new()
        .route(
            "/",
            get(custom_resources).layer(middleware::from_fn(authorization_list)),
        )
        .route(
            "/{resource}",
            get(custom_resource).layer(middleware::from_fn(authorization_get)),
        )
}

fn allowed_names(auth: &ConfigMap) -> Vec<String> {
    value_from_env(auth, "requestheader-allowed-names", &ALLOWED_NAMES)
}

fn group(auth: &ConfigMap, headers: &HeaderMap) -> Option<String> {
    value_from_header(&group_headers(auth), headers)
}

fn group_headers(auth: &ConfigMap) -> Vec<String> {
    value_from_env(auth, "requestheader-group-headers", &GROUP_HEADERS)
}

fn username(auth: &ConfigMap, headers: &HeaderMap) -> Option<String> {
    value_from_header(&username_headers(auth), headers)
}

fn username_headers(auth: &ConfigMap) -> Vec<String> {
    value_from_env(auth, "requestheader-username-headers", &USERNAME_HEADERS)
}

fn value_from_env(auth: &ConfigMap, key: &str, value: &OnceLock<Vec<String>>) -> Vec<String> {
    value
        .get_or_init(|| {
            let value = match &auth.data {
                Some(v) => v.get(key).cloned().unwrap_or_default(),
                _ => "".to_string(),
            };
            log::info!("{key}: {value}");
            if value.is_empty() {
                vec![]
            } else if let Ok(json) = Json::from_bytes(value.as_bytes()) {
                json.0
            } else {
                vec![]
            }
        })
        .to_vec()
}

fn value_from_header(keys: &Vec<String>, headers: &HeaderMap) -> Option<String> {
    for key in keys {
        if let Some(value) = headers.get(key) {
            return value.to_str().map(|v| v.to_string()).ok();
        }
    }

    None
}

fn config(auth: &ConfigMap) -> Result<RustlsConfig, Box<dyn Error>> {
    let ca = auth
        .data
        .as_ref()
        .map(|v| v.get("requestheader-client-ca-file").unwrap())
        .unwrap();
    let ca_cert = CertificateDer::from_pem_slice(ca.as_bytes()).unwrap();

    let mut cert_store = RootCertStore::empty();
    cert_store.add(ca_cert)?;

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(cert_store)).build()?;

    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(&[FQDN.to_string()])?;
    let server_cert = CertificateDer::from(cert);
    let server_key = PrivateKeyDer::try_from(signing_key.serialize_der())?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![server_cert], server_key)?;

    Ok(RustlsConfig::from_config(Arc::new(config)))
}

async fn authentication(
    Extension(client_certs): Extension<Vec<CertificateDer<'static>>>,
    Extension(auth): Extension<ConfigMap>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let client_cert = if let Some(v) = client_certs.first() {
        v
    } else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    let x509 = if let Ok((_, v)) = X509Certificate::from_der(client_cert) {
        v
    } else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    let common_name = if let Some(v) = x509.subject().iter_common_name().next() {
        v
    } else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    let cn = common_name.as_str().unwrap_or_default();
    log::trace!("Client CN={cn}");

    for name in allowed_names(&auth) {
        if name.as_str() == cn {
            return next.run(req).await;
        }
    }

    StatusCode::UNAUTHORIZED.into_response()
}

async fn authorization(
    auth: ConfigMap,
    namespace: Option<String>,
    resource: Option<String>,
    verbs: &str,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    for (key, value) in &headers {
        log::trace!(
            "HEADER {}: {}",
            key.as_str(),
            value.to_str().unwrap_or_default()
        );
    }

    let group = group(&auth, &headers);
    let username = username(&auth, &headers);

    let data = SubjectAccessReview {
        spec: SubjectAccessReviewSpec {
            groups: Some(vec![group.unwrap_or_default()]),
            resource_attributes: Some(ResourceAttributes {
                group: Some(GROUP.to_string()),
                name: Some(resource.unwrap_or_default()),
                namespace: Some(namespace.unwrap_or_default()),
                resource: Some(RESOURCE_PLURAL.to_string()),
                verb: Some(verbs.to_string()),
                version: Some(VERSION.to_string()),
                ..Default::default()
            }),
            user: Some(username.unwrap_or_default()),
            ..Default::default()
        },
        ..Default::default()
    };

    let sar: Api<SubjectAccessReview> = match Client::try_default().await {
        Ok(v) => Api::all(v),
        Err(e) => {
            log::error!("{e:?}");
            return StatusCode::FORBIDDEN.into_response();
        }
    };

    let res: SubjectAccessReview = match sar.create(&PostParams::default(), &data).await {
        Ok(v) => v,
        Err(e) => {
            log::error!("{e:?}");
            return StatusCode::FORBIDDEN.into_response();
        }
    };

    match res.status {
        Some(status) if status.allowed => next.run(req).await,
        Some(status) if status.reason.is_some() => {
            log::debug!("Permission Deny: {}", status.reason.unwrap());
            StatusCode::FORBIDDEN.into_response()
        }
        _ => {
            log::debug!("Permission Deny");
            StatusCode::FORBIDDEN.into_response()
        }
    }
}

async fn authorization_get(
    Extension(auth): Extension<ConfigMap>,
    Path((namespace, resource)): Path<(String, String)>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    authorization(
        auth,
        Some(namespace),
        Some(resource),
        "get",
        headers,
        req,
        next,
    )
    .await
}

async fn authorization_list(
    Extension(auth): Extension<ConfigMap>,
    Path(namespace): Path<String>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    authorization(auth, Some(namespace), None, "list", headers, req, next).await
}

async fn api_resources() -> impl IntoResponse {
    Json(APIResourceList {
        group_version: format!("{GROUP}/{VERSION}"),
        resources: vec![APIResource {
            group: Some(GROUP.to_string()),
            kind: "Sample".to_string(),
            name: RESOURCE_PLURAL.to_string(),
            namespaced: true,
            singular_name: RESOURCE_SINGLE.to_string(),
            verbs: vec!["get".to_string(), "list".to_string()],
            ..Default::default()
        }],
    })
}

async fn custom_resource(Path((namespace, resource)): Path<(String, String)>) -> impl IntoResponse {
    let resource = Sample::new(
        resource.as_str(),
        SampleSpec {
            name: format!("{namespace}.{resource}"),
        },
    );
    Json(resource)
}

async fn custom_resources(Path(namespace): Path<String>) -> impl IntoResponse {
    let resource = Sample::new("sample1", SampleSpec { name: namespace });
    let resources = SampleList {
        api_version: format!("{GROUP}/{VERSION}"),
        kind: "SampleList".to_string(),
        metadata: ListMeta {
            resource_version: Some("1".to_string()),
            ..Default::default()
        },
        items: vec![resource],
    };
    Json(resources)
}

// -----------------------------------------------------------------------------------------------

#[derive(Clone, CustomResource, Debug, Deserialize, JsonSchema, Serialize)]
#[kube(
    kind = "Sample",
    group = "sample-api-server",
    version = "v1alpha1",
    namespaced
)]
pub struct SampleSpec {
    name: String,
}

// -----------------------------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SampleList {
    api_version: String,
    kind: String,
    metadata: ListMeta,
    items: Vec<Sample>,
}

// -----------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct TrustedAcceptor {
    inner: RustlsAcceptor,
}

impl TrustedAcceptor {
    fn new(inner: RustlsAcceptor) -> Self {
        Self { inner }
    }
}

impl<I, S> Accept<I, S> for TrustedAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = AddExtension<S, Vec<CertificateDer<'static>>>;
    type Future = BoxFuture<'static, std::io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.clone();

        Box::pin(async move {
            let (stream, service) = acceptor.accept(stream, service).await?;
            let (_, server) = stream.get_ref();
            let certs = server
                .peer_certificates()
                .map(|v| v.to_vec())
                .unwrap_or_default();
            let service = Extension(certs).layer(service);
            Ok((stream, service))
        })
    }
}
