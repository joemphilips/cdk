use cdk::nuts::nut_ctf::GetConditionsRequest;
use cdk::Error;

/// Axum's standard query decoder cannot decode a repeatable status field.
pub(crate) fn conditions_query(query: Option<&str>) -> Result<GetConditionsRequest, Error> {
    let mut params = GetConditionsRequest::default();
    let invalid = || Error::Custom("Invalid conditions query".to_string());
    for (name, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match name.as_ref() {
            "since" if params.since.is_none() => {
                params.since = Some(value.parse().map_err(|_| invalid())?)
            }
            "limit" if params.limit.is_none() => {
                params.limit = Some(value.parse().map_err(|_| invalid())?)
            }
            "cursor" if params.cursor.is_none() => params.cursor = Some(value.to_string()),
            "status" => params.status.push(value.to_string()),
            "since" | "limit" | "cursor" => return Err(invalid()),
            _ => {}
        }
    }
    Ok(params)
}
