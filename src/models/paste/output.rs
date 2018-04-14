use super::{Paste, Content};

use base64;

use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct Output {
  #[serde(flatten)]
  pub paste: Paste,
  pub files: Vec<OutputFile>,
}

#[derive(Debug, Serialize)]
pub struct OutputFile {
  id: String,
  name: Option<String>,
  // ideally we'd just do Option<Content>, then flatten it and skip serialization if none
  // but you can't do that yet with serde
  #[serde(skip_serializing_if = "Option::is_none")]
  format: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  content: Option<String>,
}

impl OutputFile {
  pub fn new<S: Into<String>>(id: &Uuid, name: Option<S>, content: Option<Content>) -> Self {
    let (format, content) = match content {
      Some(Content::Text(t)) => (Some("text".into()), Some(t)),
      Some(Content::Base64(b)) => (Some("base64".into()), Some(base64::encode(&b))),
      None => (None, None),
      _ => panic!(),
    };
    OutputFile {
      id: id.simple().to_string(),
      name: name.map(Into::into),
      format,
      content,
    }
  }
}