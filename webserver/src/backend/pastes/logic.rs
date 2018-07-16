use database::DbConn;
use database::models::deletion_keys::NewDeletionKey;
use database::models::pastes::{Paste, NewPaste};
use database::schema::{deletion_keys, pastes};
use models::paste::Visibility;
use sidekiq_::Job;
use store::Store;
use super::models::{PastePayload, CreateSuccess, CreateError};
use utils::HashedPassword;

use chrono::Utc;

use diesel;
use diesel::prelude::*;

use sidekiq::{Client as SidekiqClient, Value};

use unicode_segmentation::UnicodeSegmentation;

use std::borrow::Cow;

impl<'a> PastePayload<'a> {
  fn check(&self) -> Result<(), CreateError> {
    const MAX_SIZE: usize = 25 * 1024;

    if self.author.is_none() && self.visibility == Visibility::Private {
      return Err(CreateError::AnonymousPrivate);
    }

    if self.files.is_empty() {
      return Err(CreateError::NoFiles);
    }

    if let Some(expiration_date) = self.expires {
      if expiration_date < Utc::now() {
        return Err(CreateError::PastExpirationDate);
      }
    }

    if self.files.len() > 1 {
      let mut names: Vec<Cow<str>> = self.files.iter()
        .enumerate()
        .map(|(i, x)| match x.name {
          None => Cow::Owned(format!("pastefile{}", i + 1)),
          Some(ref n) => Cow::Borrowed(n.as_str()),
        })
        .collect();
      let len = names.len();
      names.sort();
      names.dedup();
      if len != names.len() {
        return Err(CreateError::DuplicateFileNames);
      }
    }

    if let Some(ref name) = self.name {
      if name.len() > MAX_SIZE {
        return Err(CreateError::PasteNameTooLarge);
      }

      if name.graphemes(true).count() > 255 {
        return Err(CreateError::PasteNameTooLong);
      }
    }

    if let Some(ref description) = self.description {
      if description.len() > MAX_SIZE {
        return Err(CreateError::PasteDescriptionTooLarge);
      }

      if description.graphemes(true).count() > 255 {
        return Err(CreateError::PasteDescriptionTooLong);
      }
    }

    if let Some(ref password) = self.password {
      if password.is_empty() {
        return Err(CreateError::EmptyPassword);
      }
    }

    if self.files.iter().any(|x| x.content.is_empty()) {
      return Err(CreateError::EmptyFile);
    }

    if self.files.iter().filter_map(|x| x.name.as_ref()).any(|x| x.len() > MAX_SIZE) {
      return Err(CreateError::FileNameTooLarge);
    }

    if self.files.iter().filter_map(|x| x.name.as_ref()).any(|x| x.graphemes(true).count() > 255) {
      return Err(CreateError::FileNameTooLong);
    }

    Ok(())
  }

  pub fn create(self, conn: &DbConn, sidekiq: &SidekiqClient) -> Result<CreateSuccess, CreateError> {
    self.check()?;

    let id = Store::new_paste(self.author.map(|x| x.id()))
      .map_err(|e| CreateError::Internal(e.into()))?;

    let np = NewPaste::new(
      id,
      self.name,
      self.description,
      self.visibility,
      self.author.map(|x| x.id()),
      None,
      self.expires.map(|x| x.naive_utc()),
      self.password.as_ref().map(|x| HashedPassword::from(x).into_string()),
    );

    let paste: Paste = diesel::insert_into(pastes::table)
      .values(&np)
      .get_result(&**conn)
      .map_err(|e| CreateError::Internal(e.into()))?;

    let deletion_key = match self.author {
      Some(_) => None,
      None => {
        let ndk = NewDeletionKey::generate(id);
        let key = diesel::insert_into(deletion_keys::table)
          .values(&ndk)
          .get_result(&**conn)
          .map_err(|e| CreateError::Internal(e.into()))?;
        Some(key)
      }
    };

    let mut files = Vec::with_capacity(self.files.len());
    for file in self.files {
      let f = paste.create_file(conn, file.name, file.highlight_language, self.password.as_ref(), file.content)
        .map_err(|e| CreateError::Internal(e.into()))?;
      files.push(f);
    }

    if let Some(expiration_date) = self.expires {
      let timestamp = expiration_date.timestamp();

      let user = match self.author {
        Some(a) => a.id().simple().to_string(),
        None => "anonymous".to_string(),
      };

      let job = Job::queue("ExpirePaste", timestamp, vec![
        Value::Number(timestamp.into()),
        Value::String(Store::directory().to_string_lossy().to_string()),
        Value::String(user),
        Value::String(id.simple().to_string()),
      ]);
      sidekiq.push(job.into()).map_err(|e| CreateError::Internal(e.into()))?;
    }

    Ok(CreateSuccess {
      paste,
      files,
      deletion_key,
    })
  }
}
