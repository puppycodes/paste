
use database::DbConn;
use database::models::pastes::Paste as DbPaste;
use database::models::users::User;
use database::schema::users;
use errors::*;
use models::id::PasteId;
use routes::web::{Rst, OptionalWebUser, Session};

use chrono::Duration;

use cookie::{Cookie, SameSite};

use diesel::prelude::*;

use rocket::http::{Cookies, Status as HttpStatus};
use rocket::request::Form;
use rocket::response::Redirect;

#[post("/p/<username>/<id>/password", format = "application/x-www-form-urlencoded", data = "<pass>")]
fn post(pass: Form<PastePassword>, username: String, id: PasteId, user: OptionalWebUser, mut sess: Session, conn: DbConn, mut cookies: Cookies) -> Result<Rst> {
  let pass = pass.into_inner();

  let paste: DbPaste = match id.get(&conn)? {
    Some(p) => p,
    None => return Ok(Rst::Status(HttpStatus::NotFound)),
  };

  let expected_username: String = match paste.author_id() {
    Some(author) => {
      let user: User = users::table.find(author).first(&*conn)?;
      user.username().to_string()
    },
    None => "anonymous".into(),
  };

  if username != expected_username {
    return Ok(Rst::Status(HttpStatus::NotFound));
  }

  if let Some((status, _)) = paste.check_access(user.as_ref().map(|x| x.id())) {
    return Ok(Rst::Status(status));
  }

  let redir_path = format!("/p/{}/{}", expected_username, id.simple());

  if paste.password().is_none() {
    sess.add_data("error", "This paste is not encrypted.");
    return Ok(Rst::Redirect(Redirect::to(&redir_path)));
  };

  if !paste.check_password(&pass.password) {
    sess.add_data("error", "Incorrect password.");
    return Ok(Rst::Redirect(Redirect::to(&redir_path)));
  }

  let cookie = Cookie::build("password", pass.password)
    .secure(true)
    .http_only(true)
    .same_site(SameSite::Strict)
    .max_age(Duration::minutes(15))
    .path(redir_path.clone())
    .finish();
  cookies.add_private(cookie);

  Ok(Rst::Redirect(Redirect::to(&redir_path)))
}

#[derive(FromForm)]
struct PastePassword {
  password: String,
}
