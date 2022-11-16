#[macro_use] extern crate rocket;
use rocket_dyn_templates::{Template, context};
use rocket::{form::Form, http::{Cookie, CookieJar}, response::Redirect};
use argon2::{password_hash::PasswordHasher,Argon2};
use rocket_db_pools::{sqlx::{self,Row}, Database, Connection};

#[derive(FromForm, Debug)]
struct User<'r> {
    name: &'r str,
    password: &'r str,
}

// Database of Valid Usernames and Passwords
#[derive(Database)]
#[database("Users")]
struct Users(sqlx::SqlitePool);


#[get("/")]
fn index() -> Template {
    Template::render("index",context! {})
}

#[post("/login", data = "<user>")]
async fn userlogon(db: Connection<Users>, cookies: &CookieJar<'_>, user: Form<User<'_>>) -> Redirect{
    let authok: bool;
    match hash_password(user.password.to_string()){ // argon 2 salt and hash
        Ok(hash) => {
            // retrieve the user record from sqlite
            match get_password(db, user.name).await{ 
                // authok is true if the known hash and entered password's hash match
                Some(tmp) => authok = hash == tmp, 
                None => authok = false,
            }
            },
        // If the user input fails automatic sanitization, send them back to login
        Err(_) => return Redirect::to(uri!(index())), 
    }
    if authok{
        println!("authentication OK");
        // get next auth number in sequence
        // give client encrypted cookie with name as payload
        cookies.add_private(Cookie::new("authtoken", String::from(user.name))); 

        return Redirect::to(uri!(home()));
    }
    // redirect unauthorized user back to login
    Redirect::to(uri!(index()))
}

#[get("/home")]
fn home(db: Connection<Users>, cookies: &CookieJar<'_>) -> Template {
    let mut name = String::from("UNKNOWN");
    match cookies.get_private("authtoken"){
        Some(crumb) => {
            name = crumb.value().to_string();
        }
        None => return Template::render("auth",context!{authok: false}),
    }
    Template::render("home",context! {name})
}

#[catch(422)]
fn invalid() -> Template {
    Template::render("invalid",context! {})
}


#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index, userlogon, home])
    .register("/", catchers![invalid])
    .attach(Template::fairing()).attach(Users::init())
}


fn hash_password(password: String) -> Result<String, argon2::password_hash::Error> {
    let salt = "mDUIuDJzLud1affbdtGjWw"; //predetermined salt
    let argon2 = Argon2::default();
    Ok(argon2.hash_password(password.as_bytes(), &salt)?.to_string())
}
// is this vulnerable to SQL injection? possibly. It's out of scope of this assignment and I'm not testing it
async fn get_password(mut db: Connection<Users>, name: &str) -> Option<String> {
    match sqlx::query("SELECT password FROM Usersrs WHERE name = ?").bind(name).fetch_one(&mut *db).await{
        Ok(entry) => {
            Some(entry.get(0))},
        Err(_) => return None

    }
}
