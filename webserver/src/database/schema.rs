table! {
    api_keys (key) {
        key -> Uuid,
        user_id -> Uuid,
        name -> Text,
    }
}

table! {
    deletion_keys (key) {
        key -> Uuid,
        paste_id -> Uuid,
    }
}

table! {
    email_verifications (id) {
        id -> Uuid,
        email -> Text,
        user_id -> Uuid,
        key -> Text,
        last_sent -> Nullable<Timestamp>,
        expiry -> Timestamp,
    }
}

table! {
    files (id) {
        id -> Uuid,
        paste_id -> Uuid,
        name -> Text,
        is_binary -> Nullable<Bool>,
        created_at -> Timestamp,
        highlight_language -> Nullable<Text>,
    }
}

table! {
    login_attempts (addr) {
        addr -> Cidr,
        timestamp -> Timestamp,
        attempts -> Int4,
    }
}

table! {
    password_reset_attempts (addr) {
        addr -> Cidr,
        timestamp -> Timestamp,
        attempts -> Int4,
    }
}

table! {
    password_resets (id) {
        id -> Uuid,
        secret -> Text,
        expiry -> Timestamp,
        user_id -> Uuid,
    }
}

table! {
    pastes (id) {
        id -> Uuid,
        name -> Nullable<Text>,
        visibility -> Int2,
        author_id -> Nullable<Uuid>,
        description -> Nullable<Text>,
        created_at -> Timestamp,
        expires -> Nullable<Timestamp>,
        password -> Nullable<Text>,
    }
}

table! {
    users (id) {
        id -> Uuid,
        username -> Text,
        password -> Text,
        name -> Text,
        email -> Text,
        email_verified -> Bool,
    }
}

joinable!(api_keys -> users (user_id));
joinable!(deletion_keys -> pastes (paste_id));
joinable!(email_verifications -> users (user_id));
joinable!(files -> pastes (paste_id));
joinable!(password_resets -> users (user_id));
joinable!(pastes -> users (author_id));

allow_tables_to_appear_in_same_query!(
    api_keys,
    deletion_keys,
    email_verifications,
    files,
    login_attempts,
    password_reset_attempts,
    password_resets,
    pastes,
    users,
);
