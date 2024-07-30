# How to roll your own auth

This repo is my implementation of the rust version of Ben Awad's [how to roll your own auth](https://www.youtube.com/watch?v=CcrgG5MjGOk).

You can check out Ben Awad's TypeScript verision [here](https://github.com/benawad/how-to-roll-your-own-auth/blob/main/README.md?plain=1).

## Project Structure

The project is organized into the following modules:

- `errors`: Handles error types and error handling for the application.
- `routes`: Contains the route handlers for the API endpoints, including:
  - `auth`:
    - `logout`: Handles user logout functionality.
    - `oauth`: Manages OAuth-related operations with Discord.
    - `refresh_token`: Handles token refresh operations.
  - `protected`: Manages protected routes that require authentication.
  - `view`: Provides HTML views for the application.
- `startup`: Manages the application startup and configuration.

## Features

- OAuth integration with Discord
- JWT-based authentication with separate access and refresh tokens
- Protected routes requiring authentication
- Token refresh functionality
- Logout mechanism
- PostgreSQL database integration using SQLx
- Secrets management using [Shuttle's SecretStore](https://docs.shuttle.rs/resources/shuttle-secrets)
- HTML views for sign-in and protected content

## Prerequisites

- Rust toolchain
- Docker (for running PostgreSQL via Shuttle)
- [Shuttle CLI](https://docs.shuttle.rs/getting-started/shuttle-commands)

## Configuration

The application requires the following secrets to be set in `Secrets.toml`, check `example.Secrets.toml`:

- `ACCESS_TOKEN_SECRET`: Secret for signing JWT access tokens
- `REFRESH_TOKEN_SECRET`: Secret for signing JWT refresh tokens
- `DISCORD_OAUTH_CLIENT_ID`: Discord OAuth client ID
- `DISCORD_OAUTH_CLIENT_SECRET`: Discord OAuth client secret
- `COOKIE_KEY`: A key that will be used to to sign cookies

`COOKIE_KEY` should be a cryptographically random key >= 64 bytes
You can generate one using rust like this and pass it as a string in Secrets.toml e.g
```toml
# secrets.toml
COOKIE_KEY="[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63]"
```

```rs
fn main() {
    let key: &Vec<u8> = &(0..64).collect();
    println!("{:?}", key);
}
```
Check [axum-extra docs](https://docs.rs/axum-extra/latest/axum_extra/extract/cookie/struct.Key.html) for more information about the `Key`

## Running the Application

1. Ensure you have the [Shuttle CLI](https://docs.shuttle.rs/getting-started/shuttle-commands) installed.
2. Set the required secrets in the `Secrets.toml`.
3. Run the application using the Shuttle CLI:

```sh
cargo shuttle run
```
This command will create a PostgreSQL database for you automatically. Make sure you have docker running before running it.

## API Endpoints

- `/api/auth/discord/authorize`: Initiates the Discord OAuth flow
- `/api/auth/discord/callback`: Handles the OAuth callback from Discord
- `/api/auth/logout`: Logs out the user
- `/api/auth/refresh`: Refreshes the access token
- `/protected`: A protected route that requires authentication and returns user information

## Views

- `/`: Landing page with a sign-in link
- `/home`: Protected home page displaying user information

