use axum::response::Html;

#[axum::debug_handler]
pub async fn home() -> Html<&'static str> {
    Html(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Protected Route</title>
    <script>
        async function fetchProtectedContent() {
            try {
                const response = await fetch('/protected', {
                    method: 'GET',
                    credentials: 'include'
                });

                if (response.status === 401) {
                    window.location.href = '/';
                    return;
                }

                const data = await response.json();
                console.log(data);
                document.getElementById('user-id').innerText = `User ID: ${data.id}`;
                document.getElementById('discord-id').innerText = `Discord ID: ${data.discord_id}`;
                document.getElementById('email').innerText = `Email: ${data.email}`;
            } catch (error) {
                console.error('Error fetching protected content:', error);
            }
        }

        document.addEventListener('DOMContentLoaded', (event) => {
            fetchProtectedContent();
        });
    </script>
</head>
<body>
    <h1>You are signed in 🥳️</h1>
    <p id="user-id"></p>
    <p id="discord-id"></p>
    <p id="email"></p>
</body>
</html>
    "#,
    )
}

#[axum::debug_handler]
pub async fn landing() -> Html<String> {
    let url = "/api/auth/discord/authorize";
    Html(format!(
        r#"
        <p>Welcome!</p>
        <a href={url}>
            Click here to sign in with discord!
        </a>
    "#
    ))
}
