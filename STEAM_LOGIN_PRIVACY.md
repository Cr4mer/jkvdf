# Steam login – privacy and security

**Short answer:** This app only uses Steam to **identify** you (like “Sign in with Google”). We **never** see your Steam password or get any way to access your Steam account. Your account cannot be stolen by logging in here.

---

## How login works

1. You click **Admin Login with Steam**.
2. Your browser is sent to **Steam’s own website** (`steamcommunity.com`) – the same place you use for Steam.
3. You sign in there with your Steam username and password. **That happens only on Steam’s site.** Our site never sees your password.
4. After you sign in, Steam redirects you back to our app and tells us only: *“This person is Steam ID …”* (a public number, like a username).
5. We store that **Steam ID** in your browser (localStorage) so we know you’re an admin. We do **not** store any password or Steam login token.

So: we only get a **public identifier** (Steam ID). We do **not** get:

- Your Steam password  
- A token that could be used to log into Steam as you  
- The ability to change your Steam account or make purchases  

**Can your Steam account be stolen from this?** No. We never receive anything that could be used to log into Steam. The only thing we know is “this browser session belongs to the Steam account with this ID,” which is the same kind of info many sites get when you use “Sign in with Steam” or “Sign in with Google.”

---

## What we store

- **In your browser (localStorage):** your Steam ID (e.g. `STEAM_0:1:12345`). This is a public identifier; many sites show Steam IDs.
- **In Firebase:** we only use data you create in the app (e.g. training sessions, if you’re an admin). We do not store your Steam password or any Steam login credentials.

---

## How to double-check

When you click login:

1. Look at the address bar. You should be redirected to a URL that starts with **`https://steamcommunity.com`** – Steam’s official domain.
2. Only enter your Steam password on that Steam page. If our app ever asked for your Steam password directly on our own page, that would be wrong – we don’t do that and never should.

For more on Steam’s login system: [Steam Web API / OpenID](https://steamcommunity.com/dev).

---

You can share this page with anyone who is worried about using their Steam account to log in.
