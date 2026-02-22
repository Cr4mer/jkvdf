# Firebase Deployment Guide

## Prerequisites

1. **Install Firebase CLI** (if not already installed):
   ```bash
   npm install -g firebase-tools
   ```

2. **Login to Firebase**:
   ```bash
   npm run firebase:login
   ```
   Or using npx:
   ```bash
   npx firebase login
   ```

## Environment Setup

Create a `.env` file in the root directory with your Firebase configuration:

```env
# Firebase Configuration
# Get these values from your Firebase Console: https://console.firebase.google.com/

VITE_FIREBASE_API_KEY=your_api_key_here
VITE_FIREBASE_AUTH_DOMAIN=your_project_id.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=your_project_id
VITE_FIREBASE_STORAGE_BUCKET=your_project_id.appspot.com
VITE_FIREBASE_MESSAGING_SENDER_ID=your_messaging_sender_id
VITE_FIREBASE_APP_ID=your_app_id

# Optional: FACEIT API key for Rooster stats. If the faceitProxy Cloud Function is
# unavailable (e.g. CORS or not deployed), the app will use this key from the client.
# Set when building so the hosted app can load FACEIT data: VITE_FACEIT_API_KEY=your_key

# Cloud Functions (faceitProxy, leetifyProxy) read API keys from functions/.env.
# Copy functions/.env.example to functions/.env and set:
#   LEETIFY_API_KEY=  (from https://leetify.com/app/developer)
#   FACEIT_API_KEY=   (from https://developers.faceit.com/)
# Premier stats need Leetify; FACEIT stats need FACEIT. Blaze plan required to deploy functions.
```

## Deployment Steps

### 1. Initialize Firebase (if not already done)
```bash
npm run firebase:init
```
Or:
```bash
npx firebase init
```

Select:
- **Hosting**: Configure files for Firebase Hosting
- **Firestore**: Deploy Firestore rules and indexes
- Choose your existing Firebase project

### 2. Build your project
```bash
npm run build
```

### 3. Deploy to Firebase

**Deploy everything (hosting + firestore rules):**
```bash
npm run deploy
```

**Deploy only hosting:**
```bash
npm run deploy:hosting
```

**Deploy only Firestore rules:**
```bash
firebase deploy --only firestore:rules
```

### 4. Manual deployment (alternative)

If you need more control:
```bash
# Build the project
npm run build

# Deploy to Firebase
firebase deploy
```

## Firebase Configuration

The project is already configured:
- **Hosting directory**: `dist` (build output from Vite)
- **Firestore rules**: `firebase.firestore.rules`
- **SPA routing**: Configured to redirect all routes to `index.html`

## Troubleshooting

### Build fails
- Check your environment variables are set correctly
- Run `npm install` to ensure all dependencies are installed

### Firebase not initialized
- Run `firebase login` first
- Then run `firebase init`

### Environment variables not working
- Make sure your `.env` file is in the root directory
- Restart your dev server after creating/updating `.env`

## Security Setup

### Setting Up Admin Steam IDs in Firestore

The application uses Firestore security rules that check for admin Steam IDs in the `/admins` collection. You need to set this up once:

1. **Open Firebase Console**: Go to https://console.firebase.google.com/
2. **Navigate to Firestore Database**
3. **Create the `admins` collection** (if it doesn't exist)
4. **Add documents** with document IDs matching your admin Steam IDs (uppercase):
   - Document ID: `STEAM_0:1:125547` (or your admin's Steam ID)
   - Fields: `steamId` (string): `STEAM_0:1:125547`, `addedAt` (timestamp): current time

**Example Admin Documents:**
```
Collection: admins
├── STEAM_0:1:125547
│   ├── steamId: "STEAM_0:1:125547"
│   └── addedAt: [timestamp]
├── STEAM_0:0:43407091
│   ├── steamId: "STEAM_0:0:43407091"
│   └── addedAt: [timestamp]
└── ...
```

**Important**: 
- Document IDs must be the Steam ID in UPPERCASE format
- Only admins listed in this collection can write to maps/nades
- Anyone can read maps/nades (public content)
- Training sessions remain publicly accessible

### Firebase Functions (FACEIT proxy and training session delete)

1. **Install and build functions** (first time or after adding dependencies):
   ```bash
   cd functions && npm install && npm run build && cd ..
   ```

2. **Set FACEIT API key** (required for Rooster / FACEIT stats):
   ```bash
   firebase functions:config:set faceit.api_key="YOUR_FACEIT_API_KEY"
   ```
   Or set the secret in Firebase Console (Secret Manager) as `FACEIT_API_KEY` and reference it in your function code.

3. **Deploy functions**:
   ```bash
   firebase deploy --only functions
   ```

4. **Deployed callables**:
   - `faceitProxy`: proxies FACEIT API requests (key stays on server).
   - `leetifyProxy`: proxies Leetify API for Premier (CS2) stats (key stays on server).
   - `deleteTrainingSession`: deletes a training session (creator or admin only).

### Premier stats (Leetify)

To make **Premier stats** work on the Performance Center page:

1. **Get a Leetify API key**
   - Go to https://leetify.com/app/developer
   - Sign in or create an account, then create/copy an API key.

2. **Put the key in `functions/.env`**
   - Open `functions/.env` (create from `functions/.env.example` if needed).
   - Set:
     ```env
     LEETIFY_API_KEY=your_leetify_api_key_here
     ```
   - Save the file. Do not commit `.env`.

3. **Deploy the Leetify function** (PowerShell use `;` instead of `&&`):
   ```bash
   cd functions
   npm run build
   firebase deploy --only functions:leetifyProxy
   ```
   Or from project root:
   ```bash
   cd functions; npm run build; firebase deploy --only functions:leetifyProxy
   ```

4. **In the app**
   - Open the Performance Center (Rooster) page and switch to the **Premier stats** tab.
   - Click **Refresh Premier stats**. If the key is missing you’ll see an error; once set and deployed, stats load for players who are on Leetify (signed up at leetify.com and Steam linked).

**Note:** The Leetify API only returns data for users who have registered at leetify.com and linked their Steam account. Players who haven’t will show “No Leetify data” until they do.

### Security Features Implemented

1. **Firestore Security Rules**: 
   - Validates data structure on all writes
   - Checks admin Steam IDs from `/admins` collection
   - Prevents unauthorized writes to maps/nades

2. **Security Headers**: 
   - X-Content-Type-Options: nosniff
   - X-Frame-Options: DENY
   - X-XSS-Protection: 1; mode=block
   - Referrer-Policy: strict-origin-when-cross-origin
   - Strict-Transport-Security: max-age=31536000

3. **Input Validation**: 
   - Client-side validation in admin forms
   - Server-side validation via Firestore rules
   - Sanitized error messages (no API keys exposed)

### Migration: Legacy maps/nades and delete

Firestore rules allow **delete** on a map or nade only when the document contains an `_adminSteamId` field that exists in the `admins` collection. Documents created before this security change do not have `_adminSteamId`, so delete from the app will be denied for those documents.

**To fix legacy documents so delete works:**

1. **Option A – Firebase Console (small number of docs)**  
   - Open Firestore Database in Firebase Console.  
   - For each existing document in `maps` (and each document in `maps/{mapId}/nades`):  
     - Open the document.  
     - Add a field: name `_adminSteamId`, type **string**, value one of your admin Steam IDs in uppercase (e.g. `STEAM_0:1:125547`).  
     - Save.  
   - After this, admins can delete those maps/nades from the app.

2. **Option B – One-time script (many documents)**  
   - Use the Firebase Admin SDK in a one-off script (Node.js or similar).  
   - List all documents in `maps` and in each `maps/{mapId}/nades` subcollection.  
   - For each document that does not have `_adminSteamId`, run an update that sets `_adminSteamId` to a chosen admin Steam ID (e.g. `STEAM_0:1:125547`).  
   - Run the script once with a service account that has write access to Firestore.  
   - No rule change is required; once `_adminSteamId` is set, the existing delete rule applies.

New maps/nades created or updated through the app already include `_adminSteamId`, so their delete will work without migration.

## Advanced Deployment

### Deploy to a specific project
```bash
firebase deploy --project your-project-id
```

### Preview before deploying
```bash
firebase hosting:channel:deploy preview
```

### Rollback to a previous version
```bash
firebase hosting:rollback
```

















