# Faceit API Setup Guide

This guide will help you set up the Faceit API to display real player statistics on the Rooster page.

## Step 1: Get a Faceit API Key

1. Go to [Faceit Developers](https://www.faceit.com/en/developers) and sign in with your Faceit account.
2. Navigate to your [Applications](https://developers.faceit.com/applications)
3. Click "Create New Application"
4. **Important**: Select **"Client-side"** as your application type since this is a frontend JavaScript application
5. Fill in the application details:
   - **Name**: Your app name (e.g., "JKVDF Stats")
   - **Description**: Brief description of your application
   - **Website URL**: Your application URL (can be `http://localhost:5173` during development)
   - **Redirect URL**: Your OAuth redirect URL (not needed for stats, use your website URL)
   - **Client Type**: Make sure **"Web App"** or **"Client-side"** is selected
6. Click "Create Application"
7. Copy the **API Key** from your application dashboard

### Security Note for Client-side API Keys

Since this is a client-side application, the API key will be visible in the browser. To protect it:

1. **Set up domain restrictions** in Faceit App Studio:
   - Go to your application settings
   - Add your production domain to the allowed domains list
   - Add `localhost` for local development

2. **Optional**: Consider using a proxy server for production to keep the API key secure

## Step 2: Configure Your Environment Variable

1. Locate the `.env` file in the root of your project
2. Find the line: `VITE_FACEIT_API_KEY=your_faceit_api_key_here`
3. Replace `your_faceit_api_key_here` with your actual API key from Step 1
4. Save the file

Example:
```
VITE_FACEIT_API_KEY=abc123xyz789_YourActualKeyHere
```

## Step 3: Restart Your Development Server

After updating the `.env` file, you need to restart your development server for the changes to take effect:

1. Stop your current dev server (Ctrl+C in the terminal)
2. Start it again with `npm run dev`

## Step 4: Verify the Setup

1. Navigate to the Rooster page in your application
2. Check the browser console for any API errors
3. The page should display real stats instead of mock data
4. If you see the info box at the bottom, you're still using mock data

## Troubleshooting

### API Key Not Working
- Make sure there are no extra spaces in your `.env` file
- Verify the API key is correct in your Faceit dashboard
- Check the browser console for specific error messages

### Still Showing Mock Data
- Restart your dev server after updating `.env`
- Clear your browser cache and reload
- Check that the `.env` file is in the root directory (same folder as `package.json`)

### Rate Limiting
Faceit API has rate limits. If you exceed them:
- Wait a few minutes before trying again
- Consider implementing caching for API responses

## API Features

The current implementation fetches detailed statistics from the Faceit API:

### Real Statistics (from last 20 matches):
- ✅ **Win Rate** - Actual win rate from recent matches
- ✅ **K/D Ratio** - Calculated from match data
- ✅ **Average Kills** - Real kills per match
- ✅ **Average Deaths** - Real deaths per match  
- ✅ **Average Assists** - Real assists per match
- ✅ **Headshot Rate** - From lifetime stats

### Calculated Metrics:
- ✅ **RWS (Round Win Share)** - Approximation based on win rate and K/D
- ✅ **Impact** - Calculated from kills, assists, and win rate

**Note**: These metrics are calculated approximations. True RWS and Impact require round-by-round data that would need premium API access or extensive data processing.

## Security Notes

### Environment Variables

⚠️ **Never commit your `.env` file to version control!**

The `.env` file is already included in `.gitignore` to prevent accidental commits of your API keys.

### Client-side API Key Security

Since you're using a **client-side API key**, it will be visible in the browser. Here are important security measures:

1. **Domain Restrictions** (Required)
   - Go to your Faceit application settings in App Studio
   - Set up domain allowlist restrictions
   - Add your production domain (e.g., `yourdomain.com`)
   - Add `localhost` for development

2. **Rate Limiting**
   - The Faceit API has built-in rate limits
   - Monitor your usage in the Faceit dashboard
   - Implement caching to reduce API calls

3. **Production Considerations**
   - The API key is embedded in your JavaScript bundle
   - Anyone can view it in the browser's developer tools
   - This is acceptable for public data like player statistics
   - For sensitive operations, consider using a backend proxy

4. **What NOT to do**
   - Don't use server-side API keys in client-side code
   - Don't try to "hide" the key using obfuscation (it doesn't work)
   - Don't make the key publicly available without domain restrictions

## Support

For more information about the Faceit API:
- [Faceit API Documentation](https://developers.faceit.com/)
- [Faceit API Reference](https://open.faceit.com/data/v4)
