# Anisakys Web Interface

Modern web interface for the Anisakys phishing detection and automated reporting engine.

## Features

- **Real-time Dashboard** - Live statistics and threat monitoring
- **URL Scanner** - Multi-API threat intelligence scanning
- **Report Management** - ICANN compliance tracking
- **Threat Analytics** - Visualizations and trend analysis
- **Configuration Panel** - System settings and API integrations

## Tech Stack

- **React 18** - Modern UI framework
- **TypeScript** - Type-safe development
- **Vite** - Fast build tool
- **Tailwind CSS** - Utility-first styling
- **React Router** - Client-side routing
- **TanStack Query** - Server state management
- **Recharts** - Data visualization
- **Lucide React** - Icon system

## Prerequisites

- Node.js 18+ or npm/yarn/pnpm
- Anisakys backend API running (default: http://localhost:8080)

## Quick Start

### 1. Install Dependencies

```bash
cd frontend
npm install
```

### 2. Configure Environment

Copy the example environment file and configure:

```bash
cp .env.example .env
```

Edit `.env` and set your API URL:

```env
VITE_API_URL=http://localhost:8080/api/v1
```

### 3. Start Development Server

```bash
npm run dev
```

The application will be available at http://localhost:3000

### 4. Login

Use your Anisakys API key to log in. The API key is configured in the backend via:
- Environment variable: `ANISAKYS_API_KEY`
- Command line: `--api-key your_key_here`

## Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint
- `npm run type-check` - Run TypeScript type checking

## Project Structure

```
frontend/
├── src/
│   ├── components/        # Reusable UI components
│   │   ├── Badge.tsx
│   │   ├── Button.tsx
│   │   ├── Card.tsx
│   │   ├── Layout.tsx
│   │   ├── Loading.tsx
│   │   ├── Modal.tsx
│   │   ├── Navbar.tsx
│   │   └── StatCard.tsx
│   ├── pages/            # Application pages
│   │   ├── Analytics.tsx
│   │   ├── Dashboard.tsx
│   │   ├── Login.tsx
│   │   ├── Reports.tsx
│   │   ├── Scanner.tsx
│   │   └── Settings.tsx
│   ├── services/         # API services
│   │   └── api.ts
│   ├── hooks/           # Custom React hooks
│   │   └── useAuth.tsx
│   ├── types/           # TypeScript types
│   │   └── index.ts
│   ├── App.tsx          # Main app component
│   ├── main.tsx         # Entry point
│   └── index.css        # Global styles
├── index.html
├── package.json
├── tsconfig.json
├── vite.config.ts
└── tailwind.config.js
```

## Features Overview

### Dashboard
- Real-time statistics (scans, threats, reports)
- Activity timeline charts
- Threat distribution visualization
- Top keywords and TLDs
- Recent activity feed

### URL Scanner
- Manual URL scanning
- Multi-API results (VirusTotal, URLVoid, PhishTank)
- Confidence scoring
- WHOIS information
- Screenshot evidence
- Actionable recommendations

### Reports
- ICANN compliance tracking
- Response deadline monitoring
- Status management (sent, acknowledged, resolved, escalated)
- Filtering and search
- Detailed report views

### Analytics
- Activity trends (configurable periods)
- Detection rate analysis
- Threat map visualization
- Performance metrics
- Geographic distribution

### Settings
- Scan configuration (keywords, domains, intervals)
- API integrations (VirusTotal, URLVoid, PhishTank, Grinder)
- SMTP configuration
- Threshold settings
- Connection testing

## API Integration

The frontend communicates with the Anisakys backend via REST API:

### Authentication
All API requests require Bearer token authentication:
```
Authorization: Bearer YOUR_API_KEY
```

### Key Endpoints

- `GET /api/v1/health` - Health check
- `GET /api/v1/stats` - System statistics
- `POST /api/v1/multi-scan` - Scan URL
- `GET /api/v1/status/:url` - Check scan status
- `GET /api/v1/sites` - List phishing sites
- `GET /api/v1/reports` - List reports
- `POST /api/v1/report` - Create report
- `GET /api/v1/analytics/chart` - Chart data
- `GET /api/v1/config` - Get configuration
- `PUT /api/v1/config` - Update configuration

## Production Build

### Build for Production

```bash
npm run build
```

This creates an optimized build in the `dist/` directory.

### Preview Production Build

```bash
npm run preview
```

### Deploy

The production build is a static site that can be deployed to:
- Nginx/Apache
- Netlify
- Vercel
- AWS S3 + CloudFront
- Any static hosting service

Example Nginx configuration:

```nginx
server {
    listen 80;
    server_name your-domain.com;
    root /path/to/frontend/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Docker Deployment

A Dockerfile for the frontend will be provided in the production build configuration.

## Development

### Adding a New Page

1. Create component in `src/pages/YourPage.tsx`
2. Export from `src/pages/index.ts`
3. Add route in `src/App.tsx`
4. Add navigation link in `src/components/Navbar.tsx`

### Adding a New API Endpoint

1. Add TypeScript types in `src/types/index.ts`
2. Add API method in `src/services/api.ts`
3. Use in component with `useQuery` or `useMutation`

### Styling

The project uses Tailwind CSS. Custom utilities are defined in:
- `tailwind.config.js` - Theme configuration
- `src/index.css` - Global styles and custom classes

## Troubleshooting

### CORS Issues

Ensure the backend has CORS enabled for your frontend URL. The backend should include:

```python
from flask_cors import CORS

CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:3000"],
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})
```

### API Connection Issues

1. Verify backend is running: `curl http://localhost:8080/api/v1/health`
2. Check API URL in `.env` file
3. Verify API key is correct
4. Check browser console for errors

### Build Issues

```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install

# Clear Vite cache
rm -rf node_modules/.vite
```

## License

Part of the Anisakys project. See main project LICENSE for details.

## Support

For issues and questions, please refer to the main Anisakys repository.
