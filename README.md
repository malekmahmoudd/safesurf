# SafeSurf

SafeSurf checks a website URL with VirusTotal before sending a question about it to Groq through a LangGraph workflow.

## Run locally

1. Create a `.env` file from `.env.example` and add your VirusTotal and Groq API keys.
2. Install dependencies: `pip install -r requirements.txt`
3. Start the product: `uvicorn src.main:app --reload`
4. Open `http://127.0.0.1:8000`

## Deploy

The included `Dockerfile` runs the product on any container host. Configure these environment variables in the host's secret manager—never commit them:

- `VIRUSTOTAL_API_KEY`
- `GROQ_API_KEY`

The chat interface can be deployed separately to Vercel. It stays intentionally free of API keys and needs the API service available at the same `/api/check` route or through a production proxy.

## Safety flow

`START → VirusTotal safety check → Groq response | fallback → END`

The workflow fails closed: invalid URLs, missing configuration, unavailable reputation checks, and reported malicious or suspicious detections never reach the LLM. It uses VirusTotal's existing URL report lookup rather than waiting for an asynchronous scan. A clean result is not a guarantee that a website is safe.
