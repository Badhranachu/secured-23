# Local Setup

1. Install local services: MySQL, Redis, and Ollama.
2. Create MySQL database `aegis_ai`.
3. Backend:
   - `cd backend`
   - `Copy-Item .env.example .env`
   - `pip install -r requirements.txt`
   - `python manage.py migrate`
   - `python manage.py seed_demo`
   - `python manage.py runserver 127.0.0.1:8000`
4. Celery on Windows:
   - `celery -A config worker -l info --pool=solo`
   - `celery -A config beat -l info`
5. Frontend:
   - `cd frontend`
   - `Copy-Item .env.example .env`
   - `cmd /c npm install`
   - `cmd /c npm run dev`
6. Optional AI:
   - OpenRouter: set `OPENROUTER_API_KEY` and `OPENROUTER_MODEL`
   - Ollama: run `ollama serve` and ensure `qwen2.5:3b` is installed
