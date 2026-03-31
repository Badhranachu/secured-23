# AEGIS AI

Local SaaS-style security scanner built with Django, DRF, MySQL, Celery, Redis, React, Vite, Axios, and Recharts.

## Backend
- `cd backend`
- `Copy-Item .env.example .env`
- fill in MySQL, Redis, SMTP, OpenRouter, and Ollama settings
- `pip install -r requirements.txt`
- `python manage.py migrate`
- `python manage.py seed_demo`
- `python manage.py createsuperuser`
- `python manage.py runserver 127.0.0.1:8000`
- `celery -A config worker -l info --pool=solo`
- `celery -A config beat -l info`

## Frontend
- `cd frontend`
- `Copy-Item .env.example .env`
- `cmd /c npm install`
- `cmd /c npm run dev`
