# Sundai Ideas Submission Platform

A collaborative web application for tracking and submitting hackathon ideas for Sundai's weekly meetings.

## Features

- Submit and track innovative ideas
- Target user identification
- Interactive calendar view
- Voting system
- Comment system
- User authentication
- Responsive design with cyberpunk theme

## Tech Stack

- Python 3.11
- Flask 2.3.3
- SQLAlchemy 3.0.5
- Bootstrap 5.3.0
- SQLite

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/sundai-idea-submission.git
cd sundai-idea-submission
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
flask db upgrade
```

5. Run the application:
```bash
python app.py
```

The application will be available at http://localhost:8080

## Environment Variables

Create a `.env` file in the root directory with the following variables:
```
FLASK_SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///instance/ideas.db
```

## Contributing

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Submit a pull request

## License

MIT License
