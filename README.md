# FilesPad - Secure File Sharing Platform

A Flask-based file sharing platform with temporary storage and secure access features.

## Features

- Drag-and-drop file upload
- Secure file storage with encryption
- Optional password protection
- Automatic file deletion after 3 days
- Clean, modern UI with Tailwind CSS
- No user accounts required
- Cloudinary storage integration

## Requirements

- Python 3.8+
- Flask
- Cloudinary account
- Other dependencies listed in requirements.txt

## Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd filespad
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

4. Configure environment variables:
   - Copy `.env.example` to `.env`
   - Update the following variables in `.env`:
     - `SECRET_KEY`: A secure random string
     - `CLOUDINARY_CLOUD_NAME`: Your Cloudinary cloud name
     - `CLOUDINARY_API_KEY`: Your Cloudinary API key
     - `CLOUDINARY_API_SECRET`: Your Cloudinary API secret
     - `ENCRYPTION_KEY`: A secure encryption key (will be auto-generated if not provided)

5. Run the application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Usage

1. Upload a file:
   - Drag and drop a file onto the upload area
   - Optionally set a password
   - Click "Upload File"
   - Copy the generated access code

2. Download a file:
   - Enter the access code on the main page
   - If password protected, enter the password
   - Download the file

## Security Features

- File encryption using Fernet (symmetric encryption)
- Optional password protection for files
- Automatic file deletion after 3 days
- HTTPS support
- No storage of sensitive data in plain text

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 