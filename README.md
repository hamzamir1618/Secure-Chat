# Secure-Chat

**A Mini Console-Based Secure Chat System**

This is a client-server chat application built in Python, designed as a console-based tool to demonstrate how real-world secure communication systems combine cryptographic primitives to achieve **CIANR** properties:

- **C**onfidentiality  
- **I**ntegrity  
- **A**uthenticity  
- **N**on-**R**epudiation  

It serves as an educational example of implementing secure messaging using standard cryptographic techniques (likely involving symmetric/asymmetric encryption, digital signatures, key exchange, etc.).

## Features

- Console-based interface (no GUI)
- Client-server architecture
- End-to-end security demonstration
- Achieves key security goals through combined crypto primitives
- Easy to run and experiment with for learning purposes

## Repository Structure

```
Secure-Chat/
├── app/                  # Core application code (modules for crypto, networking, etc.)
├── scripts/              # Executable scripts to run the server and client
├── tests/
│   └── manual/           # Manual test cases or instructions
├── requirements.txt      # Python dependencies
├── .gitignore
├── .gitattributes
└── README.md
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/hamzamir1618/Secure-Chat.git
   cd Secure-Chat
   ```

2. (Recommended) Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Typical usage:

- Start the server:
  ```bash
  python scripts/run_server.py  
  ```

- In separate terminals, start clients:
  ```bash
  python scripts/run_client.py  
  ```

Follow any on-screen prompts to connect, authenticate, and chat securely.

Refer to the `tests/manual/` directory for example usage scenarios or manual testing guides.

## Security Notes

This project is intended for **educational purposes** to illustrate cryptographic concepts in a practical chat system. It is not audited for production use and may not be secure against real-world attacks.

## Contributing

Feel free to fork the repository, open issues, or submit pull requests to improve the code, documentation, or add features.

## License

MIT

---

