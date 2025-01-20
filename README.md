# Orchestrator Pro - Intentionally Vulnerable Simple Supply Chain Management Software Demo

Orchestrator Pro is a supply chain management software developed as a demonstration & submission material for the CyberSecurity Competition conducted by Ministry of Electronics and Information Technology. This demo highlights several basic yet key cybersecurity vulnerabilities and mitigation strategies in the context of MSMEs (Micro, Small, and Medium Enterprises). The application showcases common vulnerabilities, such as Remote Code Execution (RCE) and Insecure Direct Object Reference (IDOR), and highlights their potential risks in supply chain management.

This demo app is designed to raise awareness about the importance of securing supply chain systems against cyber threats, especially for MSMEs that may lack robust cybersecurity measures.

## Features

- **User Authentication**: Basic login functionality with a vulnerable SQL injection implementation for demonstrating common security flaws.
- **Order Management**: Regular users can view and track orders. Admin users can manage and view orders.
- **File Upload & Execution**: A vulnerable file upload feature allows an attacker to upload and execute arbitrary Python scripts on the server.
- **Admin Panel**: Admin users can view all orders and upload files to the system, but this panel has several vulnerabilities that need to be mitigated.
- **Dashboard**: A user-friendly dashboard showing order statuses, recent activities, inventory overview, and supply chain analytics.

## Security Vulnerabilities Demonstrated

- **Remote Code Execution (RCE)**: The app includes a vulnerable file upload feature that allows an attacker to upload and execute malicious scripts on the server, showcasing the potential for RCE attacks.
- **Insecure Session Token**: The app generates insecure session token upon logging in. This weak token can be easily decrypted using bruteforce attacks and manipulated to modify vital fields such as user_id, role, username, etc... to impersonate as another user and get access to sensitive data and potentially administrative controls over the functioning of the application
- **SQL Injection**: The user authentication route is vulnerable to SQL injection, allowing unauthorized users to bypass authentication.
- **Insecure Direct Object Reference (IDOR)**: The order management section is vulnerable to IDOR attacks, allowing a user to access unauthorized orders by modifying URLs.

## Research Paper Overview

The Orchestrator Pro app is designed in line with the findings from the following research paper: [Paper Drive Link](https://drive.google.com/file/d/1fqLPGTyEcRKMUiR0zixAS_N-_oNSfFV3/view?usp=sharing)

### Abstract:
MSMEs play a crucial role in the GDP growth, industrial production, and job creation in the nation's economy, yet they remain vulnerable to cyber threats that can disrupt operations and compromise sensitive data. This paper explores the unique cybersecurity challenges faced by MSMEs, particularly within the context of their supply chains. It proposes innovative solutions and regulatory frameworks tailored to these enterprises, emphasizing the need for secure data-sharing practices, third-party risk management, and affordable technological interventions.

## Installation

To run the Orchestrator Pro demo application, follow these steps:

1. Clone the repository:
    ```bash
    git clone https://github.com/akhichit2008/Orchestrator-Demo.git
    cd orchestrator-pro
    ```

2. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Create the database:
    ```bash
    python
    >>> from app import db
    >>> db.create_all()
    ```

4. Run the application:
    ```bash
    python app.py
    ```

5. Open a browser and go to `http://127.0.0.1:5000` to view the app.

## Technologies Used

- **Flask**: A lightweight Python web framework for building the app.
- **SQLAlchemy**: An ORM (Object Relational Mapper) to interact with the SQLite database.
- **Bootstrap**: A front-end framework to make the UI responsive and stylish.
- **Python 3.x**: The backend scripting language for the app.
  
## Demo Features

- **Login Page**: Users can log in with credentials. The SQL injection vulnerability allows bypassing authentication with crafted inputs.
- **Admin Panel**: Access the admin panel to view all orders and upload files. Vulnerable to RCE.
- **Order Status Page**: Regular users can view their order status, but admins have additional privileges.
- **Upload Page**: Vulnerable to file upload exploits and RCE attacks.

## Disclaimer

This application is intentionally vulnerable to demonstrate common security flaws in supply chain management systems. It is not meant for production use. Always implement security best practices and conduct proper security audits before deploying any application.

---

By showcasing the vulnerabilities in Orchestrator Pro, I aim to raise awareness among MSMEs about the cybersecurity risks that could potentially disrupt their operations and compromise sensitive data. The solutions proposed in the accompanying research paper offer recommendations to mitigate these risks and improve the security posture of MSMEs
