# Lock Point  

Lock Point is a secure file management and sharing platform that prioritizes data security and user convenience. With robust encryption, access controls, and seamless collaboration features, it allows users to upload, share, and manage files with confidence.  

---

## **Features**  

### **Core Functionalities**  
- **File Encryption**:  
  - AES encryption for file storage.  
  - RSA encryption for secure file transmission.  

- **File Management**:  
  - Upload files to an Amazon S3 bucket.  
  - View, download, delete, and manage file permissions.  
  - Attributes include ownership, file size, type, and access control.  

- **File Sharing**:  
  - Share files one-to-one or one-to-many.  
  - Revoke permissions for shared files.  

- **User Authentication**:  
  - Secure login/signup with password hashing.  
  - Google OAuth 2.0 for seamless authentication.  

- **Access Control List (ACL)**:  
  - View email IDs of users with access to files.  
  - Manage sharing permissions.  

- **Dashboard**:  
  - Centralized view of uploaded files.  
  - Perform CRUD operations on files.  

---

## **Tools and Technologies**  

### **Frontend**  
- React.js  
- Axios  

### **Backend**  
- Flask  
- Flask-RESTful  
- Flask-JWT-Extended  

### **File Security**  
- AES Encryption (File Storage)  
- RSA Encryption (File Transmission)  

### **Authentication**  
- Google OAuth 2.0  
- bcrypt for password hashing  

### **Database**  
- MongoDB (for user credentials and file metadata)  

### **Cloud Storage**  
- Amazon S3 (via boto3)  

---

## **Setup and Installation**  

### **Prerequisites**  
- Python 3.x  
- Node.js and npm  
- MongoDB  
- AWS account with S3 access  

### **Backend Setup**  
1. Clone the repository:  
   ```bash
   git clone https://github.com/barath-sk17/LockPoint.git
   cd lock-point/backend
