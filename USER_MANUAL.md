# Total Beginner’s Guide to Running Your New App

Hello! Don't worry if you've never done anything like this before. I have written down **every single step** for you. Just follow along exactly, and everything will work perfectly!

---

## **Phase 1: Getting the Tools You Need**

Before we can run the specific "Anomaly Detection" app, we need to install two main programs on your computer. 

### 🖥️ For Windows Users (Most Likely You)

#### **Step 1: Install Python **
1.  Open your web browser (Chrome, Edge, etc.).
2.  Go to this link: [https://www.python.org/downloads/](https://www.python.org/downloads/)
3.  You will see **"Download Python 3.x.x"**. Click it.
4.  Once it downloads, click on the file to open it.
5.  **⚠️ VERY IMPORTANT**: On the first screen of the installer, look at the bottom. **Check the box that says "Add Python to PATH"**. If you don't check this, nothing will work!
6.  Click **"Install Now"** and wait for it to finish.
7.  Click **"Close"**.

#### **Step 2: Install MySQL **
1.  Go to this link: [https://dev.mysql.com/downloads/installer/](https://dev.mysql.com/downloads/installer/)
2.  Click the **first "Download" button** you see (the smaller file size is fine).
3.  On the next page, click **"No thanks, just start my download"**.
4.  Open the file once it downloads.
5.  If it asks for permission, click **"Yes"**.
6.  When the installer opens, choose **"Server only"** or **"Developer Default"** and keep clicking **Next**.
7.  It will ask you to set a **Root Password**.
    *   Type in a simple password you will remember (like `password123`).
8.  Keep clicking **Next** and **Execute** until it says "Finished".

---

### 🐧 For Linux Users (If you are using Ubuntu)
1.  Open your "Terminal" (the black screen app).
2.  Copy this line exactly and paste it in:
    ```bash
    sudo apt update
    ```
3.  Press Enter. Type your password if asked (you won't see the letters typing, that's normal).
4.  Then copy and paste this line:
    ```bash
    sudo apt install -y python3-pip python3-venv mysql-server
    ```
5.  Press Enter and wait for it to finish.

---

## **Phase 2: Setting Up the Database**

Now we need to tell the MySQL program to create a space for our app.

### **On Windows:**
1.  Click your **Start Menu** button.
2.  Type `MySQL Command Line Client` and click on the app that appears (it looks like a black black box).
3.  It will ask for a password. Type the **Root Password** you created in Phase 1 (Step 7) and press Enter.
4.  Now, copy the block of text below.

    ```sql
    CREATE DATABASE IF NOT EXISTS cloud_anomaly_db;
    USE cloud_anomaly_db;

    CREATE TABLE IF NOT EXISTS uploads (
        id INT AUTO_INCREMENT PRIMARY KEY,
        file_names TEXT NOT NULL,
        file_types TEXT NOT NULL,
        detection_status VARCHAR(255) NOT NULL,
        timestamp DATETIME NOT NULL
    );
    ```
5.  Press **Enter**. If it says `Query OK`, you did it! You can close that black window now.

### **On Linux:**
1.  In your terminal, type: `mysql -u root -p`
2.  Type your password.
3.  Paste the same code block from above.

---

## **Phase 3: Making the App Run **

I made a special file for you that does all the hard work automatically.

### **On Windows:**
1.  Open the folder where you have this project files.
2.  Look for a file named **`run_app.bat`** (it might look like a stored gear icon).
3.  **Double-click it.**
4.  A black window will pop up. It will start installing things. **Don't touch it!** Just let it do its thing.
    *   *Note: If it closes immediately, you might not have installed Python correctly (did you check the "Add to PATH" box?).*
5.  Once it stops moving, it will say something like `Running on http://127.0.0.1:8080`. **Do not close this black window.** Keep it open!

### **On Linux:**
1.  Open your terminal in the project folder.
2.  Type: `./run_app.sh`
3.  Press Enter.

---

## **Phase 4: Using Your New App**

1.  Open your web browser (Chrome, Firefox, Edge).
2.  In the top address bar (where you type google.com), type exactly this and press Enter:
    **`http://127.0.0.1:8080`**
3.  You should see your "Anomaly Detection System"!
4.  Click on **File Transfer**.
5.  Click the button to **Select a File** from your computer (try a picture or a PDF).
6.  Click **Upload**.
7.  Watch it succeed! You can go to the **Results** page to see it listed there.

---

## **Phase 5: The "Cool Trick" (Simulating an Attack)**

Want to see the security system in action? Let's pretend to be a hacker!

1.  Go back to the **File Transfer** page on your browser.
2.  Select a file again, but **don't click upload yet**.
3.  Go to the folder where your project is.
4.  **Windows Users**:
    *   Right-click in an empty space in the folder and select "Open Terminal Here" or "Open PowerShell Here".
    *   Type: `python DDoS.py` but **DO NOT PRESS ENTER YET**.
5.  **Now, do this quickly:**
    *   Click the **Upload** button in your browser.
    *   Immediately go back to your black window and press **Enter** to run the attack script.
6.  **Look at the browser!**
    *   It should scream **"Anomaly Detected!"** and stop the upload.
    *   This means the system works! It saw the "hacker" script and protected you.

---

**That's it! You're a pro now!** 🎉
If anything goes wrong, just ensure you didn't skip any steps in the beginning.
