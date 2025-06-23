# HellProfile - Password Manager

HellProfile is a simple, locally-stored password manager application built with Python and Tkinter. It allows users to securely store passwords and notes within encrypted profile vaults.

## Features

-   **Profile Management:** Create, select, and manage multiple password profiles.
-   **AES Encryption:** AES encryption is used for secure storage of passwords and notes.
-   **Password and Note Storage:** Store website credentials (username, password, website) and general notes.
-   **User Interface:** Intuitive graphical user interface built with Tkinter.
-   **Cross-Platform:** Compatible with Windows and Linux.
-   **Clipboard Integration:** Quickly copy website URLs, usernames, and passwords to the clipboard.
-   **Profile Metadata:** Tracks profile descriptions, creation dates, and last accessed times.

## Prerequisites

-   Python 3.6+
-   Tkinter (usually included with Python)
-   cryptography library

## Installation

1.  **Install Dependencies:**

    ```bash
    pip install cryptography tkinter
    ```

2.  **Download the Script:**
    Download the `main.py` file from this repository.

## Usage

1.  **Run the Script:**

    ```bash
    python main.py
    ```

2.  **Creating a New Profile:**
    -   If no profiles exist, the application will prompt you to create a new profile.
    -   Enter a profile name, description (optional), master password, and confirm the password.
    -   Click "Create Profile" to create the new profile.

3.  **Selecting an Existing Profile:**
    -   If profiles exist, the application will display a list of available profiles.
    -   Select a profile and click "Open".
    -   Enter the master password for the selected profile to unlock and access it.

4.  **Main Interface:**
    -   Once a profile is opened, the main interface will display options to:
        -   Add Password
        -   Add Note
        -   Delete Entry
        -   View Details
        -   Switch Profile

5.  **Adding a Password:**
    -   Click "Add Password" to open the "Add Password" dialog.
    -   Enter the name, website, username, and password for the new entry.
    -   Click "Save" to add the password to the profile.

6.  **Adding a Note:**
    -   Click "Add Note" to open the "Add Note" dialog.
    -   Enter the name, title, and content for the new note.
    -   Click "Save" to add the note to the profile.

7.  **Deleting an Entry:**
    -   Select an entry from the list.
    -   Click "Delete Entry".
    -   Confirm the deletion in the confirmation dialog.

8.  **Viewing Entry Details:**
    -   Select an entry from the list.
    -   Click "View Details" to view the details of the selected entry.
    -   For password entries, you can copy the website, username, and password to the clipboard.
    -   For note entries, you can copy the content to the clipboard.

9.  **Switching Profiles:**
    -   Click "Switch Profile" in the main interface to return to the profile selection screen.

## Security Notes

-   **Master Password:** The security of your stored passwords relies entirely on the strength and secrecy of your master password. Choose a strong, unique password and do not share it with anyone.
-   **Local Storage:** HellProfile stores your encrypted data locally. Ensure your system is protected from unauthorized access.
-   **Encryption:** AES encryption is used, but as with any software, vulnerabilities may exist. Use at your own risk.

## Directory Structure

-   `main.py`: The main Python script containing the password manager application.
-   `[profile_name].enc`: Encrypted file storing password data for each profile. Stored in `~/Documents/HellProfile` on Linux and `%APPDATA%/HellProfile` on Windows.
-   `profiles_metadata.json`: JSON file storing metadata about each profile (description, creation date, last accessed).

## Contributing

Contributions are welcome! If you find a bug or have a feature request, please open an issue or submit a pull request.

## License

This project is open source and available under the [MIT License](LICENSE).
