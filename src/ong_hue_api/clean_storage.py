"""
Clean all storage data
"""

from hue_rest_api import CredentialsManager


def main():
    """Removes cookies, tokens and passwords from storage"""
    creds = CredentialsManager()
    creds.clean_stored_password()
    print("Storage clean")

if __name__ == '__main__':
    main()
