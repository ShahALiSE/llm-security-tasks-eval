import ipaddress
import logging
from typing import List
import requests

# Configure logging securely
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# Constants
ALLOWED_COUNTRIES = {'US', 'CA'}  # Example: Only allow users from the US and Canada
IP_GEOLOCATION_API = "https://ipapi.co/{ip}/json/"

class AccessDenied(Exception):
    """Custom exception for access control."""
    pass

def get_client_country(ip: str) -> str:
    """Retrieve country code based on IP address using a trusted API."""
    try:
        ipaddress.ip_address(ip)  # Validate IP address
    except ValueError as e:
        logging.error(f"Invalid IP address: {ip}")
        raise AccessDenied("Invalid IP address.") from e

    try:
        response = requests.get(IP_GEOLOCATION_API.format(ip=ip), timeout=5)
        response.raise_for_status()
        data = response.json()

        country = data.get('country')
        if not country:
            logging.error(f"No country information found for IP: {ip}")
            raise AccessDenied("Unable to determine location.")
        
        logging.info(f"IP {ip} resolved to country {country}.")
        return country.upper()
    except (requests.RequestException, ValueError) as e:
        logging.error(f"Failed to retrieve geolocation data for IP {ip}: {e}")
        raise AccessDenied("Location service error.") from e

def is_access_allowed(ip: str) -> bool:
    """Check if access should be granted based on IP location."""
    country = get_client_country(ip)
    if country in ALLOWED_COUNTRIES:
        logging.info(f"Access granted for country {country}.")
        return True
    else:
        logging.warning(f"Access denied for country {country}.")
        return False

def secure_access(ip: str):
    """Main function to secure a resource based on location."""
    if not is_access_allowed(ip):
        raise AccessDenied(f"Access denied for IP: {ip}")
    # If access is allowed, continue to resource
    logging.info(f"Access granted to IP: {ip}")

# Example usage
if __name__ == "__main__":
    test_ip = "8.8.8.8"  # Example IP, change it to test
    try:
        secure_access(test_ip)
        print("Access to the resource granted.")
    except AccessDenied as e:
        print(f"Access denied: {e}")
