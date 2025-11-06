"""
Simple test script to verify the proxy connection works
"""
import requests

# Decodo residential proxy configuration
PROXY_HOST = "us.decodo.com"
PROXY_PORT = 10000
PROXY_USER = "sp12ay6sup"
PROXY_PASS = "3mo2E1_R0ksylXqdmN"

# Construct proxy URL
proxy_url = f'http://{PROXY_USER}:{PROXY_PASS}@{PROXY_HOST}:{PROXY_PORT}'

proxies = {
    'http': proxy_url,
    'https': proxy_url
}

def test_connection():
    """Test the proxy connection"""
    print("=" * 60)
    print("Testing Proxy Connection...")
    print("=" * 60)
    
    try:
        # Test URL - returns your public IP
        url = 'https://ipv4.icanhazip.com'
        
        print(f"\nConnecting to {url} through proxy...")
        print(f"Proxy: {PROXY_HOST}:{PROXY_PORT}")
        
        response = requests.get(url, proxies=proxies, timeout=10)
        response.raise_for_status()
        
        ip_address = response.text.strip()
        
        print(f"\nSUCCESS!")
        print(f"Your proxy IP address: {ip_address}")
        print(f"Status code: {response.status_code}")
        print(f"\nProxy is working correctly!")
        
        return True
        
    except requests.exceptions.ProxyError as e:
        print(f"\n❌ PROXY ERROR:")
        error_str = str(e)
        
        if '402' in error_str or 'Payment Required' in error_str:
            print(f"⚠️  402 Payment Required - Your Decodo account needs payment or credentials expired")
            print(f"\n📋 What to do:")
            print(f"   1. Log into https://decodo.com")
            print(f"   2. Check your account balance/credits")
            print(f"   3. Verify your proxy credentials are still valid")
            print(f"   4. Update credentials in app.py if needed")
        elif '401' in error_str or 'Unauthorized' in error_str:
            print(f"⚠️  Authentication Failed - Invalid username or password")
            print(f"\n📋 Check your proxy credentials in app.py")
        elif '403' in error_str or 'Forbidden' in error_str:
            print(f"⚠️  Access Forbidden - Account may not have permission")
        else:
            print(f"Could not connect to the proxy server.")
        
        print(f"\nDetails: {e}")
        return False
        
    except requests.exceptions.RequestException as e:
        print(f"\n❌ REQUEST ERROR:")
        error_str = str(e)
        if '402' in error_str or 'Payment Required' in error_str:
            print(f"⚠️  402 Payment Required - Check your Decodo account")
        else:
            print(f"An error occurred: {e}")
        return False
    
    finally:
        print("=" * 60)

if __name__ == "__main__":
    test_connection()

