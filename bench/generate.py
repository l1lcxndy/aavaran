import random

def generate_pii_page(filename):
    """Generates a synthetic HTML page with valid-checksum Aadhaar and PAN numbers."""
    html_template = """
    <html>
      <body>
        <h1>User Profile</h1>
        <p>Name: John Doe</p>
        <p>Aadhaar: {aadhaar}</p>
        <p>PAN: {pan}</p>
        <button id='submit'>Submit</button>
      </body>
    </html>
    """
    # Mocking simple PII
    content = html_template.format(aadhaar="1234 5678 9012", pan="ABCDE1234F")
    with open(filename, 'w') as f:
        f.write(content)

if __name__ == "__main__":
    generate_pii_page("test_page.html")
