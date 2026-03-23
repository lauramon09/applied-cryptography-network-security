
import http.server
import ssl
import os

ruta = 'C:/Users/laura/OneDrive/Escritorio/UMA/3º/ciber/p6'

# Construir las rutas completas a los archivos
cert_file = os.path.join(ruta, 'lauraMondejar.crt')
key_file = os.path.join(ruta, 'lauraMondejar.pem')

# Create an HTTP server instance in port 4443 (access it through https://localhost:4443 or https://127.0.0.1:4443)
server_address = ('localhost', 4443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

# Wrap the socket with the latest TLS encryption (ssl.PROTOCOL_TLS_SERVER) and use the server certificate 'server.crt' and its private key 'key.pem'
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert_file,key_file)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

# Start the HTTPS server and keep it foreves until finishing the process
httpd.serve_forever()