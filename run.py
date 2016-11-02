#!flask/bin/python
import os
from app import app
app.run(host='0.0.0.0', port = int(os.environ.get('PORT', 8080)), debug=True)